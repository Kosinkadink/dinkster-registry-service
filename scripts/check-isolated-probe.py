from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
import zipfile
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from dinkster_schema import SCHEMA_WIRE_VERSION, schema_from_wire, schema_signature

from dinkster_registry_service.admission_checks import run_executable_probe
from dinkster_registry_service.seed import FIXTURE_ROOT
from dinkster_registry_service.settings import ServerSettings


def check_dependency_environment() -> None:
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        package = root / "index" / "probe-dependency"
        package.mkdir(parents=True)
        wheel = package / "probe_dependency-1.0-py3-none-any.whl"
        marker = root / "outside-jail"
        files = {
            "probe_dependency.py": (
                "import resource\n"
                "assert 0 < resource.getrlimit(resource.RLIMIT_CPU)[0] <= 300\n"
                "assert 0 < resource.getrlimit(resource.RLIMIT_FSIZE)[0] <= 64 * 1024 * 1024\n"
                "VALUE = 83\n"
            ),
            "dinkster_workers/__init__.py": "raise RuntimeError('counterfeit harness imported')\n",
            "dinkster_workers/_doctor_probe.py": (
                "raise RuntimeError('counterfeit probe imported')\n"
            ),
            "probe_dependency-1.0.dist-info/METADATA": (
                "Metadata-Version: 2.1\nName: probe-dependency\nVersion: 1.0\n"
            ),
            "probe_dependency-1.0.dist-info/WHEEL": (
                "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
            ),
            "dependency-startup.pth": (
                "import builtins, pathlib; builtins.DEPENDENCY_STARTUP = 'jailed'; exec("
                + repr(
                    f"try:\n pathlib.Path({str(marker)!r}).write_text('escaped')\n"
                    "except OSError:\n pass"
                )
                + ")\n"
            ),
        }
        with zipfile.ZipFile(wheel, "w") as archive:
            for name, data in files.items():
                archive.writestr(name, data)
            archive.writestr(
                "probe_dependency-1.0.dist-info/RECORD",
                "".join(f"{name},,\n" for name in files)
                + "probe_dependency-1.0.dist-info/RECORD,,\n",
            )
        package.joinpath("index.html").write_text(f'<a href="{wheel.name}">wheel</a>')
        server = ThreadingHTTPServer(
            ("127.0.0.1", 0), partial(SimpleHTTPRequestHandler, directory=str(package.parent))
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            pack = root / "pack"
            shutil.copytree(FIXTURE_ROOT / "example-pack", pack)
            manifest = pack / "dinkster-pack.toml"
            manifest.write_text(
                manifest.read_text().replace(
                    "[pack]\n", '[pack]\nrequires = ["probe-dependency==1.0"]\n'
                )
            )
            nodes = pack / "nodes.py"
            nodes.write_text(
                "from probe_dependency import VALUE\nimport builtins, socket\n"
                "assert not hasattr(builtins, 'DEPENDENCY_STARTUP')\n"
                "try:\n"
                f" socket.create_connection(('127.0.0.1', {server.server_port}), timeout=1)\n"
                "except OSError:\n pass\n"
                "else:\n raise RuntimeError('probe reached host network')\n"
                + nodes.read_text().replace("version=2,", "version=VALUE,")
            )
            result = run_executable_probe(
                pack,
                settings=ServerSettings(
                    probe_package_index_url=f"http://127.0.0.1:{server.server_port}"
                ),
            )
            if result.blocked or result.data is None:
                raise SystemExit(f"dependency probe failed: {result}")
            versions = {item["nodeType"]: item["schemaVersion"] for item in result.data["schemas"]}
            if versions.get("example.resize") != 83:
                raise SystemExit("probe did not use its declared dependency")
            if marker.exists():
                raise SystemExit("dependency startup code ran outside the jail")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


def check_controlled_probe_environment() -> None:
    fixture = (FIXTURE_ROOT / "example-pack").resolve()
    with tempfile.TemporaryDirectory() as temporary_directory:
        pack_root = Path(temporary_directory) / "example-pack"
        shutil.copytree(fixture, pack_root)
        nodes = pack_root / "nodes.py"
        marker = "REGISTRY_PROBE_ENV="
        nodes.write_text(
            "import json, os\n"
            f"os.write(2, ({marker!r} + json.dumps(dict(os.environ)) + '\\n').encode())\n"
            + nodes.read_text()
        )
        controlled_path = os.pathsep.join(
            (str(Path(sys.executable).parent), "/usr/local/bin", "/usr/bin", "/bin")
        )
        host_path = controlled_path + ":/host-only-probe-path"
        original = dict(os.environ)
        try:
            os.environ.update(
                {
                    "PATH": host_path,
                    "LANG": "host-only-locale",
                    "DINKSTER_REVIEW_CANARY": "host-only-canary",
                }
            )
            result = run_executable_probe(pack_root, require_isolation=True)
        finally:
            os.environ.clear()
            os.environ.update(original)

    if result.operator_details is None:
        raise SystemExit("isolated probe did not retain operator diagnostics")
    stderr_tail = result.operator_details["stderrTail"]
    if not isinstance(stderr_tail, str):
        raise SystemExit("isolated probe stderr diagnostics are invalid")
    environment_lines = [
        line.removeprefix(marker) for line in stderr_tail.splitlines() if line.startswith(marker)
    ]
    if len(environment_lines) != 1:
        raise SystemExit("isolated probe did not report exactly one environment")
    environment = json.loads(environment_lines[0])
    if environment.get("PATH") != controlled_path or environment.get("PATH") == host_path:
        raise SystemExit("isolated probe received the host PATH")
    if environment.get("LANG") != "C.UTF-8":
        raise SystemExit("isolated probe received the host locale")
    if "DINKSTER_REVIEW_CANARY" in environment:
        raise SystemExit("isolated probe received an unapproved host variable")


def main() -> None:
    fixture = (FIXTURE_ROOT / "example-pack").resolve()
    result = run_executable_probe(fixture, require_isolation=True)
    if result.blocked:
        messages = "; ".join(f"{finding.code}: {finding.message}" for finding in result.findings)
        raise SystemExit(f"isolated probe failed: {messages}")
    if result.data is None or len(result.data["schemas"]) != 2:
        raise SystemExit("isolated probe did not return the two fixture schemas")
    expected_versions = {"example.resize": 2, "example.save": 1}
    for record in result.data["schemas"]:
        node_type = record["nodeType"]
        if record["schemaVersion"] != expected_versions.get(node_type):
            raise SystemExit(f"isolated probe returned an invalid node version for {node_type}")
        if record["schemaWireVersion"] != SCHEMA_WIRE_VERSION:
            raise SystemExit(f"isolated probe returned an invalid wire version for {node_type}")
        schema = schema_from_wire(record["schema"])
        if record["schemaSignature"] != schema_signature(schema):
            raise SystemExit(f"isolated probe returned an invalid schema signature for {node_type}")
    check_controlled_probe_environment()
    check_dependency_environment()
    print("isolated_probe=passed schemas=2 environment=controlled dependencies=isolated")


if __name__ == "__main__":
    main()
