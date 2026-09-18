from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from dinkster_registry_service.admission_checks import run_executable_probe
from dinkster_registry_service.seed import FIXTURE_ROOT


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
    check_controlled_probe_environment()
    print("isolated_probe=passed schemas=2 environment=controlled")


if __name__ == "__main__":
    main()
