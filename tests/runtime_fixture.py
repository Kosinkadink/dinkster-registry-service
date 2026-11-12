from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import platform
import shutil
import sys
import sysconfig
import tarfile
import zipfile
from dataclasses import dataclass
from importlib.metadata import distribution
from pathlib import Path
from typing import Any

import zstandard
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from dinkster_registry_service.settings import ServerSettings


def _json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def _wheel(files: dict[str, bytes], name: str, version: str, tag: str) -> tuple[str, bytes]:
    stem = f"{name.replace('-', '_')}-{version}"
    record = io.StringIO()
    writer = csv.writer(record, lineterminator="\n")
    for path, data in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
        writer.writerow((path, "sha256=" + digest, len(data)))
    writer.writerow((f"{stem}.dist-info/RECORD", "", ""))
    files[f"{stem}.dist-info/RECORD"] = record.getvalue().encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for path, data in files.items():
            archive.writestr(path, data)
    return f"{stem}-{tag}.whl", output.getvalue()


def _installed_wheels() -> list[tuple[str, str, str, bytes]]:
    pending = [Requirement("dinkster-api")]
    selected = set()
    wheels: list[tuple[str, str, str, bytes]] = []
    while pending:
        requirement = pending.pop()
        name = canonicalize_name(requirement.name)
        if name in selected or (requirement.marker and not requirement.marker.evaluate()):
            continue
        selected.add(name)
        dist = distribution(name)
        pending.extend(Requirement(value) for value in dist.requires or ())
        files = {}
        for path in dist.files or ():
            if ".." in path.parts or path.name in {"RECORD", "INSTALLER", "REQUESTED"}:
                continue
            source = Path(str(dist.locate_file(path)))
            if not source.is_file():
                continue
            files[str(path)] = source.read_bytes()
        wheel_metadata = dist.read_text("WHEEL")
        assert wheel_metadata is not None
        tag = next(line[5:] for line in wheel_metadata.splitlines() if line.startswith("Tag: "))
        filename, payload = _wheel(files, name, dist.version, tag)
        wheels.append((name, dist.version, filename, payload))
    return wheels


@dataclass(frozen=True)
class RuntimeFixture:
    mirror: Path
    base_ids: dict[str, str]
    engine_version: str
    wheel_origin: str

    def settings(self, root: Path, **values: Any) -> ServerSettings:
        return ServerSettings(
            object_store_root=root / "runtime-store", probe_runtime_mirror=self.mirror, **values
        )

    def wheel_record(self, name: str, version: str) -> dict[str, object]:
        if name == "dinkster-api":
            path = next((self.mirror / "wheels").glob("dinkster_api-*.whl"))
            data = path.read_bytes()
        else:
            stem = f"{name.replace('-', '_')}-{version}.dist-info"
            filename, data = _wheel(
                {
                    f"{stem}/METADATA": (
                        f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n\n"
                    ).encode(),
                    f"{stem}/WHEEL": (
                        b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
                    ),
                    f"{name.replace('-', '_')}/__init__.py": b"ANSWER = 42\n",
                },
                name,
                version,
                "py3-none-any",
            )
            path = self.mirror / "wheels" / filename
            path.write_bytes(data)
        return {
            "filename": path.name,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "url": f"{self.wheel_origin}/{self.mirror.name}/wheels/{path.name}",
        }


def build_runtime(root: Path, version: str, wheel_origin: str) -> RuntimeFixture:
    root.mkdir()
    tree = root / "tree"
    python = tree / "python"
    (python / "bin").mkdir(parents=True)
    shutil.copy2(Path(sys.executable).resolve(), python / "bin/python3")
    shutil.copytree(
        Path(sysconfig.get_path("stdlib")),
        python / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}",
        ignore=shutil.ignore_patterns("site-packages", "__pycache__"),
    )
    library = Path(sysconfig.get_config_var("LIBDIR")) / sysconfig.get_config_var("LDLIBRARY")
    if library.is_file():
        shutil.copy2(library.resolve(), python / "lib" / library.name)
    (tree / "wheels").mkdir()
    (root / "wheels").mkdir()
    rows: list[dict[str, Any]] = []
    for name, selected_version, filename, payload in _installed_wheels():
        (tree / "wheels" / filename).write_bytes(payload)
        (root / "wheels" / filename).write_bytes(payload)
        rows.append(
            {
                "name": name,
                "version": selected_version,
                "lockedVersion": selected_version,
                "filename": filename,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "index": "https://pypi.org/simple",
                "url": f"{wheel_origin}/{root.name}/wheels/{filename}",
                "verification": "lock",
            }
        )
    compressed = io.BytesIO()
    with zstandard.ZstdCompressor().stream_writer(compressed, closefd=False) as stream:
        with tarfile.open(fileobj=stream, mode="w|") as archive:
            archive.add(tree / "python", "python")
            archive.add(tree / "wheels", "wheels")
    payload = compressed.getvalue()
    shutil.rmtree(tree)
    base_ids = {}
    for variant in ("linux-cpu", "cpu", "cuda"):
        base: dict[str, Any] = {
            "format": "dinkster.base/1",
            "variant": variant,
            "platform": {"os": "linux", "arch": "x86_64"},
            "python": platform.python_version(),
            "interpreter": {"executable": "python/bin/python3"},
            "wheels": rows,
            "replaces": sorted(row["name"] for row in rows),
            "workerProtocol": 11,
            "nvidia": None,
            "archive": {"format": "tar+zstd"},
        }
        identity = "sha256:" + hashlib.sha256(_json(base)).hexdigest()
        base_ids[variant] = identity
        directory = root / "base" / variant / identity[7:]
        directory.mkdir(parents=True)
        part = "base.tar.zst.001"
        (directory / part).write_bytes(payload)
        base["archive"]["parts"] = [
            {"filename": part, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        ]
        base.update(id=identity, signature=None)
        (directory / "manifest.json").write_bytes(_json(base))
    windows = json.loads((Path(__file__).parent / "fixtures/windows-base.json").read_bytes())
    base_ids["win-cpu"] = windows["id"]
    directory = root / "base/win-cpu" / windows["id"][7:]
    directory.mkdir(parents=True)
    (directory / "manifest.json").write_bytes(_json(windows))
    constraints = b""
    engine = {
        "format": "dinkster.engine/1",
        "repository": "Kosinkadink/Dinkster",
        "commit": "9ada7f6240fda0e5a8748e5bcbbe0ccdc369d54f",
        "version": version,
        "workerProtocol": 11,
        "artifacts": [
            {
                "name": "constraints.txt",
                "size": 0,
                "sha256": hashlib.sha256(constraints).hexdigest(),
            }
        ],
    }
    data = _json(engine)
    digest = hashlib.sha256(data).hexdigest()
    directory = root / "engine" / digest
    directory.mkdir(parents=True)
    (directory / "release-manifest.json").write_bytes(data)
    (directory / "constraints.txt").write_bytes(constraints)
    (root / "engine/index.json").write_bytes(
        _json([{**engine, "sha256": digest, "path": f"engine/{digest}"}])
    )
    channel = {
        "format": "dinkster.channel/1",
        "minimumDesktopVersion": "0.0.0",
        "engine": {
            "version": version,
            "release": "sha256:" + digest,
            "locations": [{"type": "mirror", "path": f"engine/{digest}/release-manifest.json"}],
        },
        "base": {
            variant: {
                "id": identity,
                "locations": [
                    {"type": "mirror", "path": f"base/{variant}/{identity[7:]}/manifest.json"}
                ],
            }
            for variant, identity in base_ids.items()
        },
    }
    (root / "channels").mkdir()
    (root / "channels/main.json").write_bytes(_json(channel))
    return RuntimeFixture(root, base_ids, version, wheel_origin)
