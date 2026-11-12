from __future__ import annotations

import io
import tempfile
import tomllib
import zipfile
from dataclasses import dataclass
from pathlib import Path

import tomli_w
from dinkster_registry.archive_admission import (
    AdmissionFinding,
    ProbeSettings,
    StageResult,
    run_executable_probe,
)
from dinkster_workers.manifest import load_manifest

from .scan_engine import stage_scan_api


@dataclass(frozen=True)
class ProbeDependencies:
    helper_wheels: tuple[bytes, ...]
    library_wheels: tuple[tuple[str, bytes], ...]
    requirements: tuple[str, ...]


def run_prepared_probe(
    root: Path,
    dependencies: ProbeDependencies,
    *,
    settings: ProbeSettings,
    require_isolation: bool = True,
    scan_engine: dict[str, str] | None = None,
    development_release: Path | None = None,
) -> StageResult:
    """Run a probe using resolved bytes, without catalog or object-store authority."""
    manifest_path = root / "dinkster-pack.toml"
    original = manifest_path.read_bytes()
    manifest = load_manifest(manifest_path)
    try:
        for data in dependencies.helper_wheels:
            # Helpers keep their installed layout, not their relocated probe assets.
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for member in archive.infolist():
                    if member.is_dir():
                        continue
                    destination = root / member.filename
                    if destination.exists():
                        raise ValueError("Helper wheel overlaps the submitted pack.")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(archive.read(member))
        if dependencies.helper_wheels:
            # Published metadata and the original wheel are never changed.
            document = tomllib.loads(original.decode())
            document["pack"]["requires"] = list(dependencies.requirements)
            document["pack"].pop("extra-requires", None)
            manifest_path.write_text(tomli_w.dumps(document))
        with tempfile.TemporaryDirectory(prefix="registry-library-wheels-") as directory:
            wheels = []
            for filename, data in dependencies.library_wheels:
                path = Path(directory) / filename
                path.write_bytes(data)
                wheels.append(path)
            if scan_engine is not None:
                try:
                    api_wheel, engine_version = stage_scan_api(
                        scan_engine, Path(directory), development_release=development_release
                    )
                    if manifest.compatibility is None:
                        raise ValueError("selected engine requires pack compatibility")
                    manifest.compatibility.require_engine(manifest.name, engine_version)
                except (ValueError, OSError) as exc:
                    return StageResult(
                        (AdmissionFinding("probe.engine-unavailable", "error", "block", str(exc)),)
                    )
                return run_executable_probe(
                    root,
                    settings=settings,
                    require_isolation=require_isolation,
                    dependency_wheels=tuple(wheels),
                    api_wheel=api_wheel,
                )
            if wheels:
                return run_executable_probe(
                    root,
                    settings=settings,
                    require_isolation=require_isolation,
                    dependency_wheels=tuple(wheels),
                )
            return run_executable_probe(
                root, settings=settings, require_isolation=require_isolation
            )
    except (ValueError, FileNotFoundError) as exc:
        return StageResult(
            (AdmissionFinding("probe.pack-dependencies-unavailable", "error", "block", str(exc)),)
        )
    finally:
        manifest_path.write_bytes(original)
