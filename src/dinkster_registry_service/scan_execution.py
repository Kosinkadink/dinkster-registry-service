from __future__ import annotations

import hashlib
import io
import tempfile
import tomllib
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tomli_w
from dinkster_registry.archive_admission import (
    AdmissionFinding,
    ProbeSettings,
    StageResult,
    run_executable_probe,
    run_locked_probe,
)
from dinkster_store import object_path, readable_label
from dinkster_supervisor.environment_artifacts import acquire
from dinkster_supervisor.environment_downloads import fetch_artifact
from dinkster_supervisor.environment_generations import prepare_engine_interpreter
from dinkster_supervisor.environment_state import writer_lock
from dinkster_workers.manifest import load_manifest
from dinkster_workers.pack_lock import PackLock, normalize_requirement
from dinkster_workers.provision import ProvisionError

from .digests import artifact_digest as digest_bytes
from .scan_engine import stage_scan_api
from .scan_runtime import scan_catalog


@dataclass(frozen=True)
class ProbeDependencies:
    helper_wheels: tuple[bytes, ...]
    library_wheels: tuple[tuple[str, bytes], ...]
    requirements: tuple[str, ...]
    bindings: tuple[str, ...] = ()


def run_prepared_probe(
    root: Path,
    dependencies: ProbeDependencies,
    *,
    settings: ProbeSettings,
    require_isolation: bool = True,
    scan_engine: dict[str, str] | None = None,
    development_release: Path | None = None,
    install_locks: dict[str, dict[str, Any]] | None = None,
    lock_bytes: dict[str, bytes] | None = None,
    artifact_digest: str | None = None,
    runtime_store: Path | None = None,
    development_runtime: Path | None = None,
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
            if install_locks:
                if runtime_store is None or lock_bytes is None:
                    raise ValueError("Locked probes require assigned locks and a runtime store")
                locks = {}
                if set(lock_bytes) != set(install_locks):
                    raise ValueError("Assigned dependency lock variants differ")
                for variant, binding in install_locks.items():
                    if binding["artifactDigest"] != artifact_digest:
                        raise ValueError(f"{variant}: lock artifact digest differs from archive")
                    data = lock_bytes[variant]
                    if len(data) != binding["size"] or digest_bytes(data) != binding["digest"]:
                        raise ValueError(f"{variant}: submitted dependency lock bytes changed")
                    lock = PackLock.from_json(data)
                    if lock.pack != manifest.name or lock.variant != variant:
                        raise ValueError(f"{variant}: dependency lock pack or variant differs")
                    locks[variant] = lock
                catalog, variant = scan_catalog(
                    scan_engine, install_locks, mirror=development_runtime
                )
                if manifest.compatibility is not None:
                    manifest.compatibility.require_engine(
                        manifest.name, catalog.channel.engine_version
                    )
                lock = locks[variant]
                if missing := {
                    normalize_requirement(value) for value in dependencies.requirements
                } - set(lock.requirements):
                    raise ValueError(
                        f"{variant}: dependency lock omits requirements {sorted(missing)}"
                    )
                for wheel in wheels:
                    sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
                    if not any(
                        item.filename == wheel.name and item.sha256 == sha
                        for package in lock.packages
                        for item in package.wheels
                    ):
                        raise ValueError(
                            f"{variant}: dependency lock differs from verified library {wheel.name}"
                        )
                runtime_store.mkdir(parents=True, exist_ok=True)
                with writer_lock(runtime_store):
                    for wheel in wheels:
                        sha = hashlib.sha256(wheel.read_bytes()).hexdigest()
                        fetch_artifact(
                            (str(wheel.parent),),
                            wheel.name,
                            object_path(
                                runtime_store / "wheels",
                                "sha256:" + sha,
                                label=readable_label(wheel.stem),
                            )
                            / wheel.name,
                            sha,
                            wheel.stat().st_size,
                        )
                    constraints = acquire(catalog, variant, runtime_store)
                    with tempfile.TemporaryDirectory(
                        prefix=".probe-", dir=runtime_store
                    ) as scratch_directory:
                        scratch = Path(scratch_directory)
                        python = prepare_engine_interpreter(
                            scratch / "engine",
                            store=runtime_store,
                            base=catalog.channel.base_for(variant),
                            constraints=constraints,
                        )
                        return run_locked_probe(
                            root,
                            lock,
                            generation_python=python,
                            packs=scratch / "packs",
                            wheel_store=runtime_store / "wheels",
                            uv_cache=runtime_store / "uv-cache",
                            variant=variant,
                            settings=settings,
                            require_isolation=require_isolation,
                            source_roots=(root,),
                        )
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
    except (ValueError, OSError, ProvisionError) as exc:
        return StageResult(
            (AdmissionFinding("probe.pack-dependencies-unavailable", "error", "block", str(exc)),)
        )
    finally:
        manifest_path.write_bytes(original)
