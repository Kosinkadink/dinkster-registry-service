from __future__ import annotations

import base64
import hashlib
import io
import shutil
import tempfile
import tomllib
import zipfile
from dataclasses import dataclass, replace
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
from dinkster_workers.pack_lock import (
    GenerationPackages,
    LockedDistribution,
    PackLock,
    normalize_requirement,
)
from dinkster_workers.provision import ProvisionError
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from .digests import artifact_digest as digest_bytes
from .pack_locks import iter_install_locks
from .scan_engine import stage_scan_api
from .scan_runtime import scan_catalog


@dataclass(frozen=True)
class ProbeDependencies:
    helper_wheels: tuple[bytes, ...]
    library_wheels: tuple[tuple[str, bytes], ...]
    requirements: tuple[str, ...]
    bindings: tuple[str, ...] = ()
    parts: tuple[tuple[str, ProbeDependencies], ...] = ()

    def to_record(self) -> dict[str, Any]:
        return {
            "helperWheels": [base64.b64encode(value).decode() for value in self.helper_wheels],
            "libraryWheels": [
                {"filename": name, "data": base64.b64encode(value).decode()}
                for name, value in self.library_wheels
            ],
            "requirements": list(self.requirements),
            "bindings": list(self.bindings),
            **(
                {"parts": {name: dependency.to_record() for name, dependency in self.parts}}
                if self.parts
                else {}
            ),
        }

    @classmethod
    def from_record(cls, record: dict[str, Any]) -> ProbeDependencies:
        return cls(
            tuple(base64.b64decode(value, validate=True) for value in record["helperWheels"]),
            tuple(
                (item["filename"], base64.b64decode(item["data"], validate=True))
                for item in record["libraryWheels"]
            ),
            tuple(record["requirements"]),
            tuple(record["bindings"]),
            tuple(
                (name, cls.from_record(value)) for name, value in record.get("parts", {}).items()
            ),
        )

    @property
    def transfer_size(self) -> int:
        return (
            sum(map(len, self.helper_wheels))
            + sum(len(value) for _, value in self.library_wheels)
            + sum(value.transfer_size for _, value in self.parts)
        )

    @property
    def all_bindings(self) -> tuple[str, ...]:
        return tuple(
            sorted(set(self.bindings).union(*(value.all_bindings for _, value in self.parts)))
        )


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
    """Admit every entry before exposing a single combined parent catalog."""
    manifest = load_manifest(root / "dinkster-pack.toml")
    declared = {selected.part for selected in manifest.parts}
    if set(dict(dependencies.parts)) != declared:
        return StageResult(
            (
                AdmissionFinding(
                    "probe.parts-invalid",
                    "error",
                    "block",
                    "Assigned execution-part dependencies differ.",
                ),
            )
        )
    if declared and not install_locks:
        return StageResult(
            (
                AdmissionFinding(
                    "probe.parts-invalid",
                    "error",
                    "block",
                    "Execution parts require published dependency locks.",
                ),
            )
        )
    for variant, binding in (install_locks or {}).items():
        if set(binding.get("parts", {})) != declared:
            return StageResult(
                (
                    AdmissionFinding(
                        "probe.parts-invalid",
                        "error",
                        "block",
                        f"{variant}: declared execution-part locks differ.",
                    ),
                )
            )
    if not declared:
        return _run_selected_probe(
            root,
            dependencies,
            settings=settings,
            require_isolation=require_isolation,
            scan_engine=scan_engine,
            development_release=development_release,
            install_locks=install_locks,
            lock_bytes=lock_bytes,
            artifact_digest=artifact_digest,
            runtime_store=runtime_store,
            development_runtime=development_runtime,
        )
    schemas: list[dict[str, Any]] = []
    findings: list[AdmissionFinding] = []
    details: dict[str, Any] = {}
    owners: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="registry-entry-probes-") as directory:
        for part, selected in ((None, dependencies), *dependencies.parts):
            source = root
            if declared:
                source = Path(directory) / (part or "main")
                shutil.copytree(root, source)
            result = _run_selected_probe(
                source,
                selected,
                settings=settings,
                require_isolation=require_isolation,
                scan_engine=scan_engine,
                development_release=development_release,
                install_locks=install_locks,
                lock_bytes=lock_bytes,
                artifact_digest=artifact_digest,
                runtime_store=runtime_store,
                development_runtime=development_runtime,
                part=part,
            )
            findings.extend(result.findings)
            details[part or "main"] = result.operator_details
            if result.blocked:
                return replace(result, findings=tuple(findings))
            for schema in (result.data or {}).get("schemas", []):
                if schema["nodeType"] in owners:
                    return StageResult(
                        (
                            AdmissionFinding(
                                "probe.node-conflict",
                                "error",
                                "block",
                                "Execution parts publish the same node type.",
                            ),
                        )
                    )
                owners.add(schema["nodeType"])
                schemas.append(schema)
    return StageResult(tuple(findings), {"schemas": schemas}, {"parts": details})


def _run_selected_probe(
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
    part: str | None = None,
) -> StageResult:
    """Probe one entry without catalog or object-store authority."""
    manifest_path = root / "dinkster-pack.toml"
    original = manifest_path.read_bytes()
    manifest = load_manifest(manifest_path, part=part)
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
            selected = document["pack"]
            if part is not None:
                selected = next(item for item in selected["parts"] if item["name"] == part)
            selected["requires"] = list(dependencies.requirements)
            selected.pop("extra-requires", None)
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
                if set(lock_bytes) != {key for key, _ in iter_install_locks(install_locks)}:
                    raise ValueError("Assigned dependency lock variants or parts differ")
                for key, binding in iter_install_locks(install_locks):
                    variant, _, selector = key.partition("~")
                    if binding["artifactDigest"] != artifact_digest:
                        raise ValueError(f"{variant}: lock artifact digest differs from archive")
                    data = lock_bytes[key]
                    if len(data) != binding["size"] or digest_bytes(data) != binding["digest"]:
                        raise ValueError(f"{key}: submitted dependency lock bytes changed")
                    lock = PackLock.from_json(data)
                    if (
                        lock.pack != manifest.name
                        or lock.variant != variant
                        or lock.part != (selector or None)
                    ):
                        raise ValueError(f"{key}: dependency lock pack, variant or part differs")
                    locks[key] = lock
                catalog, variant = scan_catalog(
                    scan_engine, install_locks, mirror=development_runtime
                )
                if manifest.compatibility is not None:
                    manifest.compatibility.require_engine(
                        manifest.name, catalog.channel.engine_version
                    )
                lock = locks[variant if part is None else f"{variant}~{part}"]
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
                        # Validate helper ranges against the locked pack and actual engine
                        # packages, not declaration spelling. This probe-only view never
                        # changes submitted lock bytes or published bindings.
                        generation = GenerationPackages.inspect(python)
                        requirements = tuple(
                            dict.fromkeys(
                                (
                                    *lock.requirements,
                                    *map(normalize_requirement, dependencies.requirements),
                                )
                            )
                        )
                        inherited = {
                            canonicalize_name(Requirement(value).name) for value in requirements
                        } - {package.name for package in lock.packages}
                        if lock.engine is not None:
                            inherited.discard("dinkster-api")
                        probe_lock = replace(
                            lock,
                            requirements=requirements,
                            packages=(
                                *lock.packages,
                                *(
                                    LockedDistribution(name, generation.versions[name], ())
                                    for name in sorted(inherited)
                                    if name in generation.versions
                                ),
                            ),
                        )
                        return run_locked_probe(
                            root,
                            probe_lock,
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
