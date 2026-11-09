from __future__ import annotations

from pathlib import Path

from dinkster_registry.archive_admission import AdmissionFinding, StageResult
from dinkster_registry.archive_admission import run_manifest_admission as check_archive_manifest
from dinkster_schema import (
    claims_conflict,
    comfy_group_registry_to_wire,
)
from dinkster_workers.manifest import load_manifest
from packaging.requirements import Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import (
    NamespaceGrantRecord,
    PackRecord,
    ReleaseDependencyRecord,
    ReleaseRecord,
)
from .versioning import VersionError, public_version_key
from .wheels import Wheel, WheelError


def check_wheel_catalog(wheel: Wheel, session: Session) -> None:
    """Check again under the promotion lock so concurrent scans cannot claim an import."""
    rows = session.execute(
        select(PackRecord, ReleaseRecord).join(
            ReleaseRecord, ReleaseRecord.pack_id == PackRecord.id
        )
    ).all()
    required = {canonicalize_name(Requirement(value).name) for value in wheel.requirements}
    for pack, release in rows:
        previous = release.manifest.get("wheel", {})
        library = previous.get("library", False)
        if pack.name == wheel.name:
            if library != wheel.library:
                raise WheelError("wheel.library-claims", "A distribution cannot change pack kind.")
            continue
        imports = previous.get("imports", [pack.name.replace("-", "_").replace(".", "_")])
        if set(imports).intersection(wheel.imports):
            raise WheelError(
                "wheel.import-conflict", f"Top-level import already belongs to {pack.name!r}."
            )
        if canonicalize_name(pack.name) in required and not library:
            raise WheelError(
                "wheel.requires-pack", f"Requires-Dist names pack {pack.name!r}, not a library."
            )
        if not wheel.library:
            existing_requirements = release.manifest.get("pythonRequirements", [])
            if any(
                canonicalize_name(Requirement(value).name) == canonicalize_name(wheel.name)
                for value in existing_requirements
            ):
                raise WheelError(
                    "wheel.requires-pack",
                    f"Existing release {pack.name!r} requires this name as a library.",
                )
    if not wheel.library and canonicalize_name(wheel.name) in required:
        raise WheelError("wheel.requires-pack", "A pack cannot require itself as a library.")


def run_manifest_admission(
    root: Path,
    pack_name: str,
    release_version: str,
    session: Session,
    *,
    rescan: bool = False,
    publisher: str | None = None,
) -> StageResult:
    result = check_archive_manifest(root, pack_name, release_version, publisher=publisher)
    if result.blocked:
        return result
    assert result.data is not None
    metadata = result.data
    try:
        manifest = load_manifest(root / "dinkster-pack.toml")
        if manifest.publisher and manifest.publisher != publisher:
            return StageResult(
                (
                    AdmissionFinding(
                        "manifest.publisher-mismatch",
                        "error",
                        "block",
                        "Manifest publisher differs from the authenticated publisher.",
                    ),
                )
            )
        if manifest.comfy_groups is not None:
            if publisher != "dinkster":
                raise ValueError("translation records require the Dinkster publisher")
            metadata["translations"] = [
                {
                    "name": pack_name,
                    "version": release_version,
                    "publisher": publisher,
                    "groups": (
                        comfy_group_registry_to_wire(manifest.comfy_groups)
                        if manifest.comfy_groups is not None
                        else None
                    ),
                }
            ]
        pack = session.scalar(select(PackRecord).where(PackRecord.name == pack_name))
        if pack is not None and not rescan:
            conflict = session.scalar(
                select(ReleaseRecord.id).where(
                    ReleaseRecord.pack_id == pack.id,
                    (
                        (ReleaseRecord.version == release_version)
                        | (ReleaseRecord.version_key == public_version_key(release_version))
                    ),
                )
            )
            if conflict is not None:
                raise ValueError("release version or semantic collision key already exists")
        grants = session.execute(select(NamespaceGrantRecord, PackRecord).join(PackRecord)).all()
        for claim in (pack_name, *metadata["namespaces"]):
            for grant, granted_pack in grants:
                if (
                    granted_pack.name != pack_name
                    and not (publisher is not None and grant.publisher_id == publisher)
                    and claims_conflict(claim, grant.claim)
                ):
                    raise ValueError(
                        f"namespace claim {claim!r} conflicts with pack {granted_pack.name!r}"
                    )
        active_releases = session.execute(
            select(ReleaseRecord, PackRecord)
            .join(PackRecord, PackRecord.id == ReleaseRecord.pack_id)
            .where(ReleaseRecord.state == "active", PackRecord.visibility == "public")
        ).all()
        releases_by_pack: dict[str, list[ReleaseRecord]] = {}
        for active_release, active_pack in active_releases:
            releases_by_pack.setdefault(active_pack.name, []).append(active_release)
        for dependency in metadata["dependencies"]:
            name = dependency["packName"]
            version_range = dependency["versionRange"]
            versions = releases_by_pack.get(name, [])
            required = SpecifierSet(version_range)
            if not any(
                required.contains(Version(value.version), prereleases=True) for value in versions
            ):
                raise ValueError(
                    f"dependency {name!r} has no active public version satisfying {version_range!r}"
                )

        dependency_rows = session.execute(
            select(ReleaseDependencyRecord, ReleaseRecord, PackRecord)
            .join(ReleaseRecord, ReleaseRecord.id == ReleaseDependencyRecord.release_id)
            .join(PackRecord, PackRecord.id == ReleaseRecord.pack_id)
            .where(ReleaseRecord.state == "active")
        ).all()
        active_graph: dict[str, set[str]] = {}
        for dependency_row, _, dependency_pack in dependency_rows:
            active_graph.setdefault(dependency_pack.name, set()).add(dependency_row.pack_name)
        pending = [dependency["packName"] for dependency in metadata["dependencies"]]
        visited: set[str] = set()
        while pending:
            dependency_name = pending.pop()
            if dependency_name == pack_name:
                raise ValueError("pack dependencies contain a cycle")
            if dependency_name in visited:
                continue
            visited.add(dependency_name)
            pending.extend(active_graph.get(dependency_name, ()))
    except (InvalidSpecifier, ValueError, VersionError) as exc:
        return StageResult((AdmissionFinding("manifest.invalid", "error", "block", str(exc)),))
    return result
