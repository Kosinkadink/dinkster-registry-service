from __future__ import annotations

from pathlib import Path

from dinkster_registry.archive_admission import AdmissionFinding, StageResult
from dinkster_registry.archive_admission import run_manifest_admission as check_archive_manifest
from dinkster_schema import claims_conflict
from packaging.specifiers import InvalidSpecifier, SpecifierSet
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
