from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID

from dinkster_registry.archive_admission import AdmissionFinding, StageResult
from dinkster_registry.archive_admission import run_manifest_admission as check_archive_manifest
from dinkster_schema import claims_conflict
from dinkster_workers.manifest import load_manifest
from packaging.requirements import Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import Version
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import (
    ArtifactRecord,
    NamespaceGrantRecord,
    PackRecord,
    ReleaseCandidateRecord,
    ReleaseRecord,
)
from .digests import artifact_digest
from .object_store import MAX_ARTIFACT_SIZE, ObjectStore
from .versioning import VersionError, public_version_key
from .wheels import Wheel, WheelError, extracted_wheel, inspect_wheel


@dataclass(frozen=True)
class DependencyRelease:
    name: str
    version: str
    digest: str
    size: int
    object_key: str
    metadata: dict[str, Any] | None
    available: bool

    @property
    def binding(self) -> str:
        return f"{self.name}=={self.version}#{self.digest}"

    def read(self, store: ObjectStore) -> tuple[Wheel, bytes]:
        data = store.read(self.object_key, max_size=MAX_ARTIFACT_SIZE)
        if artifact_digest(data) != self.digest or len(data) != self.size:
            raise ValueError(f"Dependency artifact changed for {self.name!r}.")
        return inspect_wheel(data, self.name, self.version), data

    def pack_dependencies(self, store: ObjectStore | None) -> tuple[str, ...]:
        if self.metadata is not None:
            if self.metadata.get("kind") == "library":
                raise ValueError("Pack dependencies must name packs, not libraries.")
            return tuple(row["packName"] for row in self.metadata["dependencies"])
        assert store is not None
        wheel, data = self.read(store)
        if wheel.library:
            raise ValueError("Pack dependencies must name packs, not libraries.")
        with extracted_wheel(data, wheel) as root:
            manifest = load_manifest(root / "dinkster-pack.toml")
            return tuple(row.pack for row in manifest.dependencies)


def dependency_releases(session: Session, set_id: UUID | None = None) -> list[DependencyRelease]:
    """Keep known library identities, but resolve only public active or same-set bytes."""
    rows = session.execute(
        select(PackRecord, ReleaseRecord, ArtifactRecord)
        .join(ReleaseRecord, ReleaseRecord.pack_id == PackRecord.id)
        .join(ArtifactRecord, ArtifactRecord.digest == ReleaseRecord.artifact_digest)
    ).all()
    releases = []
    for pack, release, artifact in rows:
        releases.append(
            DependencyRelease(
                pack.name,
                release.version,
                artifact.digest,
                artifact.size,
                artifact.object_key,
                release.manifest,
                pack.visibility == "public" and release.state == "active",
            )
        )
    if set_id is not None:
        for candidate in session.scalars(
            select(ReleaseCandidateRecord).where(ReleaseCandidateRecord.set_id == set_id)
        ):
            releases.append(
                DependencyRelease(
                    candidate.pack_name,
                    candidate.version,
                    candidate.declared_digest,
                    candidate.declared_size,
                    candidate.object_key,
                    candidate.manifest,
                    candidate.status != "rejected",
                )
            )
    return releases


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
    dependencies: list[DependencyRelease] | None = None,
    object_store: ObjectStore | None = None,
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
        releases_by_pack: dict[str, list[DependencyRelease]] = {}
        for release in dependency_releases(session) if dependencies is None else dependencies:
            if release.available:
                releases_by_pack.setdefault(release.name, []).append(release)
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

        pending = [dependency["packName"] for dependency in metadata["dependencies"]]
        visited: set[str] = set()
        while pending:
            dependency_name = pending.pop()
            if dependency_name == pack_name:
                raise ValueError("pack dependencies contain a cycle")
            if dependency_name in visited:
                continue
            visited.add(dependency_name)
            for release in releases_by_pack.get(dependency_name, ()):
                pending.extend(release.pack_dependencies(object_store))
    except (InvalidSpecifier, ValueError, VersionError) as exc:
        return StageResult((AdmissionFinding("manifest.invalid", "error", "block", str(exc)),))
    return result
