from __future__ import annotations

import json
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from dinkster_workers.pack_lock import PackLock
from dinkster_workers.provision import ProvisionError

from .digests import artifact_digest

MAX_LOCKS_SIZE = 8 * 1024 * 1024
MAX_LOCK_SIZE = 1024 * 1024
MAX_BASE_VARIANTS = 32


class PackLocksError(ValueError):
    """Published dependency locks do not bind to the submitted pack and base."""


@dataclass(frozen=True)
class PublishedPackLock:
    variant: str
    base_id: str
    data: bytes

    @property
    def digest(self) -> str:
        return artifact_digest(self.data)


def lock_object_key(digest: str) -> str:
    from .digests import require_blake3_digest

    checked = require_blake3_digest(digest).removeprefix("blake3:")
    return f"pack-locks/blake3/{checked[:2]}/{checked}.json"


def quarantine_lock_key(candidate: object, variant: str) -> str:
    return f"quarantine/locks/{candidate}/{variant}.json"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PackLocksError(f"duplicate lock field {key!r}")
        result[key] = value
    return result


def parse_pack_locks(data: bytes, *, pack: str, digest: str) -> tuple[PublishedPackLock, ...]:
    """Validate the complete submitted map without resolving or importing pack code."""
    if not 1 <= len(data) <= MAX_LOCKS_SIZE:
        raise PackLocksError(f"locks must contain 1 through {MAX_LOCKS_SIZE} bytes")
    try:
        document = json.loads(data, object_pairs_hook=_unique_object)
        if not isinstance(document, dict) or not 1 <= len(document) <= MAX_BASE_VARIANTS:
            raise PackLocksError("locks must be a nonempty variant map with at most32 entries")
        result: list[PublishedPackLock] = []
        with tempfile.TemporaryDirectory(prefix="registry-pack-locks-") as temporary:
            path = Path(temporary) / "lock.json"
            for variant, binding in sorted(document.items()):
                if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", variant) is None:
                    raise PackLocksError("lock variant must be a portable variant name")
                if not isinstance(binding, dict) or set(binding) != {
                    "baseId",
                    "artifactDigest",
                    "lock",
                }:
                    raise PackLocksError(f"{variant}: expected baseId, artifactDigest and lock")
                base = binding["baseId"]
                if not isinstance(base, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", base) is None:
                    raise PackLocksError(f"{variant}: expected an exact sha256 base identity")
                if binding["artifactDigest"] != digest:
                    raise PackLocksError(f"{variant}: lock artifact digest differs from archive")
                record = binding["lock"]
                if not isinstance(record, dict) or any(
                    not isinstance(record.get(field), str)
                    for field in ("format", "pack", "variant", "requiresPython")
                ):
                    raise PackLocksError(f"{variant}: dependency lock requires string identities")
                for field in ("requirements", "indexes"):
                    values = record.get(field)
                    if not isinstance(values, list) or any(
                        not isinstance(value, str) for value in values
                    ):
                        raise PackLocksError(f"{variant}: {field} must be an array of strings")
                packages = record.get("packages")
                if not isinstance(packages, list):
                    raise PackLocksError(f"{variant}: packages must be an array")
                for package in packages:
                    if not isinstance(package, dict) or any(
                        not isinstance(package.get(field), str) for field in ("name", "version")
                    ):
                        raise PackLocksError(f"{variant}: package identity must be strings")
                    wheels = package.get("wheels")
                    if not isinstance(wheels, list) or not wheels:
                        raise PackLocksError(f"{variant}: package wheels must be a nonempty array")
                    for wheel in wheels:
                        if (
                            not isinstance(wheel, dict)
                            or type(wheel.get("size")) is not int
                            or any(
                                not isinstance(wheel.get(field), str)
                                for field in ("filename", "sha256", "url")
                            )
                        ):
                            raise PackLocksError(f"{variant}: invalid wheel field types")
                payload = json.dumps(
                    record, sort_keys=True, separators=(",", ":"), allow_nan=False
                ).encode("ascii")
                if len(payload) > MAX_LOCK_SIZE:
                    raise PackLocksError(
                        f"{variant}: dependency lock exceeds {MAX_LOCK_SIZE} bytes"
                    )
                path.write_bytes(payload)
                lock = PackLock.read(path)
                if lock.pack != pack or lock.variant != variant:
                    raise PackLocksError(f"{variant}: dependency lock pack or variant differs")
                for package in lock.packages:
                    for wheel in package.wheels:
                        origin = urlparse(wheel.url)
                        if (
                            wheel.size < 1
                            or origin.scheme not in {"https", "http"}
                            or not origin.hostname
                            or origin.username is not None
                            or origin.password is not None
                        ):
                            raise PackLocksError(
                                f"{variant}: published wheels require credential-free HTTP origins"
                            )
                result.append(PublishedPackLock(variant, base, payload))
        return tuple(result)
    except (KeyError, TypeError, ValueError, ProvisionError) as exc:
        raise PackLocksError(f"invalid published pack locks: {exc}") from exc
