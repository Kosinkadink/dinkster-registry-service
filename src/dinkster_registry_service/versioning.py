from __future__ import annotations

from packaging.version import InvalidVersion, Version


class VersionError(ValueError):
    """A version is not a normalized public PEP 440 version."""


def require_public_version(value: str) -> str:
    try:
        version = Version(value)
    except InvalidVersion as exc:
        raise VersionError(f"invalid public PEP 440 version: {value!r}") from exc
    if version.local is not None:
        raise VersionError("local PEP 440 versions are not supported by the registry")
    if str(version) != value:
        raise VersionError(f"version must use normalized PEP 440 form: {str(version)!r}")
    return value


def public_version_key(value: str) -> str:
    version = Version(require_public_version(value))
    release = list(version.release)
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    key = (f"{version.epoch}!" if version.epoch else "") + ".".join(map(str, release))
    if version.pre is not None:
        key += f"{version.pre[0]}{version.pre[1]}"
    if version.post is not None:
        key += f".post{version.post}"
    if version.dev is not None:
        key += f".dev{version.dev}"
    return key
