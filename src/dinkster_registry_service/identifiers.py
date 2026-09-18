from __future__ import annotations

from dinkster_schema import canonical_name, validate_name


class IdentifierError(ValueError):
    """A registry identifier violates the shared Dinkster grammar."""


def require_canonical_pack_name(value: str) -> str:
    problem = validate_name(value)
    if problem is not None:
        raise IdentifierError(f"invalid pack name {value!r}: {problem}")
    canonical = canonical_name(value)
    if canonical != value:
        raise IdentifierError(f"pack name must use canonical hyphen spelling: {canonical!r}")
    return value
