from __future__ import annotations

import re

from blake3 import blake3

DIGEST_PREFIX = "blake3:"
DIGEST_PATTERN = re.compile(r"^blake3:[0-9a-f]{64}$")


class DigestError(ValueError):
    """A value is not a supported artifact digest."""


def require_blake3_digest(value: str) -> str:
    if DIGEST_PATTERN.fullmatch(value) is None:
        raise DigestError(
            "artifact digest must use blake3:<64 lowercase hex>; other algorithms are "
            "unsupported, so rebuild or reinstall the pack"
        )
    return value


def artifact_digest(data: bytes) -> str:
    return DIGEST_PREFIX + blake3(data).hexdigest()


def artifact_object_key(digest: str) -> str:
    checked = require_blake3_digest(digest)
    hex_digest = checked.removeprefix(DIGEST_PREFIX)
    return f"artifacts/blake3/{hex_digest[:2]}/{hex_digest}.dinksterpack.zip"
