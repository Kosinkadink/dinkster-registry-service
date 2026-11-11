from __future__ import annotations

import json
import re


class ScanEngineError(ValueError):
    """A scan engine binding does not identify exact trusted release bytes."""


def parse_scan_engine(data: bytes | None) -> dict[str, str] | None:
    if data is None:
        return None
    if not 1 <= len(data) <= 1024:
        raise ScanEngineError("engine binding must contain 1 through 1024 bytes")

    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ScanEngineError(f"duplicate engine field {key!r}")
            result[key] = value
        return result

    try:
        record = json.loads(data, object_pairs_hook=unique)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ScanEngineError("engine binding must be valid JSON with unique fields") from exc
    if not isinstance(record, dict) or set(record) != {"commit", "manifestDigest"}:
        raise ScanEngineError("engine binding requires commit and manifestDigest")
    commit, digest = record["commit"], record["manifestDigest"]
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ScanEngineError("engine binding requires a full Git commit")
    if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise ScanEngineError("engine binding requires an exact sha256 manifest digest")
    return {"commit": commit, "manifestDigest": digest}
