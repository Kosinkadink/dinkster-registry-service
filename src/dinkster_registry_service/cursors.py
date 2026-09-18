from __future__ import annotations

import base64
import json
import secrets
from collections.abc import Mapping
from typing import Any

from blake3 import blake3


class CursorError(ValueError):
    """A pagination cursor is malformed or bound to another selection."""


class CursorCodec:
    def __init__(self, secret: bytes) -> None:
        self._key = blake3(secret).digest()

    def issue(self, endpoint: str, query: Mapping[str, object], offset: int) -> str:
        body = json.dumps(
            {"endpoint": endpoint, "offset": offset, "query": query},
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        signature = blake3(body, key=self._key).digest(length=16)
        return base64.urlsafe_b64encode(body + signature).decode("ascii").rstrip("=")

    def verify(self, token: str, endpoint: str, query: Mapping[str, object]) -> int:
        try:
            padding = "=" * (-len(token) % 4)
            encoded = (token + padding).encode("ascii")
            decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
            body, signature = decoded[:-16], decoded[-16:]
            if len(body) == 0 or not secrets.compare_digest(
                signature, blake3(body, key=self._key).digest(length=16)
            ):
                raise CursorError("cursor signature is invalid")
            payload: Any = json.loads(body)
        except (UnicodeEncodeError, ValueError, json.JSONDecodeError) as exc:
            raise CursorError("cursor is malformed") from exc
        if not isinstance(payload, dict):
            raise CursorError("cursor payload is invalid")
        if payload.get("endpoint") != endpoint or payload.get("query") != dict(query):
            raise CursorError("cursor does not match this request")
        offset = payload.get("offset")
        if not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
            raise CursorError("cursor offset is invalid")
        return offset
