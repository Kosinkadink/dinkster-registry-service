from __future__ import annotations

import secrets
import time
from uuid import UUID


def uuid7() -> UUID:
    milliseconds = int(time.time() * 1000) & ((1 << 48) - 1)
    value = milliseconds << 80
    value |= 0x7 << 76
    value |= secrets.randbits(12) << 64
    value |= 0b10 << 62
    value |= secrets.randbits(62)
    return UUID(int=value)
