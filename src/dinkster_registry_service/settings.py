from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from .database import default_object_root


def _environment_integer(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {value!r}") from None


def _require_range(name: str, value: int, minimum: int, maximum: int) -> None:
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}, got {value}")


@dataclass(frozen=True)
class ServerSettings:
    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/dinkster_registry"
    object_store_root: Path = default_object_root()
    public_base_url: str = "http://127.0.0.1:8000"
    cursor_secret: bytes = b"local-cursor-secret-change-in-production"
    probe_timeout_seconds: int = 30
    probe_output_limit_bytes: int = 256 * 1024
    probe_operator_tail_bytes: int = 8 * 1024
    scanner_max_attempts: int = 3

    def __post_init__(self) -> None:
        _require_range("DINKSTER_PROBE_TIMEOUT_SECONDS", self.probe_timeout_seconds, 1, 600)
        _require_range(
            "DINKSTER_PROBE_OUTPUT_LIMIT_BYTES",
            self.probe_output_limit_bytes,
            4 * 1024,
            4 * 1024 * 1024,
        )
        _require_range(
            "DINKSTER_PROBE_OPERATOR_TAIL_BYTES",
            self.probe_operator_tail_bytes,
            512,
            self.probe_output_limit_bytes,
        )
        _require_range("DINKSTER_SCANNER_MAX_ATTEMPTS", self.scanner_max_attempts, 1, 10)

    @classmethod
    def from_environment(cls) -> ServerSettings:
        defaults = cls()
        return cls(
            database_url=os.getenv("DINKSTER_DATABASE_URL", defaults.database_url),
            object_store_root=Path(
                os.getenv("DINKSTER_OBJECT_STORE_ROOT", str(default_object_root()))
            ),
            public_base_url=os.getenv("DINKSTER_PUBLIC_BASE_URL", defaults.public_base_url).rstrip(
                "/"
            ),
            cursor_secret=os.getenv(
                "DINKSTER_CURSOR_SECRET", defaults.cursor_secret.decode("ascii")
            ).encode("utf-8"),
            probe_timeout_seconds=_environment_integer(
                "DINKSTER_PROBE_TIMEOUT_SECONDS", defaults.probe_timeout_seconds
            ),
            probe_output_limit_bytes=_environment_integer(
                "DINKSTER_PROBE_OUTPUT_LIMIT_BYTES", defaults.probe_output_limit_bytes
            ),
            probe_operator_tail_bytes=_environment_integer(
                "DINKSTER_PROBE_OPERATOR_TAIL_BYTES", defaults.probe_operator_tail_bytes
            ),
            scanner_max_attempts=_environment_integer(
                "DINKSTER_SCANNER_MAX_ATTEMPTS", defaults.scanner_max_attempts
            ),
        )
