from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal, cast

from dinkster_registry.archive_admission import ProbeSettings

from .database import default_object_root

if TYPE_CHECKING:
    from .object_store import ObjectStore


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


def _environment_value(primary: str, alias: str, default: str) -> str:
    return os.getenv(primary, os.getenv(alias, default))


@dataclass(frozen=True)
class ServerSettings(ProbeSettings):
    database_url: str = "postgresql+psycopg://postgres:postgres@localhost:5432/dinkster_registry"
    object_store_root: Path = default_object_root()
    public_base_url: str = "http://127.0.0.1:8000"
    environment: str = "development"
    s3_endpoint_url: str | None = None
    s3_bucket: str | None = None
    s3_access_key_id: str | None = field(default=None, repr=False)
    s3_secret_access_key: str | None = field(default=None, repr=False)
    s3_region: str | None = None
    cursor_secret: bytes = b"local-cursor-secret-change-in-production"
    scanner_max_attempts: int = 3
    scanner_token_sha256: str | None = field(default=None, repr=False)
    scanner_fly_app: str | None = None
    scanner_machine_ids: tuple[str, ...] = ()
    scanner_machine_limit: int = 1
    scanner_fly_token: str | None = field(default=None, repr=False)
    identity_issuer: str = "https://id.dinkster.org"
    identity_audience: str = "dinkster-registry"
    security_signing_key_path: Path | None = field(default=None, repr=False)
    probe_engine_release: Path | None = None
    probe_runtime_mirror: Path | None = None

    def __post_init__(self) -> None:
        if self.scanner_fly_app or self.scanner_machine_ids or self.scanner_fly_token:
            if (
                self.scanner_fly_app is None
                or re.fullmatch(r"[a-z][a-z0-9-]{0,62}", self.scanner_fly_app) is None
                or self.scanner_fly_app == os.getenv("FLY_APP_NAME")
                or not self.scanner_machine_ids
                or len(self.scanner_machine_ids) != len(set(self.scanner_machine_ids))
                or len(self.scanner_machine_ids) > 8
                or any(
                    re.fullmatch(r"[0-9a-f]{14,16}", value) is None
                    for value in self.scanner_machine_ids
                )
                or not self.scanner_fly_token
                or "\n" in self.scanner_fly_token
                or "\r" in self.scanner_fly_token
                or self.scanner_token_sha256 is None
            ):
                raise ValueError(
                    "Scanner lifecycle requires a separate DINKSTER_SCANNER_FLY_APP, "
                    "registered DINKSTER_SCANNER_MACHINE_IDS, DINKSTER_SCANNER_FLY_TOKEN "
                    "and worker verifier"
                )
            _require_range(
                "DINKSTER_SCANNER_MACHINE_LIMIT",
                self.scanner_machine_limit,
                1,
                len(self.scanner_machine_ids),
            )
        else:
            _require_range("DINKSTER_SCANNER_MACHINE_LIMIT", self.scanner_machine_limit, 1, 8)
        if (
            self.scanner_token_sha256 is not None
            and re.fullmatch(r"[0-9a-f]{64}", self.scanner_token_sha256) is None
        ):
            raise ValueError("DINKSTER_SCANNER_TOKEN_SHA256 must be a lowercase SHA256 digest")
        if (
            self.probe_engine_release is not None or self.probe_runtime_mirror is not None
        ) and self.environment != "development":
            raise ValueError("local probe engine inputs are allowed only in development")
        if self.probe_dependency_source not in {"cpu", "index"}:
            raise ValueError("DINKSTER_PROBE_DEPENDENCY_SOURCE must be cpu or index")
        _require_range("DINKSTER_PROBE_TIMEOUT_SECONDS", self.probe_timeout_seconds, 1, 600)
        _require_range(
            "DINKSTER_PROBE_DEPENDENCY_TIMEOUT_SECONDS",
            self.probe_dependency_timeout_seconds,
            1,
            1800,
        )
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
        missing_s3 = self.missing_s3_settings()
        if self.environment == "production" and missing_s3:
            raise ValueError("production requires S3 settings: " + ", ".join(missing_s3))
        if self.has_any_s3_setting() and missing_s3:
            raise ValueError("incomplete S3 settings: " + ", ".join(missing_s3))

    @classmethod
    def from_environment(cls) -> ServerSettings:
        defaults = cls()
        return cls(
            database_url=_environment_value(
                "DINKSTER_DATABASE_URL", "DATABASE_URL", defaults.database_url
            ),
            object_store_root=Path(
                os.getenv("DINKSTER_OBJECT_STORE_ROOT", str(default_object_root()))
            ),
            public_base_url=_environment_value(
                "DINKSTER_PUBLIC_BASE_URL", "PUBLIC_BASE_URL", defaults.public_base_url
            ).rstrip("/"),
            environment=os.getenv("DINKSTER_ENV", defaults.environment),
            probe_engine_release=Path(os.environ["DINKSTER_PROBE_ENGINE_RELEASE"])
            if os.getenv("DINKSTER_PROBE_ENGINE_RELEASE")
            else None,
            probe_runtime_mirror=Path(os.environ["DINKSTER_PROBE_RUNTIME_MIRROR"])
            if os.getenv("DINKSTER_PROBE_RUNTIME_MIRROR")
            else None,
            identity_issuer=os.getenv("DINKSTER_IDENTITY_ISSUER", defaults.identity_issuer).rstrip(
                "/"
            ),
            identity_audience=os.getenv("DINKSTER_IDENTITY_AUDIENCE", defaults.identity_audience),
            security_signing_key_path=Path(os.environ["DINKSTER_SECURITY_SIGNING_KEY_PATH"])
            if os.getenv("DINKSTER_SECURITY_SIGNING_KEY_PATH")
            else None,
            s3_endpoint_url=os.getenv("S3_ENDPOINT_URL"),
            s3_bucket=os.getenv("S3_BUCKET"),
            s3_access_key_id=os.getenv("S3_ACCESS_KEY_ID"),
            s3_secret_access_key=os.getenv("S3_SECRET_ACCESS_KEY"),
            s3_region=os.getenv("S3_REGION"),
            cursor_secret=os.getenv(
                "DINKSTER_CURSOR_SECRET", defaults.cursor_secret.decode("ascii")
            ).encode("utf-8"),
            probe_timeout_seconds=_environment_integer(
                "DINKSTER_PROBE_TIMEOUT_SECONDS", defaults.probe_timeout_seconds
            ),
            probe_dependency_timeout_seconds=_environment_integer(
                "DINKSTER_PROBE_DEPENDENCY_TIMEOUT_SECONDS",
                defaults.probe_dependency_timeout_seconds,
            ),
            probe_package_index_url=os.getenv(
                "DINKSTER_PROBE_PACKAGE_INDEX_URL", defaults.probe_package_index_url
            ),
            probe_dependency_source=cast(
                Literal["cpu", "index"],
                os.getenv("DINKSTER_PROBE_DEPENDENCY_SOURCE", defaults.probe_dependency_source),
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
            scanner_token_sha256=os.getenv("DINKSTER_SCANNER_TOKEN_SHA256"),
            scanner_fly_app=os.getenv("DINKSTER_SCANNER_FLY_APP"),
            scanner_machine_ids=tuple(
                filter(None, os.getenv("DINKSTER_SCANNER_MACHINE_IDS", "").split(","))
            ),
            scanner_machine_limit=_environment_integer(
                "DINKSTER_SCANNER_MACHINE_LIMIT", defaults.scanner_machine_limit
            ),
            scanner_fly_token=os.getenv("DINKSTER_SCANNER_FLY_TOKEN"),
        )

    def probe_settings(self) -> ProbeSettings:
        return ProbeSettings(
            probe_timeout_seconds=self.probe_timeout_seconds,
            probe_dependency_timeout_seconds=self.probe_dependency_timeout_seconds,
            probe_package_index_url=self.probe_package_index_url,
            probe_dependency_source=self.probe_dependency_source,
            probe_output_limit_bytes=self.probe_output_limit_bytes,
            probe_operator_tail_bytes=self.probe_operator_tail_bytes,
        )

    def has_any_s3_setting(self) -> bool:
        return any(
            value is not None
            for value in (
                self.s3_endpoint_url,
                self.s3_bucket,
                self.s3_access_key_id,
                self.s3_secret_access_key,
                self.s3_region,
            )
        )

    def missing_s3_settings(self) -> tuple[str, ...]:
        settings = (
            ("S3_ENDPOINT_URL", self.s3_endpoint_url),
            ("S3_BUCKET", self.s3_bucket),
            ("S3_ACCESS_KEY_ID", self.s3_access_key_id),
            ("S3_SECRET_ACCESS_KEY", self.s3_secret_access_key),
            ("S3_REGION", self.s3_region),
        )
        return tuple(name for name, value in settings if not value)

    def create_object_store(self) -> ObjectStore:
        from .object_store import LocalFilesystemObjectStore, S3ObjectStore

        if not self.has_any_s3_setting():
            return LocalFilesystemObjectStore(self.object_store_root)
        missing_s3 = self.missing_s3_settings()
        if missing_s3:
            raise ValueError("incomplete S3 settings: " + ", ".join(missing_s3))
        assert self.s3_endpoint_url is not None
        assert self.s3_bucket is not None
        assert self.s3_access_key_id is not None
        assert self.s3_secret_access_key is not None
        assert self.s3_region is not None
        return S3ObjectStore(
            endpoint_url=self.s3_endpoint_url,
            bucket=self.s3_bucket,
            access_key_id=self.s3_access_key_id,
            secret_access_key=self.s3_secret_access_key,
            region=self.s3_region,
        )
