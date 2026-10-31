from __future__ import annotations

import pytest

from dinkster_registry_service.object_store import LocalFilesystemObjectStore, S3ObjectStore
from dinkster_registry_service.settings import ServerSettings

PROBE_ENVIRONMENT_VARIABLES = (
    "DINKSTER_PROBE_TIMEOUT_SECONDS",
    "DINKSTER_PROBE_DEPENDENCY_TIMEOUT_SECONDS",
    "DINKSTER_PROBE_OUTPUT_LIMIT_BYTES",
    "DINKSTER_PROBE_OPERATOR_TAIL_BYTES",
    "DINKSTER_SCANNER_MAX_ATTEMPTS",
)


def test_probe_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "DINKSTER_PROBE_TIMEOUT_SECONDS": "1",
        "DINKSTER_PROBE_DEPENDENCY_TIMEOUT_SECONDS": "73",
        "DINKSTER_PROBE_PACKAGE_INDEX_URL": "http://127.0.0.1:9001/simple",
        "DINKSTER_PROBE_OUTPUT_LIMIT_BYTES": "4096",
        "DINKSTER_PROBE_OPERATOR_TAIL_BYTES": "512",
        "DINKSTER_SCANNER_MAX_ATTEMPTS": "1",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    settings = ServerSettings.from_environment()

    assert settings.probe_timeout_seconds == 1
    assert settings.probe_dependency_timeout_seconds == 73
    assert settings.probe_package_index_url == "http://127.0.0.1:9001/simple"
    assert settings.probe_output_limit_bytes == 4096
    assert settings.probe_operator_tail_bytes == 512
    assert settings.scanner_max_attempts == 1


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("DINKSTER_PROBE_TIMEOUT_SECONDS", "0"),
        ("DINKSTER_PROBE_TIMEOUT_SECONDS", "601"),
        ("DINKSTER_PROBE_DEPENDENCY_TIMEOUT_SECONDS", "0"),
        ("DINKSTER_PROBE_DEPENDENCY_TIMEOUT_SECONDS", "1801"),
        ("DINKSTER_PROBE_OUTPUT_LIMIT_BYTES", "4095"),
        ("DINKSTER_PROBE_OUTPUT_LIMIT_BYTES", "4194305"),
        ("DINKSTER_PROBE_OPERATOR_TAIL_BYTES", "511"),
        ("DINKSTER_PROBE_OPERATOR_TAIL_BYTES", "262145"),
        ("DINKSTER_SCANNER_MAX_ATTEMPTS", "0"),
        ("DINKSTER_SCANNER_MAX_ATTEMPTS", "11"),
        ("DINKSTER_PROBE_TIMEOUT_SECONDS", "not-an-integer"),
    ),
)
def test_invalid_probe_settings_fail_at_load(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    for environment_name in PROBE_ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(environment_name, raising=False)
    monkeypatch.setenv(name, value)

    with pytest.raises(ValueError, match=name):
        ServerSettings.from_environment()


S3_ENVIRONMENT_VARIABLES = (
    "S3_ENDPOINT_URL",
    "S3_BUCKET",
    "S3_ACCESS_KEY_ID",
    "S3_SECRET_ACCESS_KEY",
    "S3_REGION",
)


def test_development_uses_local_object_store_without_s3_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in S3_ENVIRONMENT_VARIABLES:
        monkeypatch.delenv(name, raising=False)

    object_store = ServerSettings.from_environment().create_object_store()

    assert isinstance(object_store, LocalFilesystemObjectStore)


@pytest.mark.parametrize("missing", S3_ENVIRONMENT_VARIABLES)
def test_production_requires_every_s3_setting(
    monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    values = {
        "S3_ENDPOINT_URL": "http://127.0.0.1:9000",
        "S3_BUCKET": "registry-artifacts",
        "S3_ACCESS_KEY_ID": "test-access-key",
        "S3_SECRET_ACCESS_KEY": "test-secret-key",
        "S3_REGION": "us-east-1",
    }
    monkeypatch.setenv("DINKSTER_ENV", "production")
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv(missing)

    with pytest.raises(ValueError, match=missing):
        ServerSettings.from_environment()


def test_development_rejects_partial_s3_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("S3_BUCKET", "registry-artifacts")

    with pytest.raises(ValueError, match="S3_ENDPOINT_URL"):
        ServerSettings.from_environment()


def test_complete_s3_settings_select_s3_store(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "S3_ENDPOINT_URL": "http://127.0.0.1:9000",
        "S3_BUCKET": "registry-artifacts",
        "S3_ACCESS_KEY_ID": "test-access-key",
        "S3_SECRET_ACCESS_KEY": "test-secret-key",
        "S3_REGION": "us-east-1",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    settings = ServerSettings.from_environment()

    assert isinstance(settings.create_object_store(), S3ObjectStore)
    assert "test-access-key" not in repr(settings)
    assert "test-secret-key" not in repr(settings)


def test_database_and_public_base_url_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DINKSTER_DATABASE_URL", raising=False)
    monkeypatch.delenv("DINKSTER_PUBLIC_BASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://registry.example.test/")

    settings = ServerSettings.from_environment()

    assert settings.database_url == "sqlite+pysqlite:///:memory:"
    assert settings.public_base_url == "https://registry.example.test"


def test_dinkster_database_and_public_base_url_override_aliases(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "sqlite+pysqlite:///:memory:")
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://registry.example.test/")
    monkeypatch.setenv("DINKSTER_DATABASE_URL", "sqlite+pysqlite:///primary.db")
    monkeypatch.setenv("DINKSTER_PUBLIC_BASE_URL", "https://primary.example.test/")

    settings = ServerSettings.from_environment()

    assert settings.database_url == "sqlite+pysqlite:///primary.db"
    assert settings.public_base_url == "https://primary.example.test"
