from __future__ import annotations

import pytest

from dinkster_registry_service.settings import ServerSettings

PROBE_ENVIRONMENT_VARIABLES = (
    "DINKSTER_PROBE_TIMEOUT_SECONDS",
    "DINKSTER_PROBE_OUTPUT_LIMIT_BYTES",
    "DINKSTER_PROBE_OPERATOR_TAIL_BYTES",
    "DINKSTER_SCANNER_MAX_ATTEMPTS",
)


def test_probe_settings_load_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    values = {
        "DINKSTER_PROBE_TIMEOUT_SECONDS": "1",
        "DINKSTER_PROBE_OUTPUT_LIMIT_BYTES": "4096",
        "DINKSTER_PROBE_OPERATOR_TAIL_BYTES": "512",
        "DINKSTER_SCANNER_MAX_ATTEMPTS": "1",
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)

    settings = ServerSettings.from_environment()

    assert settings.probe_timeout_seconds == 1
    assert settings.probe_output_limit_bytes == 4096
    assert settings.probe_operator_tail_bytes == 512
    assert settings.scanner_max_attempts == 1


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("DINKSTER_PROBE_TIMEOUT_SECONDS", "0"),
        ("DINKSTER_PROBE_TIMEOUT_SECONDS", "601"),
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
