from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from dinkster_registry import TOKEN_PREFIX

from dinkster_registry_service.cli import main
from dinkster_registry_service.database import Database
from dinkster_registry_service.principals import PrincipalRepository


def _run(monkeypatch: pytest.MonkeyPatch, *arguments: str) -> None:
    monkeypatch.setattr(sys, "argv", ["dinkster-registry", *arguments])
    main()


def test_admin_cli_bootstraps_the_unified_service(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    database_url = f"sqlite:///{tmp_path / 'registry.db'}"
    base = ("admin", "--database-url", database_url)

    _run(monkeypatch, *base, "add-user", "owner", "--operator")
    _run(monkeypatch, *base, "add-publisher", "example-org", "--owner", "owner")
    expires = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    _run(
        monkeypatch,
        *base,
        "mint-token",
        "example-org",
        "--user",
        "owner",
        "--expires",
        expires,
        "--pack",
        "example-pack",
    )

    output = capsys.readouterr().out.splitlines()
    plaintext = next(line for line in output if line.startswith(TOKEN_PREFIX))
    database = Database(database_url)
    try:
        principals = PrincipalRepository(database)
        token = principals.verify_token(plaintext, datetime.now(UTC).isoformat())
        principals.authorize("owner", "example-org", "publish")
        principals.authorize_token(token, "example-org", "example-pack")
        assert principals.is_operator("owner")
    finally:
        database.dispose()
