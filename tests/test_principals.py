from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from dinkster_registry import RegistryError

from dinkster_registry_service.database import Database
from dinkster_registry_service.principals import PrincipalRepository


def _repository(path: Path) -> PrincipalRepository:
    return PrincipalRepository(Database(f"sqlite:///{path}"))


def test_principals_tokens_and_operators_survive_reopen(tmp_path: Path) -> None:
    database_path = tmp_path / "registry.db"
    repository = _repository(database_path)
    now = datetime.now(UTC)
    expires = now + timedelta(hours=1)

    repository.register_user("owner")
    repository.add_operator("owner", "owner", now.isoformat())
    assert repository.register_publisher("example_org", "owner", now.isoformat()) == "example-org"
    plaintext, token = repository.mint_token(
        "example-org",
        "owner",
        now.isoformat(),
        expires.isoformat(),
        pack="example-pack",
        secret="fixed-test-secret",
    )

    reopened = _repository(database_path)
    verified = reopened.verify_token(plaintext, now.isoformat())
    assert verified == token
    reopened.authorize("owner", "example-org", "publish")
    reopened.authorize_token(verified, "example-org", "example-pack")
    assert reopened.is_operator("owner")
    assert [record.action for record in reopened.audit()] == [
        "add-operator",
        "register-publisher",
        "mint-token",
    ]

    reopened.revoke_token(token.token_id, "owner", now.isoformat(), "test complete")
    with pytest.raises(RegistryError, match="revoked"):
        reopened.verify_token(plaintext, now.isoformat())


def test_only_an_operator_can_add_later_operators(tmp_path: Path) -> None:
    repository = _repository(tmp_path / "registry.db")
    now = datetime.now(UTC).isoformat()
    for user in ("first", "second", "outsider"):
        repository.register_user(user)
    repository.add_operator("first", "first", now)

    with pytest.raises(RegistryError, match="not a registry operator"):
        repository.add_operator("second", "outsider", now)

    repository.add_operator("second", "first", now)
    assert repository.is_operator("second")
