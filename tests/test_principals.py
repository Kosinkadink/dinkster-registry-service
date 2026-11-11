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


def test_operator_freeze_revokes_all_scopes_and_prevents_new_tokens(tmp_path: Path) -> None:
    path = tmp_path / "registry.db"
    repository = _repository(path)
    now = datetime.now(UTC)
    expires = (now + timedelta(days=1)).isoformat()
    for user in ("operator", "owner"):
        repository.register_user(user)
    repository.add_operator("operator", "operator", now.isoformat())
    repository.register_publisher("disputed", "owner", now.isoformat())
    repository.register_publisher("unaffected", "owner", now.isoformat())
    tokens = [
        repository.mint_token("disputed", "owner", now.isoformat(), expires, pack=pack)[0]
        for pack in (None, "example-pack")
    ]
    unaffected, _ = repository.mint_token("unaffected", "owner", now.isoformat(), expires)
    with pytest.raises(RegistryError, match="registry operator"):
        repository.freeze_publisher("disputed", "owner", now.isoformat(), "disputed ownership")
    for token in tokens:
        assert repository.verify_token(token, now.isoformat()).publisher == "disputed"

    repository.freeze_publisher("disputed", "operator", now.isoformat(), "disputed ownership")
    reopened = _repository(path)
    for token in tokens:
        with pytest.raises(RegistryError, match="revoked"):
            reopened.verify_token(token, now.isoformat())
    with pytest.raises(RegistryError, match="frozen"):
        reopened.mint_token("disputed", "owner", now.isoformat(), expires)
    assert reopened.verify_token(unaffected, now.isoformat()).publisher == "unaffected"
    events = reopened.audit()
    assert [event.action for event in events[-3:]] == [
        "freeze-publisher",
        "revoke-token",
        "revoke-token",
    ]
    assert all(event.actor == "operator" for event in events[-3:])
    reopened.freeze_publisher("disputed", "operator", now.isoformat(), "repeat")
    assert reopened.audit() == events
