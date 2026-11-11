from __future__ import annotations

import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from dinkster_registry import TOKEN_PREFIX, RegistryError
from fastapi.testclient import TestClient
from sqlalchemy import delete, select, update
from sqlalchemy.exc import DatabaseError

from dinkster_registry_service.cli import main
from dinkster_registry_service.database import (
    AuditEventRecord,
    Database,
    PublisherBindingRecord,
    PublisherMembershipRecord,
    ReleaseRecord,
)
from dinkster_registry_service.indexes import StaticIndexes
from dinkster_registry_service.object_store import LocalFilesystemObjectStore, ObjectStoreError
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


@pytest.mark.parametrize("backend", ["sqlite", "postgresql"])
def test_publisher_binding_and_transfer_are_audited_and_revoke_previous_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    request: pytest.FixtureRequest,
    backend: str,
) -> None:
    if backend == "postgresql":
        request.getfixturevalue("database")
        url = request.getfixturevalue("database_url")
    else:
        url = f"sqlite:///{tmp_path / 'registry.db'}"
    base = ("admin", "--database-url", url)
    _run(monkeypatch, *base, "add-user", "operator", "--operator")
    _run(monkeypatch, *base, "add-user", "owner")
    _run(monkeypatch, *base, "add-publisher", "reserved-name", "--owner", "owner")
    database = Database(url)
    principals = PrincipalRepository(database)
    now = datetime.now(UTC)
    secret, _ = principals.mint_token(
        "reserved-name", "owner", now.isoformat(), (now + timedelta(days=1)).isoformat()
    )
    first = f"u_{uuid4()}"
    second = f"org:{uuid4()}"

    def bind(
        target: str, previous: str, *, actor: str = "operator", reason: str = "Confirmed"
    ) -> None:
        _run(
            monkeypatch,
            *base,
            "bind-publisher",
            "reserved-name",
            "--user",
            actor,
            "--identity-subject",
            target,
            "--expected-owner",
            previous,
            "--reason",
            reason,
        )

    try:
        with pytest.raises(SystemExit, match="registry operator"):
            bind(first, "unbound", actor="owner")
        bind(first, "unbound")
        # Initial binding preserves the existing first-party publishing token until cutover.
        assert principals.verify_token(secret, now.isoformat()).publisher == "reserved-name"
        principals.authorize("owner", "reserved-name", "publish")
        with pytest.raises(SystemExit, match="owner changed"):
            bind(second, "unbound")
        with pytest.raises(SystemExit, match="requires a reason"):
            bind(second, first, reason=" ")
        with pytest.raises(SystemExit, match="immutable Dinkster"):
            bind("someone@example.test", first)
        principals.freeze_publisher("reserved-name", "operator", now.isoformat(), "Dispute")
        bind(second, first)
        with pytest.raises(RegistryError):
            principals.authorize("owner", "reserved-name", "publish")
        with pytest.raises(RegistryError, match="revoked"):
            principals.verify_token(secret, now.isoformat())
        with database.session() as session:
            binding = session.get(PublisherBindingRecord, "reserved-name")
            assert binding is not None and binding.identity_subject == second
            owners = list(session.scalars(select(PublisherMembershipRecord)))
            assert [(owner.user_id, owner.role) for owner in owners] == [(second, "owner")]
            events = list(session.scalars(select(AuditEventRecord).order_by(AuditEventRecord.id)))
            assert len(events) == 2
            assert events[0].data["previousOwner"] is None
            assert events[0].data["owner"] == first
            assert events[1].data["previousOwner"] == first
            assert events[1].data["owner"] == second
            assert events[1].data["actor"] == "operator"
            event_id = events[1].id
        for statement in (
            update(AuditEventRecord).where(AuditEventRecord.id == event_id).values(data={}),
            delete(AuditEventRecord).where(AuditEventRecord.id == event_id),
        ):
            with pytest.raises(DatabaseError), database.session() as session, session.begin():
                session.execute(statement)
    finally:
        database.dispose()


def test_admin_yank_updates_indexes_and_preserves_downloads(
    monkeypatch: pytest.MonkeyPatch,
    database_url: str,
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
    client: TestClient,
) -> None:
    database, store = seeded_catalog
    StaticIndexes(database, store, "http://testserver").rebuild()
    endpoint = "/v1/packs/example-pack/versions/1.2.3"
    before = client.get(endpoint).json()
    artifact_url = "/v1/artifacts/" + before["artifact"]["digest"]
    original_bytes = client.get(artifact_url).content
    original_items = client.get("/static/packs/index.json").json()["items"]
    removed = next(
        i for i in original_items if i["name"] == "example-pack" and i["latestVersion"] == "1.2.3"
    )
    release = client.get("/static/" + removed["url"]).json()["items"][0]
    filename = release["wheels"][0]["filename"]
    assert filename in client.get("/static/cpu/simple/example-pack/").text

    _run(
        monkeypatch,
        "admin",
        "--database-url",
        database_url,
        "--object-store-root",
        str(store.root),
        "yank",
        "example-pack",
        "1.2.3",
        "--reason",
        "Replaced by separate packs.",
    )

    detail = client.get(endpoint)
    assert detail.status_code == 200
    assert detail.json()["state"] == "yanked"
    assert detail.json()["stateReason"] == "Replaced by separate packs."
    assert detail.json()["stateChangedAt"] != before["stateChangedAt"]
    assert client.get("/static/packs/index.json").json()["items"] == [
        item for item in original_items if item != removed
    ]
    assert filename not in client.get("/static/cpu/simple/example-pack/").text
    artifact = client.get(artifact_url)
    assert artifact.status_code == 200 and artifact.content == original_bytes
    ticket = client.post(endpoint + "/download-tickets").json()
    assert ticket["state"] == "yanked" and ticket["warning"] == "Replaced by separate packs."


@pytest.mark.parametrize(
    "state",
    [
        "yanked",
        "quarantined",
        "blocked",
        "pending_scan",
        "pending_review",
        "rejected",
        "unknown",
        "blank-reason",
    ],
)
def test_admin_yank_refuses_invalid_requests(
    monkeypatch: pytest.MonkeyPatch,
    database_url: str,
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
    state: str,
) -> None:
    database, store = seeded_catalog
    with database.session() as session, session.begin():
        release = session.scalar(select(ReleaseRecord).where(ReleaseRecord.version == "1.2.3"))
        assert release is not None
        release.state = "active" if state in {"unknown", "blank-reason"} else state
        release.state_reason = "Existing reason"
    indexes = StaticIndexes(database, store, "http://testserver")
    indexes.rebuild()
    original_index = store.read("static/packs/index.json")
    message = "unknown release" if state == "unknown" else "only active can be yanked"
    if state == "blank-reason":
        message = "reason must not be blank"
    with pytest.raises(SystemExit, match=message):
        _run(
            monkeypatch,
            "admin",
            "--database-url",
            database_url,
            "--object-store-root",
            str(store.root),
            "yank",
            "example-pack",
            "9.9.9" if state == "unknown" else "1.2.3",
            "--reason",
            "   " if state == "blank-reason" else "New reason",
        )
    with database.session() as session:
        release = session.scalar(select(ReleaseRecord).where(ReleaseRecord.version == "1.2.3"))
        assert release is not None and release.state_reason == "Existing reason"
        assert release.state == ("active" if state in {"unknown", "blank-reason"} else state)
    assert store.read("static/packs/index.json") == original_index


def test_admin_yank_storage_failure_is_reported_and_recoverable(
    monkeypatch: pytest.MonkeyPatch,
    database_url: str,
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore],
    client: TestClient,
) -> None:
    database, store = seeded_catalog
    indexes = StaticIndexes(database, store, "http://testserver")
    indexes.rebuild()

    def unavailable(self: LocalFilesystemObjectStore, key: str, data: bytes) -> None:
        raise ObjectStoreError("storage unavailable")

    with monkeypatch.context() as outage:
        outage.setattr(LocalFilesystemObjectStore, "replace_index", unavailable)
        with pytest.raises(SystemExit, match="release yanked, but index rebuild failed"):
            _run(
                outage,
                "admin",
                "--database-url",
                database_url,
                "--object-store-root",
                str(store.root),
                "yank",
                "example-pack",
                "1.2.3",
                "--reason",
                "Withdrawn",
            )
    detail = client.get("/v1/packs/example-pack/versions/1.2.3").json()
    assert detail["state"] == "yanked" and detail["stateReason"] == "Withdrawn"
    assert indexes.deliver_one()
    assert all(
        item["name"] != "example-pack"
        for item in client.get("/static/packs/index.json").json()["items"]
    )
    assert "example_pack-1.2.3" not in client.get("/static/cpu/simple/example-pack/").text
