from __future__ import annotations

import base64
import functools
import shutil
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Barrier, Thread
from urllib.request import urlopen

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from fastapi.testclient import TestClient
from sqlalchemy import select

from dinkster_registry_service.admission import AdmissionService
from dinkster_registry_service.app import create_app
from dinkster_registry_service.database import Database, OutboxRecord, PackRecord, ReleaseRecord
from dinkster_registry_service.indexes import StaticIndexes
from dinkster_registry_service.object_store import LocalFilesystemObjectStore, ObjectStoreError
from dinkster_registry_service.ownership import transfer_ownership
from dinkster_registry_service.principals import PrincipalRepository
from dinkster_registry_service.security import (
    SecurityDocument,
    SecurityError,
    SecurityKey,
    SecurityRelease,
    SecurityTrust,
    security_key_id,
    sign_security_document,
    verify_security_document,
    verify_security_trust,
)
from dinkster_registry_service.security_publication import SECURITY_OBJECT_KEY, SecurityPublication
from dinkster_registry_service.security_repository import (
    NoticeChange,
    SecurityRepository,
    UploadChange,
)
from dinkster_registry_service.settings import ServerSettings


def _authority(database: Database) -> tuple[SecurityRepository, SecurityRelease]:
    principals = PrincipalRepository(database)
    now = datetime.now(UTC).isoformat()
    principals.register_user("responder")
    principals.add_operator("responder", "responder", now)
    repository = SecurityRepository(database, "http://testserver")
    repository.set_role(actor="responder", user="responder", enabled=True, reason="response")
    with database.session() as session:
        pack = session.scalar(select(PackRecord).where(PackRecord.name == "example-pack"))
        assert pack is not None
        release = session.scalar(select(ReleaseRecord).where(ReleaseRecord.pack_id == pack.id))
        assert release is not None
        identity = SecurityRelease(
            pack=pack.name, version=release.version, artifact_digest=release.artifact_digest
        )
    return repository, identity


def _key(tmp_path: Path) -> tuple[Path, Ed25519PrivateKey, SecurityTrust]:
    key = Ed25519PrivateKey.generate()
    path = tmp_path / "signer.pem"
    path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    path.chmod(0o600)
    public = key.public_key().public_bytes_raw()
    now = datetime.now(UTC)
    trust = SecurityTrust(
        registry="http://testserver",
        revision=1,
        issued_at=now,
        expires_at=now + timedelta(days=30),
        keys=(
            SecurityKey(
                key_id=security_key_id(public), public_key=base64.b64encode(public).decode()
            ),
        ),
    )
    return path, key, trust


@pytest.mark.parametrize("failure", ["before", "after", "crash"])
def test_publication_recovers_exact_signed_bytes_without_losing_later_changes(
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore], tmp_path: Path, failure: str
) -> None:
    database, store = seeded_catalog
    repository, identity = _authority(database)
    path, _, trust = _key(tmp_path)
    change = NoticeChange(
        operation="issue",
        release=identity,
        expected_revision=0,
        state="malicious",
        reason="compromised",
        message="Do not execute",
        incident="case1",
    )
    notice = repository.change(actor="responder", change=change)
    assert not SecurityPublication(database, store, "http://testserver", None).deliver_one()

    class InterruptedStore(LocalFilesystemObjectStore):
        def replace_index(self, key: str, data: bytes) -> None:
            if failure == "before":
                raise ObjectStoreError("write refused")
            super().replace_index(key, data)
            if failure == "crash":
                raise RuntimeError("crash before database acknowledgement")
            raise ObjectStoreError("object write response lost")

    settings = ServerSettings(security_signing_key_path=path, public_base_url="http://testserver")
    scanner = AdmissionService(database, InterruptedStore(store.root), settings=settings)
    if failure == "crash":
        with pytest.raises(RuntimeError, match="crash"):
            scanner.run_once()
    else:
        assert scanner.run_once()
    with database.session() as session, session.begin():
        event = session.scalar(select(OutboxRecord).where(OutboxRecord.topic == "security.publish"))
        assert event is not None and event.state == "pending"
        saved = event.payload["envelope"].encode("ascii")
        event.available_at = event.created_at
    original = verify_security_document(saved, trust)
    assert original.notices == (notice,)
    if failure != "before":
        assert store.read(SECURITY_OBJECT_KEY) == saved
    corrected = repository.change(
        actor="responder",
        change=change.model_copy(
            update={
                "operation": "correct",
                "expected_revision": notice.revision,
                "state": "vulnerable",
                "message": "Corrected assessment",
            }
        ),
    )
    # A clock adjustment cannot move a newer revision ahead of a prepared retry.
    with database.session() as session, session.begin():
        events = list(
            session.scalars(select(OutboxRecord).where(OutboxRecord.topic == "security.publish"))
        )
        oldest_time = min(event.created_at for event in events)
        newer = next(event for event in events if event.payload["revision"] == corrected.revision)
        newer.created_at = oldest_time - timedelta(seconds=1)
        newer.available_at = newer.created_at
    # A new process retries the prepared envelope, then publishes the later correction.
    recovered = SecurityPublication(database, store, "http://testserver", path)
    assert recovered.deliver_one()
    assert store.read(SECURITY_OBJECT_KEY) == saved
    assert recovered.deliver_one()
    latest = verify_security_document(store.read(SECURITY_OBJECT_KEY), trust, previous=original)
    assert latest.notices == (corrected,)
    assert latest.revision > original.revision
    assert latest.issued_at < latest.expires_at
    assert not recovered.deliver_one()
    with database.session() as session:
        assert {
            event.state
            for event in session.scalars(
                select(OutboxRecord).where(OutboxRecord.topic == "security.publish")
            )
        } == {"delivered"}


def test_http_static_copy_and_offline_verification_preserve_corrections_and_catalog(
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore], database_url: str, tmp_path: Path
) -> None:
    database, store = seeded_catalog
    repository, identity = _authority(database)
    path, key, trust = _key(tmp_path)
    indexes = StaticIndexes(database, store, "http://testserver")
    indexes.rebuild()
    before = {
        p.relative_to(store.root): p.read_bytes()
        for p in (store.root / "static").rglob("*")
        if p.is_file()
    }
    publication = SecurityPublication(database, store, "http://testserver", path)
    app = create_app(
        ServerSettings(
            database_url=database_url,
            object_store_root=store.root,
            public_base_url="http://testserver",
        )
    )
    previous: SecurityDocument | None = None
    first_bytes = b""
    revision = 0
    with TestClient(app) as client:
        for operation, state in (
            ("issue", "vulnerable"),
            ("withdraw", "vulnerable"),
            ("issue", "vulnerable"),
            ("confirm", "vulnerable"),
            ("correct", "affected"),
            ("lift", "affected"),
        ):
            # Publisher withdrawal uses publisher authority, not the security role.
            actor = "responder"
            if operation in {"issue", "withdraw"}:
                principals = PrincipalRepository(database)
                if revision == 0:
                    principals.register_user("publisher-user")
                    principals.register_publisher(
                        "publisher", "publisher-user", datetime.now(UTC).isoformat()
                    )
                    with database.session() as session, session.begin():
                        pack = session.scalar(
                            select(PackRecord).where(PackRecord.name == identity.pack)
                        )
                        assert pack is not None
                        pack.publisher_id = "publisher"
                actor = "publisher-user"
            notice = repository.change(
                actor=actor,
                change=NoticeChange.model_validate(
                    {
                        "operation": operation,
                        "release": identity,
                        "expected_revision": revision,
                        "state": state,
                        "reason": "assessment",
                        "message": "Details",
                        "incident": "case1",
                        "causes": ("sha256:" + "b" * 64,) if state == "affected" else (),
                    }
                ),
            )
            revision = notice.revision
            assert publication.deliver_one()
            static = client.get("/static/security/index.json")
            http = client.get("/v1/security/blocks")
            assert static.status_code == http.status_code == 200
            assert static.content == http.content == store.read(SECURITY_OBJECT_KEY)
            assert static.headers["etag"] == http.headers["etag"]
            assert (
                client.get(
                    "/v1/security/blocks", headers={"If-None-Match": http.headers["etag"]}
                ).status_code
                == 304
            )
            assert client.head("/static/security/index.json").content == b""
            current = verify_security_document(http.content, trust, previous=previous)
            assert current.notices == (notice,)
            previous = current
            if not first_bytes:
                first_bytes = http.content
        assert previous is not None
        with pytest.raises(SecurityError, match="rolled back"):
            verify_security_document(first_bytes, trust, previous=previous)
        assert all((store.root / name).read_bytes() == data for name, data in before.items())

        mirror = tmp_path / "mirror"
        (mirror / "security").mkdir(parents=True)
        shutil.copyfile(store.root / SECURITY_OBJECT_KEY, mirror / "security/index.json")
        handler = functools.partial(SimpleHTTPRequestHandler, directory=str(mirror))
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = Thread(target=server.serve_forever)
        thread.start()
        try:
            with urlopen(
                f"http://127.0.0.1:{server.server_port}/security/index.json", timeout=5
            ) as response:
                copied = response.read()
            assert copied == http.content
            assert verify_security_document(copied, trust, previous=previous) == previous
            assert (
                verify_security_document((mirror / "security/index.json").read_bytes(), trust)
                == previous
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    # Authenticated key rotation preserves the known cleared notice checkpoint.
    next_key = Ed25519PrivateKey.generate()
    public = next_key.public_key().public_bytes_raw()
    replacement = trust.model_copy(
        update={
            "revision": 2,
            "keys": (
                SecurityKey(
                    key_id=security_key_id(public), public_key=base64.b64encode(public).decode()
                ),
            ),
        }
    )
    rotated = verify_security_trust(sign_security_document(replacement, key), trust)
    path.write_bytes(next_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
    repository.change(
        actor="responder",
        change=NoticeChange(
            operation="issue",
            release=identity,
            expected_revision=revision,
            state="malicious",
            reason="new evidence",
            message="Do not execute",
            incident="case2",
        ),
    )
    assert publication.deliver_one()
    updated = store.read(SECURITY_OBJECT_KEY)
    assert (
        verify_security_document(updated, rotated, previous=previous).notices[0].state
        == "malicious"
    )
    with pytest.raises(SecurityError):
        verify_security_document(updated, trust, previous=previous)

    malicious = verify_security_document(updated, rotated, previous=previous)
    with pytest.raises(SecurityError):
        verify_security_document(updated.replace(b"Do not execute", b"Execute freely"), rotated)
    with pytest.raises(SecurityError):
        verify_security_document(updated[:-1], rotated, previous=malicious)
    with pytest.raises(SecurityError):
        verify_security_document(
            updated, rotated.model_copy(update={"registry": "https://unrelated.example"})
        )
    # Ordinary yank changes selection, never the signed security verdict or bytes.
    AdmissionService(database, store).yank(identity.pack, identity.version, reason="withdraw")
    assert store.read(SECURITY_OBJECT_KEY) == updated
    assert verify_security_document(updated, rotated, previous=malicious) == malicious
    assert (
        store.read("static/packs/color-tools/index.json")
        == before[Path("static/packs/color-tools/index.json")]
    )


def test_replicas_coalesce_pending_notices_without_equivocation_or_upload_control_effects(
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore], tmp_path: Path
) -> None:
    database, store = seeded_catalog
    repository, identity = _authority(database)
    path, _, trust = _key(tmp_path)
    notice = repository.change(
        actor="responder",
        change=NoticeChange(
            operation="issue",
            release=identity,
            expected_revision=0,
            state="malicious",
            reason="review",
            message="Do not execute",
            incident="case1",
        ),
    )
    corrected = repository.change(
        actor="responder",
        change=NoticeChange(
            operation="correct",
            release=identity,
            expected_revision=notice.revision,
            state="vulnerable",
            reason="correct",
            message="Corrected",
            incident="case1",
        ),
    )
    repository.set_uploads(
        actor="responder",
        change=UploadChange(
            subject_type="pack",
            subject=identity.pack,
            stopped=True,
            reason="pause uploads",
        ),
    )
    barrier = Barrier(2)

    def deliver(_: int) -> bool:
        barrier.wait(timeout=10)
        return SecurityPublication(database, store, "http://testserver", path).deliver_one()

    with ThreadPoolExecutor(max_workers=2) as executor:
        assert any(executor.map(deliver, range(2)))
    data = store.read(SECURITY_OBJECT_KEY)
    assert verify_security_document(data, trust).notices == (corrected,)
    assert not SecurityPublication(database, store, "http://testserver", path).deliver_one()
    assert store.read(SECURITY_OBJECT_KEY) == data
    repository.set_uploads(
        actor="responder",
        change=UploadChange(
            subject_type="pack",
            subject=identity.pack,
            stopped=False,
            reason="resume uploads",
        ),
    )
    assert not SecurityPublication(database, store, "http://testserver", path).deliver_one()
    assert store.read(SECURITY_OBJECT_KEY) == data


def test_ownership_outbox_publishes_signed_identity_without_changing_audit_id(
    seeded_catalog: tuple[Database, LocalFilesystemObjectStore], tmp_path: Path
) -> None:
    database, store = seeded_catalog
    repository, identity = _authority(database)
    path, _, trust = _key(tmp_path)
    principals = PrincipalRepository(database)
    principals.register_publisher("replacement", "responder", datetime.now(UTC).isoformat())
    with repository.transaction() as session:
        pack = session.scalar(select(PackRecord).where(PackRecord.name == identity.pack))
        assert pack is not None
        audit_id = transfer_ownership(
            session,
            actor="responder",
            subject_kind="pack",
            subject_id=str(pack.id),
            expected_owner=None,
            target_owner="replacement",
            reason="security maintenance",
            at=datetime.now(UTC),
        )
    publication = SecurityPublication(database, store, "http://testserver", path)
    assert publication.deliver_one()
    document = verify_security_document(store.read(SECURITY_OBJECT_KEY), trust)
    (notice,) = document.ownership_changes
    assert notice.id == audit_id
    assert notice.previous_publisher is None
    assert notice.publisher == "replacement"
    assert notice.pack == identity.pack
    with database.session() as session:
        event = session.scalar(select(OutboxRecord).where(OutboxRecord.topic == "security.publish"))
        assert event is not None and event.state == "delivered"
        assert event.payload["auditId"] == str(audit_id)
