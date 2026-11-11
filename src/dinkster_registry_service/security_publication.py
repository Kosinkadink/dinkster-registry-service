"""Durable, byte-stable publication of complete signed security snapshots."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from sqlalchemy import select

from .database import Database, OutboxRecord
from .object_store import ObjectStore, ObjectStoreError
from .security import sign_security_document
from .security_repository import SecurityRepository

SECURITY_OBJECT_KEY = "static/security/index.json"


class SecurityPublication:
    def __init__(
        self, database: Database, object_store: ObjectStore, registry: str, key_path: Path | None
    ) -> None:
        self.repository = SecurityRepository(database, registry)
        self.object_store = object_store
        self.key_path = key_path

    def deliver_one(self) -> bool:
        if self.key_path is None:
            return False
        # Commit the envelope before the external write. An ambiguous write or
        # a crash after replacement must retry identical bytes, never re-sign.
        with self.repository.transaction() as session:
            pending = list(
                session.scalars(
                    select(OutboxRecord)
                    .where(
                        OutboxRecord.topic == "security.publish", OutboxRecord.state == "pending"
                    )
                    .order_by(OutboxRecord.created_at, OutboxRecord.id)
                )
            )
            if not pending:
                return False
            now = datetime.now(UTC)
            first = pending[0]
            available = first.available_at.replace(tzinfo=UTC)
            if available > now:
                return False
            if "envelope" not in first.payload:
                key = load_pem_private_key(self.key_path.read_bytes(), password=None)
                if not isinstance(key, Ed25519PrivateKey):
                    raise ValueError("security publication requires an Ed25519 private key")
                document = self.repository.document_in_transaction(
                    session, issued_at=now, expires_at=now + timedelta(days=1)
                )
                envelope = sign_security_document(document, key).decode("ascii")
                for event in pending:
                    event.payload = {
                        **event.payload,
                        "envelope": envelope,
                        "snapshotRevision": document.revision,
                    }

        # Hold the same cross-process lock through replacement and ack so a
        # delayed replica cannot publish an older snapshot over a newer one.
        with self.repository.transaction() as session:
            events = list(
                session.scalars(
                    select(OutboxRecord)
                    .where(
                        OutboxRecord.topic == "security.publish", OutboxRecord.state == "pending"
                    )
                    .order_by(OutboxRecord.created_at, OutboxRecord.id)
                )
            )
            if not events or "envelope" not in events[0].payload:
                return False
            first = events[0]
            if first.available_at.replace(tzinfo=UTC) > datetime.now(UTC):
                return False
            included = [
                event
                for event in events
                if event.payload.get("snapshotRevision") == first.payload["snapshotRevision"]
            ]
            for event in included:
                event.attempts += 1
            try:
                self.object_store.replace_index(
                    SECURITY_OBJECT_KEY, first.payload["envelope"].encode("ascii")
                )
            except ObjectStoreError:
                for event in included:
                    event.available_at = datetime.now(UTC) + timedelta(seconds=5)
            else:
                for event in included:
                    event.state = "delivered"
                    event.delivered_at = datetime.now(UTC)
            return True
