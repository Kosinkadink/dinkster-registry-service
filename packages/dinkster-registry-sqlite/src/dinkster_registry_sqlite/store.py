"""RegistryStore: the registry's durable state over the pure model.

The service half the pure ``dinkster_registry`` package was built for. The
division of labor is strict:

- The PURE MODELS are the only invariant enforcement. Every mutation
  runs through ``PrincipalDirectory`` / ``GrantTable`` / ``ReleaseIndex``
  / ``ReviewLog`` / ``admit`` FIRST; SQLite persists what the model
  already accepted and never encodes a rule of its own. A publisher or
  CI running the same pure predicates locally computes exactly what this
  store will answer.
- REHYDRATION RE-VALIDATES. Opening a store replays every row back
  through the models' own validation paths (``PrincipalDirectory.restore``,
  the ``GrantTable``/``ReleaseIndex`` constructors, ``ReviewLog`` replay),
  so a hand-edited or corrupt database refuses at open, never at
  authorization or admission time - the ``Lockfile.from_record_json``
  stance applied to the whole registry.
- MUTATIONS ARE TRANSACTIONS. Each operation is one SQLite transaction;
  the publish/review paths persist grants + release + review + audit
  together, so no crash can index a release whose claims were never
  granted (the same atomicity ``record_acceptance`` guarantees in
  memory).

Storage follows the house pattern (LibraryStore/HistoryStore): one
SQLite file, WAL, one connection behind a process-wide lock, sync
methods an HTTP layer crosses via ``asyncio.to_thread``. The schema is
versioned via ``PRAGMA user_version`` from day one: an unknown version
refuses to open rather than guessing at migration.

Review lifecycle here: every publish attempt gets its own numbered
attempt with its submission and verdict persisted as evidence (states
persist atomically with their evidence - a rejection is a visible,
reasoned record, never a silent refusal). ``needs_review`` attempts land
in a pending queue that ``resolve_review`` settles; acceptance re-runs
``admit`` against CURRENT grants/releases, so a decision made after the
world changed cannot land a conflict. Reviewer authority is the
OPERATORS table (registry staff), deliberately separate from publisher
membership - publishers never review themselves. Deadlines/escalation
are a later policy layer over these same rows.

Deliberately NOT here: the HTTP surface (Authorization-header token
transport), the auth layer producing user ids, artifact byte storage
(content-addressed files, not database rows), and search/index queries.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal, cast

from dinkster_registry import (
    Action,
    AdmissionFinding,
    AuditRecord,
    DoctorEvidence,
    Grant,
    GrantTable,
    Membership,
    PrincipalDirectory,
    RegistryError,
    Release,
    ReleaseIndex,
    ReleaseTemplate,
    ReviewLog,
    Role,
    Submission,
    TokenRecord,
    Verdict,
    VersionState,
    admit,
    canonical_json,
    record_acceptance,
    validate_artifact_digest,
    validate_version,
)
from dinkster_schema import canonical_name, validate_name

SCHEMA_VERSION = 1
MAX_YANK_REASON_CHARS = 1024


class StoreError(Exception):
    """The database itself is unusable: wrong schema version, corrupt
    rows, failed writes. Domain refusals stay ``RegistryError``."""


_TABLES = """
CREATE TABLE users (
    id TEXT PRIMARY KEY
);
CREATE TABLE operators (
    user TEXT PRIMARY KEY REFERENCES users(id)
);
CREATE TABLE publishers (
    id TEXT PRIMARY KEY,
    display TEXT NOT NULL
);
CREATE TABLE memberships (
    publisher TEXT NOT NULL,
    user TEXT NOT NULL,
    role TEXT NOT NULL,
    PRIMARY KEY (publisher, user)
);
CREATE TABLE tokens (
    token_id TEXT PRIMARY KEY,
    publisher TEXT NOT NULL,
    minted_by TEXT NOT NULL,
    pack TEXT,
    secret_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked INTEGER NOT NULL,
    revoked_reason TEXT NOT NULL
);
CREATE TABLE audit (
    seq INTEGER PRIMARY KEY,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    subject TEXT NOT NULL,
    at TEXT NOT NULL,
    details TEXT NOT NULL
);
CREATE TABLE grants (
    claim TEXT PRIMARY KEY,
    publisher TEXT NOT NULL
);
CREATE TABLE releases (
    pack TEXT NOT NULL,
    version TEXT NOT NULL,
    record TEXT NOT NULL,
    PRIMARY KEY (pack, version)
);
CREATE TABLE attempts (
    pack TEXT NOT NULL,
    version TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    submission TEXT NOT NULL,
    verdict TEXT NOT NULL,
    PRIMARY KEY (pack, version, attempt)
);
CREATE TABLE reviews (
    pack TEXT NOT NULL,
    version TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    seq INTEGER NOT NULL,
    to_state TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    at TEXT NOT NULL,
    PRIMARY KEY (pack, version, attempt, seq)
);
CREATE TABLE pending (
    pack TEXT NOT NULL,
    version TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    PRIMARY KEY (pack, version)
);
"""


# ---------------------------------------------------------------------------
# Record (de)serialization - canonical JSON both ways, re-validated on read
# ---------------------------------------------------------------------------


def _submission_json(submission: Submission) -> str:
    return canonical_json(
        {
            "publisher": submission.publisher,
            "packName": submission.pack_name,
            "namespaces": list(submission.namespaces),
            "version": submission.version,
            "artifactDigest": submission.artifact_digest,
            "evidence": {
                "packName": submission.evidence.pack_name,
                "ok": submission.evidence.ok,
                "nodeTypes": list(submission.evidence.node_types),
                "errorCodes": list(submission.evidence.error_codes),
            },
            "templates": [template.record() for template in submission.templates],
        }
    )


def _str_list(payload: dict[str, object], key: str, what: str) -> tuple[str, ...]:
    value = payload.get(key)
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in cast("list[object]", value)
    ):
        raise StoreError(f"{what} field {key!r} must be a list of strings")
    return tuple(cast("list[str]", value))


def _str_field(payload: dict[str, object], key: str, what: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str):
        raise StoreError(f"{what} field {key!r} must be a string")
    return value


def _decode_json(text: str, what: str) -> dict[str, object]:
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise StoreError(f"{what} record is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise StoreError(f"{what} record must be a JSON object")
    return cast("dict[str, object]", document)


def _templates_from_payload(payload: dict[str, object], what: str) -> tuple[ReleaseTemplate, ...]:
    """Decode the optional 'templates' list of a persisted record.
    Records written before templates existed simply lack the key -
    absence means "no templates", never corruption."""
    raw = payload.get("templates", [])
    if not isinstance(raw, list):
        raise StoreError(f"{what} field 'templates' must be a list")
    templates: list[ReleaseTemplate] = []
    for item in cast("list[object]", raw):
        if not isinstance(item, dict):
            raise StoreError(f"{what} templates entries must be objects")
        entry = cast("dict[str, object]", item)
        label = f"{what} template"
        template = ReleaseTemplate(
            id=_str_field(entry, "id", label),
            name=_str_field(entry, "name", label),
            digest=_str_field(entry, "digest", label),
            path=_str_field(entry, "path", label),
            description=_str_field(entry, "description", label),
            tags=_str_list(entry, "tags", label),
            assets=_str_list(entry, "assets", label),
        )
        if not template.id or not template.name or not template.path:
            raise StoreError(f"{what} template id/name/path must be non-empty")
        problem = validate_artifact_digest(template.digest)
        if problem is not None:
            raise StoreError(f"{what} template digest {problem}")
        templates.append(template)
    return tuple(templates)


def _submission_from_json(text: str) -> Submission:
    payload = _decode_json(text, "submission")
    evidence_raw = payload.get("evidence")
    if not isinstance(evidence_raw, dict):
        raise StoreError("submission record field 'evidence' must be an object")
    evidence_payload = cast("dict[str, object]", evidence_raw)
    ok = evidence_payload.get("ok")
    if not isinstance(ok, bool):
        raise StoreError("submission record field 'evidence.ok' must be a boolean")
    evidence = DoctorEvidence(
        pack_name=_str_field(evidence_payload, "packName", "evidence"),
        ok=ok,
        node_types=_str_list(evidence_payload, "nodeTypes", "evidence"),
        error_codes=_str_list(evidence_payload, "errorCodes", "evidence"),
    )
    return Submission(
        publisher=_str_field(payload, "publisher", "submission"),
        pack_name=_str_field(payload, "packName", "submission"),
        namespaces=_str_list(payload, "namespaces", "submission"),
        version=_str_field(payload, "version", "submission"),
        artifact_digest=_str_field(payload, "artifactDigest", "submission"),
        evidence=evidence,
        templates=_templates_from_payload(payload, "submission"),
    )


def _release_from_record(text: str) -> Release:
    """Decode a persisted release by re-running the grammar validations
    the admission path ran when it was written."""
    payload = _decode_json(text, "release")
    release = Release(
        pack=_str_field(payload, "pack", "release"),
        version=_str_field(payload, "version", "release"),
        artifact_digest=_str_field(payload, "artifactDigest", "release"),
        publisher=_str_field(payload, "publisher", "release"),
        claims=_str_list(payload, "claims", "release"),
        node_types=_str_list(payload, "nodeTypes", "release"),
        templates=_templates_from_payload(payload, "release"),
    )
    for label, name in (("pack", release.pack), ("publisher", release.publisher)):
        problem = validate_name(name)
        if problem is not None:
            raise StoreError(f"release {label} {name!r} {problem}")
        if canonical_name(name) != name:
            raise StoreError(f"release {label} {name!r} is not canonical")
    problem = validate_version(release.version)
    if problem is not None:
        raise StoreError(f"release version {release.version!r} {problem}")
    problem = validate_artifact_digest(release.artifact_digest)
    if problem is not None:
        raise StoreError(f"release digest {problem}")
    if not release.claims or release.pack not in release.claims:
        raise StoreError(f"release {release.pack!r} claims do not cover its pack identity")
    for claim in release.claims:
        problem = validate_name(claim)
        if problem is not None:
            raise StoreError(f"release claim {claim!r} {problem}")
        if canonical_name(claim) != claim:
            raise StoreError(f"release claim {claim!r} is not canonical")
    return release


ReviewDecision = Literal["accepted", "rejected"]


class RegistryStore:
    """The registry's durable state: principals, grants, releases,
    reviews - SQLite-backed, pure-model-validated. Thread contract as
    LibraryStore: one connection behind a lock, callers cross via
    ``asyncio.to_thread``."""

    def __init__(self, path: Path | str) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock, self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL")
            version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if version == 0:
                self._conn.executescript(_TABLES)
                self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            elif version != SCHEMA_VERSION:
                raise StoreError(
                    f"registry database has schema version {version}, this build "
                    f"speaks {SCHEMA_VERSION}; refusing to guess at migration"
                )
            self._rehydrate()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- rehydration (everything re-validates) -----------------------------

    def _rehydrate(self) -> None:
        conn = self._conn
        try:
            self._directory = PrincipalDirectory.restore(
                users=[r["id"] for r in conn.execute("SELECT id FROM users")],
                publishers={
                    r["id"]: r["display"] for r in conn.execute("SELECT * FROM publishers")
                },
                memberships=[
                    Membership(r["user"], r["publisher"], cast("Role", r["role"]))
                    for r in conn.execute("SELECT * FROM memberships")
                ],
                tokens=[
                    TokenRecord(
                        token_id=r["token_id"],
                        publisher=r["publisher"],
                        minted_by=r["minted_by"],
                        pack=r["pack"],
                        secret_hash=r["secret_hash"],
                        created_at=r["created_at"],
                        expires_at=r["expires_at"],
                        revoked=bool(r["revoked"]),
                        revoked_reason=r["revoked_reason"],
                    )
                    for r in conn.execute("SELECT * FROM tokens")
                ],
                audit=[
                    AuditRecord(r["actor"], r["action"], r["subject"], r["at"], r["details"])
                    for r in conn.execute("SELECT * FROM audit ORDER BY seq")
                ],
            )
            self._operators = {r["user"] for r in conn.execute("SELECT user FROM operators")}
            unknown = self._operators - {r["id"] for r in conn.execute("SELECT id FROM users")}
            if unknown:
                raise RegistryError(f"operators reference unknown users: {sorted(unknown)}")
            self._grants = GrantTable(
                Grant(r["claim"], r["publisher"]) for r in conn.execute("SELECT * FROM grants")
            )
            self._releases = ReleaseIndex(
                tuple(
                    _release_from_record(r["record"])
                    for r in conn.execute("SELECT record FROM releases")
                )
            )
            for release in self._releases.releases():
                for claim in release.claims:
                    if self._grants.owner_of(claim) != release.publisher:
                        raise RegistryError(
                            f"release {release.pack} {release.version} claim {claim!r} "
                            f"is not granted to {release.publisher!r}"
                        )
            self._reviews: dict[tuple[str, str, int], ReviewLog] = {}
            for r in conn.execute("SELECT * FROM reviews ORDER BY pack, version, attempt, seq"):
                key = (r["pack"], r["version"], r["attempt"])
                log = self._reviews.get(key)
                if log is None:
                    if r["to_state"] != "submitted":
                        raise RegistryError(f"review log for {key} does not begin at 'submitted'")
                    self._reviews[key] = ReviewLog.start(r["actor"], r["at"])
                else:
                    self._reviews[key] = log.advance(
                        cast("VersionState", r["to_state"]), r["actor"], r["at"], r["reason"]
                    )
            self._pending: dict[tuple[str, str], int] = {
                (r["pack"], r["version"]): r["attempt"]
                for r in conn.execute("SELECT * FROM pending")
            }
            for key in self._pending:
                attempt = self._pending[key]
                log = self._reviews.get((key[0], key[1], attempt))
                if log is None or log.state != "needs_review":
                    raise RegistryError(
                        f"pending review for {key[0]} {key[1]} attempt {attempt} "
                        f"has no needs_review log"
                    )
        except RegistryError as exc:
            raise StoreError(f"registry database failed validation at load: {exc}") from exc

    @contextmanager
    def _mutation(self) -> Generator[None]:
        """Rollback SQLite and restore all model state after write failures."""
        with self._lock:
            try:
                with self._conn:
                    yield
            except sqlite3.Error:
                self._rehydrate()
                raise

    # -- audit persistence helper ------------------------------------------

    def _flush_audit(self, since: int) -> None:
        """Persist audit records appended by the pure model since ``since``."""
        records = self._directory.audit()
        for index in range(since, len(records)):
            record = records[index]
            self._conn.execute(
                "INSERT INTO audit VALUES (?, ?, ?, ?, ?, ?)",
                (index, record.actor, record.action, record.subject, record.at, record.details),
            )

    # -- principals ---------------------------------------------------------

    def register_user(self, user: str) -> None:
        with self._mutation():
            self._directory.register_user(user)
            self._conn.execute("INSERT OR IGNORE INTO users VALUES (?)", (user,))

    def add_operator(self, user: str, actor: str, at: str) -> None:
        """Grant registry-operator (review) authority. Bootstrap: the
        first operator may be added by anyone (a fresh deployment has no
        one to authorize it); afterwards only operators add operators."""
        with self._lock, self._conn:
            n = len(self._directory.audit())
            if user not in {r["id"] for r in self._conn.execute("SELECT id FROM users")}:
                raise RegistryError(f"unknown user {user!r}; register the account first")
            if self._operators and actor not in self._operators:
                raise RegistryError(f"user {actor!r} is not a registry operator")
            self._operators.add(user)
            self._directory.record(actor, "add-operator", user, at)
            self._conn.execute("INSERT OR IGNORE INTO operators VALUES (?)", (user,))
            self._flush_audit(n)

    def register_publisher(self, publisher: str, owner: str, at: str) -> str:
        with self._lock, self._conn:
            n = len(self._directory.audit())
            canonical = self._directory.register_publisher(publisher, owner, at)
            self._conn.execute("INSERT INTO publishers VALUES (?, ?)", (canonical, canonical))
            self._conn.execute(
                "INSERT INTO memberships VALUES (?, ?, ?)", (canonical, owner, "owner")
            )
            self._flush_audit(n)
            return canonical

    def set_display_name(self, publisher: str, name: str, actor: str, at: str) -> None:
        with self._lock, self._conn:
            n = len(self._directory.audit())
            self._directory.set_display_name(publisher, name, actor, at)
            canonical = canonical_name(publisher)
            self._conn.execute("UPDATE publishers SET display = ? WHERE id = ?", (name, canonical))
            self._flush_audit(n)

    def add_member(self, publisher: str, user: str, role: Role, actor: str, at: str) -> None:
        with self._lock, self._conn:
            n = len(self._directory.audit())
            self._directory.add_member(publisher, user, role, actor, at)
            self._conn.execute(
                "INSERT INTO memberships VALUES (?, ?, ?)",
                (canonical_name(publisher), user, role),
            )
            self._flush_audit(n)

    def set_role(self, publisher: str, user: str, role: Role, actor: str, at: str) -> None:
        with self._lock, self._conn:
            n = len(self._directory.audit())
            self._directory.set_role(publisher, user, role, actor, at)
            self._conn.execute(
                "UPDATE memberships SET role = ? WHERE publisher = ? AND user = ?",
                (role, canonical_name(publisher), user),
            )
            self._flush_audit(n)

    def remove_member(self, publisher: str, user: str, actor: str, at: str) -> None:
        with self._lock, self._conn:
            n = len(self._directory.audit())
            self._directory.remove_member(publisher, user, actor, at)
            canonical = canonical_name(publisher)
            self._conn.execute(
                "DELETE FROM memberships WHERE publisher = ? AND user = ?", (canonical, user)
            )
            # Removal cascades token revocations in the model; resync them.
            for token in self._directory.tokens(canonical):
                if token.minted_by == user:
                    self._persist_token(token)
            self._flush_audit(n)

    def mint_token(
        self,
        publisher: str,
        minted_by: str,
        at: str,
        expires_at: str,
        pack: str | None = None,
        secret: str | None = None,
    ) -> tuple[str, TokenRecord]:
        with self._lock, self._conn:
            n = len(self._directory.audit())
            plaintext, record = self._directory.mint_token(
                publisher, minted_by, at, expires_at, pack=pack, secret=secret
            )
            self._persist_token(record)
            self._flush_audit(n)
            return plaintext, record

    def revoke_token(self, token_id: str, actor: str, at: str, reason: str) -> None:
        with self._lock, self._conn:
            n = len(self._directory.audit())
            self._directory.revoke_token(token_id, actor, at, reason)
            row = self._conn.execute(
                "SELECT publisher FROM tokens WHERE token_id = ?", (token_id,)
            ).fetchone()
            if row is not None:
                for token in self._directory.tokens(row["publisher"]):
                    if token.token_id == token_id:
                        self._persist_token(token)
            self._flush_audit(n)

    def _persist_token(self, token: TokenRecord) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO tokens VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                token.token_id,
                token.publisher,
                token.minted_by,
                token.pack,
                token.secret_hash,
                token.created_at,
                token.expires_at,
                int(token.revoked),
                token.revoked_reason,
            ),
        )

    # -- read delegation (the pure model answers) ---------------------------

    def authorize(self, user: str, publisher: str, action: Action) -> None:
        self._directory.authorize(user, publisher, action)

    def verify_token(self, presented: str, at: str) -> TokenRecord:
        return self._directory.verify_token(presented, at)

    def authorize_token(self, token: TokenRecord, publisher: str, pack: str) -> None:
        self._directory.authorize_token(token, publisher, pack)

    def role_of(self, user: str, publisher: str) -> Role | None:
        return self._directory.role_of(user, publisher)

    def memberships(self, publisher: str) -> tuple[Membership, ...]:
        return self._directory.memberships(publisher)

    def tokens(self, publisher: str) -> tuple[TokenRecord, ...]:
        return self._directory.tokens(publisher)

    def administered_tokens(self, publisher: str, actor: str) -> tuple[TokenRecord, ...]:
        """Token metadata visible to a publisher owner. Token secrets are
        never present in ``TokenRecord`` and therefore cannot leak through
        either the CLI or HTTP administration surfaces."""
        self._directory.authorize(actor, publisher, "manage-members")
        return self._directory.tokens(publisher)

    def audit(self) -> tuple[AuditRecord, ...]:
        return self._directory.audit()

    def display_name(self, publisher: str) -> str:
        return self._directory.display_name(publisher)

    def is_operator(self, user: str) -> bool:
        return user in self._operators

    def grants(self) -> tuple[Grant, ...]:
        return self._grants.grants()

    def release(self, pack: str, version: str) -> Release | None:
        return self._releases.get(canonical_name(pack), version)

    def releases(self) -> tuple[Release, ...]:
        return self._releases.releases()

    def yank_reason(self, pack: str, version: str) -> str | None:
        """The reason an accepted release was yanked, or None."""
        with self._lock:
            canonical = canonical_name(pack)
            release = self._releases.get(canonical, version)
            if release is None:
                return None
            _, log = self._release_review(release)
            if log.state != "yanked":
                return None
            return log.transitions[-1].reason

    def pending_reviews(self) -> tuple[tuple[str, str, int, Submission], ...]:
        """The review queue: (pack, version, attempt, submission)."""
        with self._lock:
            queue: list[tuple[str, str, int, Submission]] = []
            for (pack, version), attempt in sorted(self._pending.items()):
                row = self._conn.execute(
                    "SELECT submission FROM attempts"
                    " WHERE pack = ? AND version = ? AND attempt = ?",
                    (pack, version, attempt),
                ).fetchone()
                if row is None:
                    raise StoreError(f"pending review {pack} {version} has no attempt record")
                queue.append((pack, version, attempt, _submission_from_json(row["submission"])))
            return tuple(queue)

    def review_history(self, pack: str, version: str) -> tuple[tuple[int, ReviewLog], ...]:
        """Every attempt's lifecycle for one (pack, version), in order."""
        canonical = canonical_name(pack)
        return tuple(
            (attempt, log)
            for (p, v, attempt), log in sorted(self._reviews.items())
            if p == canonical and v == version
        )

    # -- publish / review -----------------------------------------------------

    def publish(self, submission: Submission, actor: str, at: str) -> Verdict:
        """One publish attempt: role-gated, admitted by the pure gate,
        persisted with its evidence whatever the outcome.

        - accepted: grants + release + review + audit land in ONE
          transaction (idempotent republication persists nothing new).
        - needs_review: the attempt joins the pending queue with the
          concrete claims named - visible, reasoned, resolvable.
        - rejected: the attempt and its findings persist as the visible
          record; nothing else changes.
        """
        with self._mutation():
            n = len(self._directory.audit())
            self._directory.authorize(actor, submission.publisher, "publish")
            pack = canonical_name(submission.pack_name)
            pending = self._pending.get((pack, submission.version))
            if pending is not None:
                previous = self._conn.execute(
                    "SELECT submission FROM attempts"
                    " WHERE pack = ? AND version = ? AND attempt = ?",
                    (pack, submission.version, pending),
                ).fetchone()
                if (
                    previous is not None
                    and _submission_from_json(previous["submission"]).artifact_digest
                    == submission.artifact_digest
                ):
                    return self._verdict_of(pack, submission.version, pending)
                raise RegistryError(
                    f"{pack} {submission.version} already has a submission pending "
                    f"review; resolve it before publishing different bytes"
                )
            verdict = admit(submission, self._grants, self._releases)
            if verdict.already_published:
                return verdict  # idempotent republication: nothing new to record
            attempt = self._next_attempt(pack, submission.version)
            log = ReviewLog.start(actor, at)
            if verdict.state == "accepted":
                log = log.advance("accepted", actor, at)
                release = record_acceptance(submission, verdict, log, self._grants, self._releases)
                self._persist_release(release)
                for claim in verdict.new_claims:
                    self._conn.execute(
                        "INSERT OR IGNORE INTO grants VALUES (?, ?)",
                        (canonical_name(claim), release.publisher),
                    )
                self._directory.record(
                    actor,
                    "publish",
                    pack,
                    at,
                    f"{submission.version} {submission.artifact_digest} accepted",
                )
            elif verdict.state == "needs_review":
                reasons = "; ".join(
                    f.message for f in verdict.findings if f.code == "registry.first-claim"
                )
                log = log.advance("needs_review", actor, at, reasons or "first claim review")
                self._pending[(pack, submission.version)] = attempt
                self._conn.execute(
                    "INSERT INTO pending VALUES (?, ?, ?)", (pack, submission.version, attempt)
                )
                self._directory.record(
                    actor,
                    "publish",
                    pack,
                    at,
                    f"{submission.version} {submission.artifact_digest} needs review",
                )
            else:  # rejected
                reasons = "; ".join(
                    f"{f.code}: {f.message}" for f in verdict.findings if f.severity == "error"
                )
                log = log.advance("rejected", actor, at, reasons or "rejected")
                self._directory.record(
                    actor,
                    "publish",
                    pack,
                    at,
                    f"{submission.version} {submission.artifact_digest} rejected",
                )
            self._persist_attempt(pack, submission.version, attempt, submission, verdict)
            self._persist_review(pack, submission.version, attempt, log)
            self._reviews[(pack, submission.version, attempt)] = log
            self._flush_audit(n)
            return verdict

    def resolve_review(
        self,
        pack: str,
        version: str,
        decision: ReviewDecision,
        actor: str,
        at: str,
        reason: str = "",
    ) -> Verdict:
        """Settle a pending review. Operators only - publishers never
        review themselves. Acceptance re-runs ``admit`` against CURRENT
        state: if the world changed underneath (a conflicting grant
        landed since submission), the resolution refuses with the fresh
        findings instead of recording a conflict."""
        if decision not in ("accepted", "rejected"):
            raise StoreError(f"unknown review decision {decision!r}")
        with self._mutation():
            n = len(self._directory.audit())
            if actor not in self._operators:
                raise RegistryError(f"user {actor!r} is not a registry operator")
            canonical = canonical_name(pack)
            attempt = self._pending.get((canonical, version))
            if attempt is None:
                raise RegistryError(f"no pending review for {canonical} {version}")
            key = (canonical, version, attempt)
            log = self._reviews[key]
            row = self._conn.execute(
                "SELECT submission FROM attempts WHERE pack = ? AND version = ? AND attempt = ?",
                (canonical, version, attempt),
            ).fetchone()
            if row is None:
                raise StoreError(f"pending review {canonical} {version} lost its attempt record")
            submission = _submission_from_json(row["submission"])
            original = self._verdict_of(canonical, version, attempt)
            if decision == "rejected":
                log = log.advance("rejected", actor, at, reason)
                verdict = Verdict(
                    state="rejected",
                    findings=original.findings,
                    new_claims=original.new_claims,
                )
                self._directory.record(
                    actor, "review", canonical, at, f"{version} rejected: {reason}"
                )
            else:
                fresh = admit(submission, self._grants, self._releases)
                if fresh.state == "rejected":
                    reasons = "; ".join(
                        f"{f.code}: {f.message}" for f in fresh.findings if f.severity == "error"
                    )
                    raise RegistryError(
                        f"cannot accept {canonical} {version}: the submission no longer "
                        f"admits against current registry state ({reasons})"
                    )
                log = log.advance("accepted", actor, at, reason)
                verdict = Verdict(
                    state="accepted",
                    findings=original.findings,
                    new_claims=fresh.new_claims,
                    already_published=fresh.already_published,
                )
                release = record_acceptance(submission, verdict, log, self._grants, self._releases)
                self._persist_release(release)
                for claim in fresh.new_claims:
                    self._conn.execute(
                        "INSERT OR IGNORE INTO grants VALUES (?, ?)",
                        (canonical_name(claim), release.publisher),
                    )
                self._directory.record(actor, "review", canonical, at, f"{version} accepted")
            del self._pending[(canonical, version)]
            self._conn.execute(
                "DELETE FROM pending WHERE pack = ? AND version = ?", (canonical, version)
            )
            self._persist_review(canonical, version, attempt, log, replace=True)
            self._reviews[key] = log
            self._flush_audit(n)
            return verdict

    def yank_release(self, pack: str, version: str, actor: str, at: str, reason: str) -> None:
        """Yank an accepted release without deleting its immutable record.

        Publisher owners control their release lifecycle. The release and
        artifact remain available for exact-pin reproduction; browse and
        new resolution consult ``yank_reason`` and exclude it."""
        if (
            not reason
            or len(reason) > MAX_YANK_REASON_CHARS
            or not reason.isascii()
            or not reason.isprintable()
        ):
            raise RegistryError(
                f"yanking a release requires 1-{MAX_YANK_REASON_CHARS} printable ASCII characters"
            )
        with self._mutation():
            n = len(self._directory.audit())
            canonical = canonical_name(pack)
            release = self._releases.get(canonical, version)
            if release is None:
                raise RegistryError(f"no release {version} for pack {canonical!r}")
            self._directory.authorize(actor, release.publisher, "edit-metadata")
            attempt, log = self._release_review(release)
            if log.state == "yanked":
                return
            log = log.advance("yanked", actor, at, reason)
            self._persist_review(canonical, version, attempt, log, replace=True)
            self._reviews[(canonical, version, attempt)] = log
            self._directory.record(actor, "yank", canonical, at, f"{version}: {reason}")
            self._flush_audit(n)

    # -- publish internals ----------------------------------------------------

    def _release_review(self, release: Release) -> tuple[int, ReviewLog]:
        """The accepted attempt that created ``release``.

        Later rejected attempts for immutable-version violations are not
        the release lifecycle and must never hide or receive its yank."""
        matches: list[tuple[int, ReviewLog]] = []
        for (pack, version, attempt), log in self._reviews.items():
            if (
                pack != release.pack
                or version != release.version
                or log.state not in ("accepted", "yanked")
            ):
                continue
            row = self._conn.execute(
                "SELECT submission FROM attempts WHERE pack = ? AND version = ? AND attempt = ?",
                (pack, version, attempt),
            ).fetchone()
            if (
                row is not None
                and _submission_from_json(row["submission"]).artifact_digest
                == release.artifact_digest
            ):
                matches.append((attempt, log))
        if len(matches) != 1:
            raise StoreError(
                f"release {release.pack} {release.version} has {len(matches)} accepted attempts"
            )
        return matches[0]

    def _next_attempt(self, pack: str, version: str) -> int:
        row = self._conn.execute(
            "SELECT MAX(attempt) AS latest FROM attempts WHERE pack = ? AND version = ?",
            (pack, version),
        ).fetchone()
        latest = row["latest"] if row is not None and row["latest"] is not None else 0
        return int(latest) + 1

    def _verdict_of(self, pack: str, version: str, attempt: int) -> Verdict:
        row = self._conn.execute(
            "SELECT verdict FROM attempts WHERE pack = ? AND version = ? AND attempt = ?",
            (pack, version, attempt),
        ).fetchone()
        if row is None:
            raise StoreError(f"attempt {pack} {version} #{attempt} has no verdict record")
        payload = _decode_json(row["verdict"], "verdict")
        state = _str_field(payload, "state", "verdict")
        if state not in ("accepted", "needs_review", "rejected"):
            raise StoreError(f"verdict record has unknown state {state!r}")
        findings_raw = payload.get("findings")
        if not isinstance(findings_raw, list):
            raise StoreError("verdict record field 'findings' must be a list")
        findings: list[AdmissionFinding] = []
        for item in cast("list[object]", findings_raw):
            if not isinstance(item, dict):
                raise StoreError("verdict findings must be JSON objects")
            entry = cast("dict[str, object]", item)
            severity = _str_field(entry, "severity", "finding")
            if severity not in ("error", "info"):
                raise StoreError(f"verdict finding has unknown severity {severity!r}")
            findings.append(
                AdmissionFinding(
                    severity=severity,
                    code=_str_field(entry, "code", "finding"),
                    message=_str_field(entry, "message", "finding"),
                    fix=_str_field(entry, "fix", "finding"),
                )
            )
        return Verdict(
            state=state,
            findings=tuple(findings),
            new_claims=_str_list(payload, "newClaims", "verdict"),
        )

    def _persist_attempt(
        self, pack: str, version: str, attempt: int, submission: Submission, verdict: Verdict
    ) -> None:
        verdict_json = canonical_json(
            {
                "state": verdict.state,
                "newClaims": list(verdict.new_claims),
                "findings": [
                    {
                        "severity": f.severity,
                        "code": f.code,
                        "message": f.message,
                        "fix": f.fix,
                    }
                    for f in verdict.findings
                ],
            }
        )
        self._conn.execute(
            "INSERT INTO attempts VALUES (?, ?, ?, ?, ?)",
            (pack, version, attempt, _submission_json(submission), verdict_json),
        )

    def _persist_review(
        self, pack: str, version: str, attempt: int, log: ReviewLog, replace: bool = False
    ) -> None:
        if replace:
            self._conn.execute(
                "DELETE FROM reviews WHERE pack = ? AND version = ? AND attempt = ?",
                (pack, version, attempt),
            )
        for seq, transition in enumerate(log.transitions):
            self._conn.execute(
                "INSERT INTO reviews VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    pack,
                    version,
                    attempt,
                    seq,
                    transition.to_state,
                    transition.actor,
                    transition.reason,
                    transition.at,
                ),
            )

    def _persist_release(self, release: Release) -> None:
        self._conn.execute(
            "INSERT INTO releases VALUES (?, ?, ?)",
            (release.pack, release.version, release.record_json()),
        )


__all__ = [
    "MAX_YANK_REASON_CHARS",
    "SCHEMA_VERSION",
    "RegistryStore",
    "ReviewDecision",
    "StoreError",
]
