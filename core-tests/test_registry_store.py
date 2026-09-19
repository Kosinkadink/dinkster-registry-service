"""RegistryStore (DESIGN M8): durable registry state over the pure model.

What this proves: the store adds persistence and NOTHING else - every
refusal the pure models make, the store makes; everything the store
accepts survives a reopen bit-for-bit; and a corrupted database refuses
at open, never at authorization or admission time. The publish/review
flow is role-gated end-to-end, persists its evidence whatever the
outcome, and cannot land a conflict even when the world changed while a
review was pending.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from dinkster_registry import (
    DoctorEvidence,
    RegistryError,
    ReleaseTemplate,
    Submission,
    artifact_digest,
)
from dinkster_sqlite_registry import RegistryStore, StoreError

T0 = "2026-07-01T00:00:00+00:00"
T1 = "2026-07-02T00:00:00+00:00"
T2 = "2026-07-03T00:00:00+00:00"
EXPIRY = "2026-08-01T00:00:00+00:00"

DIGEST_A = artifact_digest(b"artifact bytes A")
DIGEST_B = artifact_digest(b"artifact bytes B")


def submission(
    publisher: str = "acme",
    pack: str = "img-tools",
    namespaces: tuple[str, ...] = (),
    version: str = "1.0.0",
    digest: str = DIGEST_A,
    ok: bool = True,
    node_types: tuple[str, ...] = ("img-tools.blur",),
) -> Submission:
    return Submission(
        publisher=publisher,
        pack_name=pack,
        namespaces=namespaces,
        version=version,
        artifact_digest=digest,
        evidence=DoctorEvidence(
            pack_name=pack,
            ok=ok,
            node_types=node_types,
            error_codes=() if ok else ("probe.import-failed",),
        ),
    )


def store_with_publisher(path: Path) -> RegistryStore:
    store = RegistryStore(path)
    store.register_user("alice")
    store.register_user("bob")
    store.register_user("root")
    store.add_operator("root", actor="root", at=T0)
    store.register_publisher("acme", owner="alice", at=T0)
    return store


def accept_first_publish(store: RegistryStore, sub: Submission, actor: str = "alice") -> None:
    verdict = store.publish(sub, actor=actor, at=T0)
    assert verdict.state == "needs_review"
    resolved = store.resolve_review(sub.pack_name, sub.version, "accepted", "root", T1)
    assert resolved.state in ("accepted", "needs_review")


@pytest.mark.parametrize("decision", ["reject", "", "acceppted"])
def test_review_decision_is_fail_closed(tmp_path: Path, decision: str) -> None:
    store = store_with_publisher(tmp_path / "registry.db")
    sub = submission()
    assert store.publish(sub, actor="alice", at=T0).state == "needs_review"
    with pytest.raises(StoreError, match="unknown review decision"):
        store.resolve_review(sub.pack_name, sub.version, decision, "root", T1)  # type: ignore[arg-type]
    assert store.pending_reviews()[0][0:2] == (sub.pack_name, sub.version)
    store.close()


# ---------------------------------------------------------------------------
# Persistence round trips
# ---------------------------------------------------------------------------


def test_principals_round_trip_across_reopen(tmp_path: Path) -> None:
    path = tmp_path / "registry.db"
    store = store_with_publisher(path)
    store.add_member("acme", "bob", "member", actor="alice", at=T1)
    store.set_display_name("acme", "ACME Tools", actor="alice", at=T1)
    plaintext, record = store.mint_token("acme", minted_by="bob", at=T1, expires_at=EXPIRY)
    audit_before = store.audit()
    store.close()

    reopened = RegistryStore(path)
    assert reopened.role_of("alice", "acme") == "owner"
    assert reopened.role_of("bob", "acme") == "member"
    assert reopened.display_name("acme") == "ACME Tools"
    assert reopened.is_operator("root")
    assert reopened.verify_token(plaintext, at=T2) == record
    assert reopened.audit() == audit_before
    reopened.close()


def test_release_templates_survive_reopen(tmp_path: Path) -> None:
    """Template descriptors ride the release record bit-for-bit: what
    the probe recorded at publish is what a reopened store serves,
    including a needs_review submission resolved after the fact."""
    path = tmp_path / "registry.db"
    store = store_with_publisher(path)
    template = ReleaseTemplate(
        id="starter",
        name="Starter",
        digest=artifact_digest(b"document bytes"),
        path="templates/starter.json",
        description="a starting point",
        tags=("video",),
        assets=("model-a",),
    )
    accept_first_publish(store, replace(submission(), templates=(template,)))
    store.close()

    reopened = RegistryStore(path)
    release = reopened.release("img-tools", "1.0.0")
    assert release is not None
    assert release.templates == (template,)
    reopened.close()


def test_pre_template_release_records_rehydrate_empty(tmp_path: Path) -> None:
    """Records written before templates existed lack the key entirely;
    absence means "no templates", never a corrupt-database refusal."""
    path = tmp_path / "registry.db"
    store = store_with_publisher(path)
    accept_first_publish(store, submission())
    store.close()

    with sqlite3.connect(path) as conn:
        (record,) = conn.execute(
            "SELECT record FROM releases WHERE pack = ? AND version = ?",
            ("img-tools", "1.0.0"),
        ).fetchone()
        payload = json.loads(record)
        del payload["templates"]
        conn.execute(
            "UPDATE releases SET record = ? WHERE pack = ? AND version = ?",
            (json.dumps(payload), "img-tools", "1.0.0"),
        )

    reopened = RegistryStore(path)
    release = reopened.release("img-tools", "1.0.0")
    assert release is not None
    assert release.templates == ()
    reopened.close()


def test_revocations_survive_reopen(tmp_path: Path) -> None:
    path = tmp_path / "registry.db"
    store = store_with_publisher(path)
    store.add_member("acme", "bob", "member", actor="alice", at=T0)
    bob_token, _ = store.mint_token("acme", minted_by="bob", at=T0, expires_at=EXPIRY)
    keep, kept_record = store.mint_token("acme", minted_by="alice", at=T0, expires_at=EXPIRY)
    store.remove_member("acme", "bob", actor="alice", at=T1)
    store.close()

    reopened = RegistryStore(path)
    with pytest.raises(RegistryError, match="revoked"):
        reopened.verify_token(bob_token, at=T2)
    assert reopened.verify_token(keep, at=T2) == kept_record
    assert reopened.role_of("bob", "acme") is None
    reopened.close()


def test_publish_flow_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "registry.db"
    store = store_with_publisher(path)
    accept_first_publish(store, submission())
    store.close()

    reopened = RegistryStore(path)
    release = reopened.release("img-tools", "1.0.0")
    assert release is not None
    assert release.artifact_digest == DIGEST_A
    assert release.publisher == "acme"
    assert ("img-tools", "acme") in [(g.claim, g.publisher) for g in reopened.grants()]
    history = reopened.review_history("img-tools", "1.0.0")
    assert [log.state for _, log in history] == ["accepted"]
    # Established publisher: the next version admits deterministically.
    verdict = reopened.publish(submission(version="1.1.0", digest=DIGEST_B), "alice", T2)
    assert verdict.state == "accepted"
    reopened.close()


def test_yank_state_and_reason_survive_reopen(tmp_path: Path) -> None:
    path = tmp_path / "registry.db"
    store = store_with_publisher(path)
    accept_first_publish(store, submission())
    store.yank_release("img-tools", "1.0.0", "alice", T2, "critical defect")
    assert store.yank_reason("img-tools", "1.0.0") == "critical defect"
    store.close()

    reopened = RegistryStore(path)
    assert reopened.release("img-tools", "1.0.0") is not None
    assert reopened.yank_reason("img-tools", "1.0.0") == "critical defect"
    assert reopened.review_history("img-tools", "1.0.0")[-1][1].state == "yanked"
    reopened.close()


def test_yank_tracks_the_accepted_attempt_across_later_rejections(tmp_path: Path) -> None:
    path = tmp_path / "registry.db"
    store = store_with_publisher(path)
    accept_first_publish(store, submission())
    assert store.publish(submission(digest=DIGEST_B), "alice", T2).state == "rejected"
    store.yank_release("img-tools", "1.0.0", "alice", T2, "critical defect")
    assert store.publish(submission(digest=DIGEST_B), "alice", T2).state == "rejected"
    assert store.yank_reason("img-tools", "1.0.0") == "critical defect"
    store.close()

    reopened = RegistryStore(path)
    assert reopened.yank_reason("img-tools", "1.0.0") == "critical defect"
    reopened.close()


# ---------------------------------------------------------------------------
# The database is never trusted over the model
# ---------------------------------------------------------------------------


def test_unknown_schema_version_refuses(tmp_path: Path) -> None:
    path = tmp_path / "registry.db"
    RegistryStore(path).close()
    conn = sqlite3.connect(str(path))
    conn.execute("PRAGMA user_version = 99")
    conn.close()
    with pytest.raises(StoreError, match="schema version 99"):
        RegistryStore(path)


def test_corrupt_rows_refuse_at_open(tmp_path: Path) -> None:
    path = tmp_path / "registry.db"
    store = store_with_publisher(path)
    store.close()
    conn = sqlite3.connect(str(path))
    with conn:
        conn.execute("DELETE FROM memberships WHERE role = 'owner'")
    conn.close()
    with pytest.raises(StoreError, match="without an owner"):
        RegistryStore(path)


def test_tampered_release_refuses_at_open(tmp_path: Path) -> None:
    path = tmp_path / "registry.db"
    store = store_with_publisher(path)
    accept_first_publish(store, submission())
    store.close()
    conn = sqlite3.connect(str(path))
    with conn:
        conn.execute(
            "UPDATE releases SET record = ?",
            (
                '{"pack":"img-tools","version":"1.0.0","artifactDigest":"sha256:nope",'
                '"publisher":"acme","claims":["img-tools"],"nodeTypes":[]}',
            ),
        )
    conn.close()
    with pytest.raises(StoreError, match="digest"):
        RegistryStore(path)


def test_release_with_unowned_claim_refuses_at_open(tmp_path: Path) -> None:
    path = tmp_path / "registry.db"
    store = store_with_publisher(path)
    accept_first_publish(store, submission())
    store.close()
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM grants WHERE claim = 'img-tools'")
    with pytest.raises(StoreError, match="is not granted"):
        RegistryStore(path)


def test_publish_write_failure_rehydrates_memory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "registry.db"
    store = store_with_publisher(path)

    def fail_review(*args: object, **kwargs: object) -> None:
        raise sqlite3.OperationalError("injected write failure")

    monkeypatch.setattr(store, "_persist_review", fail_review)
    with pytest.raises(sqlite3.OperationalError, match="injected"):
        store.publish(submission(), actor="alice", at=T0)
    assert store.pending_reviews() == ()
    assert store.review_history("img-tools", "1.0.0") == ()
    assert store.releases() == ()
    store.close()

    reopened = RegistryStore(path)
    assert reopened.pending_reviews() == ()
    assert reopened.review_history("img-tools", "1.0.0") == ()
    reopened.close()


# ---------------------------------------------------------------------------
# Publish: role-gated, evidence-persisting, immutable
# ---------------------------------------------------------------------------


def test_publish_is_role_gated(tmp_path: Path) -> None:
    store = store_with_publisher(tmp_path / "registry.db")
    with pytest.raises(RegistryError, match="not a member"):
        store.publish(submission(), actor="bob", at=T0)
    with pytest.raises(RegistryError, match="not a member"):
        store.publish(submission(), actor="root", at=T0)
    store.close()


def test_rejected_publish_persists_visible_evidence(tmp_path: Path) -> None:
    path = tmp_path / "registry.db"
    store = store_with_publisher(path)
    verdict = store.publish(submission(ok=False), actor="alice", at=T0)
    assert verdict.state == "rejected"
    store.close()

    reopened = RegistryStore(path)
    ((attempt, log),) = reopened.review_history("img-tools", "1.0.0")
    assert attempt == 1
    assert log.state == "rejected"
    assert "doctor" in log.transitions[-1].reason or "probe" in log.transitions[-1].reason
    # Rejection recorded nothing else - and resubmission opens attempt 2.
    assert reopened.release("img-tools", "1.0.0") is None
    assert reopened.grants() == ()
    verdict = reopened.publish(submission(), actor="alice", at=T1)
    assert verdict.state == "needs_review"
    assert [a for a, _ in reopened.review_history("img-tools", "1.0.0")] == [1, 2]
    reopened.close()


def test_idempotent_republication_records_nothing_new(tmp_path: Path) -> None:
    store = store_with_publisher(tmp_path / "registry.db")
    accept_first_publish(store, submission())
    before = len(store.review_history("img-tools", "1.0.0"))
    verdict = store.publish(submission(), actor="alice", at=T2)
    assert verdict.state == "accepted"
    assert verdict.already_published
    assert len(store.review_history("img-tools", "1.0.0")) == before
    store.close()


def test_release_immutability_survives_the_store(tmp_path: Path) -> None:
    store = store_with_publisher(tmp_path / "registry.db")
    accept_first_publish(store, submission())
    verdict = store.publish(submission(digest=DIGEST_B), actor="alice", at=T2)
    assert verdict.state == "rejected"
    assert any(f.code == "registry.release-immutable" for f in verdict.findings)
    release = store.release("img-tools", "1.0.0")
    assert release is not None and release.artifact_digest == DIGEST_A
    store.close()


# ---------------------------------------------------------------------------
# The review queue
# ---------------------------------------------------------------------------


def test_pending_queue_guards_and_idempotent_resubmit(tmp_path: Path) -> None:
    store = store_with_publisher(tmp_path / "registry.db")
    first = store.publish(submission(), actor="alice", at=T0)
    assert first.state == "needs_review"
    ((pack, version, attempt, pending_sub),) = store.pending_reviews()
    assert (pack, version, attempt) == ("img-tools", "1.0.0", 1)
    assert pending_sub.artifact_digest == DIGEST_A
    # Identical bytes: the same needs_review answer, no second attempt.
    again = store.publish(submission(), actor="alice", at=T1)
    assert again.state == "needs_review"
    assert len(store.pending_reviews()) == 1
    # Different bytes while pending: refused, never silently queued twice.
    with pytest.raises(RegistryError, match="pending review"):
        store.publish(submission(digest=DIGEST_B), actor="alice", at=T1)
    store.close()


def test_resolution_requires_an_operator_and_operators_bootstrap_once(tmp_path: Path) -> None:
    store = RegistryStore(tmp_path / "registry.db")
    store.register_user("alice")
    store.register_user("root")
    store.register_publisher("acme", owner="alice", at=T0)
    store.publish(submission(), actor="alice", at=T0)
    with pytest.raises(RegistryError, match="not a registry operator"):
        store.resolve_review("img-tools", "1.0.0", "accepted", "alice", T1)
    # Bootstrap: the first operator needs no authorizer; afterwards it is gated.
    store.add_operator("root", actor="root", at=T0)
    with pytest.raises(RegistryError, match="not a registry operator"):
        store.add_operator("alice", actor="alice", at=T1)
    store.resolve_review("img-tools", "1.0.0", "accepted", "root", T1)
    assert store.release("img-tools", "1.0.0") is not None
    store.close()


def test_rejection_resolution_persists_reason(tmp_path: Path) -> None:
    path = tmp_path / "registry.db"
    store = store_with_publisher(path)
    store.publish(submission(), actor="alice", at=T0)
    store.resolve_review("img-tools", "1.0.0", "rejected", "root", T1, reason="name squatting")
    assert store.pending_reviews() == ()
    assert store.release("img-tools", "1.0.0") is None
    store.close()

    reopened = RegistryStore(path)
    ((_, log),) = reopened.review_history("img-tools", "1.0.0")
    assert log.state == "rejected"
    assert log.transitions[-1].reason == "name squatting"
    assert log.transitions[-1].actor == "root"
    reopened.close()


def test_acceptance_preserves_original_findings_after_grants_change(tmp_path: Path) -> None:
    store = store_with_publisher(tmp_path / "registry.db")
    first = submission(
        pack="first-pack",
        namespaces=("shared",),
        node_types=("first-pack.node", "shared.node"),
    )
    second = submission(
        pack="second-pack",
        namespaces=("shared",),
        node_types=("second-pack.node", "shared.node"),
        digest=DIGEST_B,
    )
    assert store.publish(first, "alice", T0).state == "needs_review"
    original = store.publish(second, "alice", T0)
    assert any("shared" in finding.message for finding in original.findings)
    store.resolve_review("first-pack", "1.0.0", "accepted", "root", T1)
    resolved = store.resolve_review("second-pack", "1.0.0", "accepted", "root", T2)
    assert resolved.state == "accepted"
    assert resolved.findings == original.findings
    store.close()


def test_acceptance_reruns_admission_against_current_state(tmp_path: Path) -> None:
    """A decision made after the world changed cannot land a conflict."""
    store = store_with_publisher(tmp_path / "registry.db")
    store.register_user("carol")
    store.register_publisher("rival", owner="carol", at=T0)
    # Both publishers submit packs claiming the same free namespace.
    ours = submission(namespaces=("shared",), node_types=("img-tools.blur", "shared.op"))
    theirs = submission(
        publisher="rival",
        pack="rival-pack",
        namespaces=("shared",),
        node_types=("rival-pack.op", "shared.op"),
        digest=DIGEST_B,
    )
    store.publish(ours, actor="alice", at=T0)
    store.publish(theirs, actor="carol", at=T0)
    # The rival's claim is granted first.
    store.resolve_review("rival-pack", "1.0.0", "accepted", "root", T1)
    # Accepting ours now would grant a conflicting claim: refused with the
    # fresh findings, and the pending review stays for a reasoned rejection.
    with pytest.raises(RegistryError, match="no longer admits"):
        store.resolve_review("img-tools", "1.0.0", "accepted", "root", T2)
    assert len(store.pending_reviews()) == 1
    assert store.release("img-tools", "1.0.0") is None
    store.close()


def test_publish_and_review_land_on_the_audit_trail(tmp_path: Path) -> None:
    store = store_with_publisher(tmp_path / "registry.db")
    accept_first_publish(store, submission())
    actions = [(r.actor, r.action) for r in store.audit()]
    assert ("alice", "publish") in actions
    assert ("root", "review") in actions
    assert ("root", "add-operator") in actions
    store.close()
