"""Registry HTTP surface (DESIGN M8): artifact bytes over bearer auth.

What this proves: artifact identity is the digest on BOTH directions of
the wire (downloads are content-addressed, uploads verify actual bytes
against the declared digest before anything lands), admission to the
vault is atomic and idempotent, and every credential failure - missing,
malformed, unknown, revoked, expired - is one indistinguishable 401.
The shipped client fetcher (``http_registry_fetcher``) speaks this
service unmodified, closing the loop on the contract it committed to.

Publish over the wire proves the non-interpretation boundary: pack name
and namespace claims come from the registry's OWN probe of the vault
bytes (never the request body), every verdict state is a 200 report
with findings, and HTTP errors mean admission never ran. The real
prober (unpack + manifest claims + doctor over the exact bytes) is
covered against a real artifact.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import io
import json
import zipfile
from pathlib import Path

import pytest
from aiohttp.test_utils import TestClient, TestServer
from dinkster.registries import NamedRegistry, publish_release
from dinkster_registry import (
    DoctorEvidence,
    RegistryError,
    ReleaseTemplate,
    Submission,
    artifact_digest,
)
from dinkster_registry.artifact import build_artifact
from dinkster_registry_sqlite import (
    ArtifactVault,
    ProbeError,
    Prober,
    ProbeResult,
    RegistryStore,
    create_registry_app,
)

T0 = "2026-07-01T00:00:00+00:00"
T1 = "2026-07-02T00:00:00+00:00"
EXPIRY = "2026-08-01T00:00:00+00:00"
AFTER_EXPIRY = "2026-09-01T00:00:00+00:00"


def zip_bytes(payload: bytes = b"pack contents") -> bytes:
    """A minimal real zip archive - the vault checks shape, not manifests."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("dinkster-pack.toml", payload)
    return buffer.getvalue()


def fake_prober(pack: str = "img-tools", ok: bool = True) -> Prober:
    """A probe that 'reads' fixed claims and evidence from any archive -
    the service must consume claims from HERE, never the request body."""

    def probe(archive: Path) -> ProbeResult:
        report = {
            "reportVersion": 1,
            "pack": pack,
            "ok": ok,
            "nodeTypes": [f"{pack}.blur"],
            "findings": []
            if ok
            else [{"severity": "error", "code": "probe.import-failed", "message": "boom"}],
        }
        return ProbeResult(pack_name=pack, namespaces=(pack,), report_json=json.dumps(report))

    return probe


def store_with_token(path: Path) -> tuple[RegistryStore, str]:
    store = RegistryStore(path)
    store.register_user("alice")
    store.register_user("root")
    store.add_operator("root", actor="root", at=T0)
    store.register_publisher("acme", owner="alice", at=T0)
    plaintext, _ = store.mint_token("acme", minted_by="alice", at=T0, expires_at=EXPIRY)
    return store, plaintext


async def make_client(
    tmp_path: Path,
    *,
    clock: str = T0,
    prober: Prober | None = None,
    max_artifact_bytes: int | None = None,
) -> tuple[TestClient, RegistryStore, ArtifactVault, str]:
    store, token = store_with_token(tmp_path / "registry.db")
    vault = ArtifactVault(tmp_path / "artifacts")
    kwargs = {} if max_artifact_bytes is None else {"max_artifact_bytes": max_artifact_bytes}
    app = create_registry_app(store, vault, clock=lambda: clock, prober=prober, **kwargs)
    client = TestClient(TestServer(app))
    await client.start_server()
    return client, store, vault, token


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# ArtifactVault
# ---------------------------------------------------------------------------


def test_vault_admission_is_idempotent_and_atomic(tmp_path: Path) -> None:
    """Identical bytes land once ever; admission leaves no partial files;
    the stored path serves back the exact bytes."""
    vault = ArtifactVault(tmp_path / "vault")
    data = zip_bytes()
    digest, created = vault.admit(data)
    assert created
    assert digest == artifact_digest(data)
    hex_digest = digest.partition(":")[2]
    path = vault.path_of(hex_digest)
    assert path is not None and path.read_bytes() == data
    assert vault.has(hex_digest)

    again, created_again = vault.admit(data)
    assert again == digest and not created_again
    assert not list((tmp_path / "vault").glob("*.part"))
    assert vault.path_of("0" * 64) is None
    assert not vault.has("0" * 64)


def test_vault_path_rejects_traversal(tmp_path: Path) -> None:
    vault = ArtifactVault(tmp_path / "vault")
    with pytest.raises(Exception, match="64 lowercase hex"):
        vault.path_of("../outside")


# ---------------------------------------------------------------------------
# Download
# ---------------------------------------------------------------------------


def test_download_unknown_and_malformed_are_404(tmp_path: Path) -> None:
    """Unknown digests and non-digest paths are both plain 404s - the
    download surface has no probing contract to leak."""

    async def scenario() -> None:
        client, _, _, _ = await make_client(tmp_path)
        try:
            resp = await client.get(f"/artifacts/{'0' * 64}.zip")
            assert resp.status == 404
            assert await resp.json() == {"error": "no such artifact"}
            for bad in ("short.zip", f"{'0' * 64}.tar", f"{'G' * 64}.zip"):
                resp = await client.get(f"/artifacts/{bad}")
                assert resp.status == 404
        finally:
            await client.close()

    asyncio.run(scenario())


def test_upload_download_round_trip_with_immutable_caching(tmp_path: Path) -> None:
    """201 on first upload, 200 on identical re-upload; downloads carry the
    quoted digest ETag + forever cache lifetime and honor If-None-Match."""

    async def scenario() -> None:
        client, _, _, token = await make_client(tmp_path)
        try:
            data = zip_bytes()
            digest = artifact_digest(data)
            hex_digest = digest.partition(":")[2]

            resp = await client.put(
                f"/artifacts/{hex_digest}.zip", data=data, headers=bearer(token)
            )
            assert resp.status == 201
            assert await resp.json() == {"digest": digest}

            resp = await client.put(
                f"/artifacts/{hex_digest}.zip", data=data, headers=bearer(token)
            )
            assert resp.status == 200  # idempotent re-upload

            resp = await client.get(f"/artifacts/{hex_digest}.zip")
            assert resp.status == 200
            assert await resp.read() == data
            assert resp.headers["ETag"] == f'"{digest}"'
            assert resp.headers["Cache-Control"] == "public, max-age=31536000, immutable"
            assert resp.headers["Content-Type"] == "application/zip"

            resp = await client.get(
                f"/artifacts/{hex_digest}.zip", headers={"If-None-Match": f'"{digest}"'}
            )
            assert resp.status == 304
            assert resp.headers["ETag"] == f'"{digest}"'
        finally:
            await client.close()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Upload refusals
# ---------------------------------------------------------------------------


def test_upload_credential_failures_are_one_indistinguishable_401(tmp_path: Path) -> None:
    """Missing header, wrong scheme, unknown token, revoked token, expired
    token: same status, same body, WWW-Authenticate present - the wire
    never confirms whether a credential exists."""

    async def scenario() -> None:
        client, store, _, token = await make_client(tmp_path, clock=AFTER_EXPIRY)
        try:
            data = zip_bytes()
            hex_digest = artifact_digest(data).partition(":")[2]
            revoked, record = store.mint_token("acme", minted_by="alice", at=T0, expires_at=EXPIRY)
            store.revoke_token(record.token_id, actor="alice", at=T0, reason="rotated")
            attempts: list[dict[str, str]] = [
                {},
                {"Authorization": "Basic dXNlcjpwYXNz"},
                {"Authorization": "Bearer "},
                bearer("dinkster_pat_definitely-not-a-token"),
                bearer(revoked),
                bearer(token),  # valid token, but the clock is past expiry
            ]
            for headers in attempts:
                resp = await client.put(f"/artifacts/{hex_digest}.zip", data=data, headers=headers)
                assert resp.status == 401
                assert await resp.json() == {"error": "unauthorized"}
                assert resp.headers["WWW-Authenticate"] == "Bearer"
        finally:
            await client.close()

    asyncio.run(scenario())


def test_upload_verifies_declared_digest_before_storing(tmp_path: Path) -> None:
    """The path's digest is a claim; the actual bytes decide. A mismatch
    refuses and nothing lands under either digest."""

    async def scenario() -> None:
        client, _, vault, token = await make_client(tmp_path)
        try:
            data = zip_bytes()
            actual_hex = artifact_digest(data).partition(":")[2]
            lying_hex = "0" * 64
            resp = await client.put(f"/artifacts/{lying_hex}.zip", data=data, headers=bearer(token))
            assert resp.status == 400
            body = await resp.json()
            assert "digest mismatch" in body["error"]
            assert not vault.has(lying_hex) and not vault.has(actual_hex)

            resp = await client.put("/artifacts/not-a-digest.zip", data=data, headers=bearer(token))
            assert resp.status == 400
        finally:
            await client.close()

    asyncio.run(scenario())


def test_upload_refuses_non_zip_bytes(tmp_path: Path) -> None:
    """The vault stores pack artifacts, not arbitrary blobs: bytes that are
    not a zip archive at all refuse before digest checking."""

    async def scenario() -> None:
        client, _, vault, token = await make_client(tmp_path)
        try:
            data = b"just some bytes, no archive"
            hex_digest = artifact_digest(data).partition(":")[2]
            resp = await client.put(
                f"/artifacts/{hex_digest}.zip", data=data, headers=bearer(token)
            )
            assert resp.status == 400
            assert "not a zip archive" in (await resp.json())["error"]
            assert not vault.has(hex_digest)
        finally:
            await client.close()

    asyncio.run(scenario())


def test_upload_over_size_cap_refuses(tmp_path: Path) -> None:
    """client_max_size does the enforcement - the body is never buffered
    past the cap, and the refusal is aiohttp's own 413."""

    async def scenario() -> None:
        client, _, vault, token = await make_client(tmp_path, max_artifact_bytes=1024)
        try:
            data = zip_bytes(b"x" * 4096)
            hex_digest = artifact_digest(data).partition(":")[2]
            resp = await client.put(
                f"/artifacts/{hex_digest}.zip", data=data, headers=bearer(token)
            )
            assert resp.status == 413
            assert not vault.has(hex_digest)
        finally:
            await client.close()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Publish
# ---------------------------------------------------------------------------


def test_publish_client_uploads_and_submits_idempotently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The shipped client speaks the in-test service's real upload and
    publish routes, and rebuilding/re-uploading identical bytes keeps the
    same digest."""

    async def scenario() -> None:
        client, _, vault, token = await make_client(tmp_path, prober=fake_prober())
        try:
            monkeypatch.setenv("TEST_REGISTRY_TOKEN", token)
            registry = NamedRegistry(
                name="test",
                endpoint=str(client.make_url("/")).rstrip("/"),
                token_env="TEST_REGISTRY_TOKEN",
            )
            pack = tmp_path / "pack"
            pack.mkdir()
            (pack / "dinkster-pack.toml").write_text(
                '[pack]\nname = "img-tools"\n\n[pack.entry]\nnodes = "nodes:NODES"\n'
            )
            (pack / "nodes.py").write_text("NODES = []\n")
            first_archive = tmp_path / "first.zip"
            second_archive = tmp_path / "second.zip"
            first_digest = build_artifact(pack, first_archive)
            second_digest = build_artifact(pack, second_archive)
            assert second_digest == first_digest

            first = await asyncio.to_thread(
                publish_release, registry, first_archive, first_digest, "1.0.0"
            )
            second = await asyncio.to_thread(
                publish_release, registry, second_archive, second_digest, "1.0.0"
            )
            assert first.state == second.state == "needs_review"
            assert [finding.code for finding in first.findings] == ["registry.first-claim"]
            assert vault.has(first_digest.partition(":")[2])
        finally:
            await client.close()

    asyncio.run(scenario())


async def upload(client: TestClient, token: str, data: bytes) -> str:
    digest = artifact_digest(data)
    resp = await client.put(
        f"/artifacts/{digest.partition(':')[2]}.zip", data=data, headers=bearer(token)
    )
    assert resp.status in (200, 201)
    return digest


def test_publish_lifecycle_over_the_wire(tmp_path: Path) -> None:
    """First claim -> 202-shaped needs_review report; after operator
    acceptance a second version publishes straight to accepted; identical
    re-publication answers alreadyPublished. All three are 200 reports -
    a verdict is never a transport error."""

    async def scenario() -> None:
        client, store, _, token = await make_client(tmp_path, prober=fake_prober())
        try:
            digest_v1 = await upload(client, token, zip_bytes(b"v1"))
            body = {"version": "1.0.0", "artifactDigest": digest_v1}
            resp = await client.post("/publish", json=body, headers=bearer(token))
            assert resp.status == 200
            verdict = await resp.json()
            assert verdict["state"] == "needs_review"
            assert any(f["code"] == "registry.first-claim" for f in verdict["findings"])

            # Identical re-submission while pending: same verdict, no new attempt.
            resp = await client.post("/publish", json=body, headers=bearer(token))
            assert resp.status == 200
            assert (await resp.json())["state"] == "needs_review"

            store.resolve_review("img-tools", "1.0.0", "accepted", "root", T1)
            first = store.release("img-tools", "1.0.0")
            assert first is not None and first.artifact_digest == digest_v1

            digest_v2 = await upload(client, token, zip_bytes(b"v2"))
            resp = await client.post(
                "/publish",
                json={"version": "2.0.0", "artifactDigest": digest_v2},
                headers=bearer(token),
            )
            assert resp.status == 200
            verdict = await resp.json()
            assert verdict["state"] == "accepted"
            assert not verdict["alreadyPublished"]

            resp = await client.post(
                "/publish",
                json={"version": "2.0.0", "artifactDigest": digest_v2},
                headers=bearer(token),
            )
            assert resp.status == 200
            verdict = await resp.json()
            assert verdict["state"] == "accepted" and verdict["alreadyPublished"]

            release = store.release("img-tools", "2.0.0")
            assert release is not None and release.artifact_digest == digest_v2
        finally:
            await client.close()

    asyncio.run(scenario())


def test_publish_rejection_is_a_report_not_an_error(tmp_path: Path) -> None:
    """Evidence with error findings lands as a rejected 200 with the
    findings visible - the attempt persists as the reasoned record."""

    async def scenario() -> None:
        client, _, _, token = await make_client(tmp_path, prober=fake_prober(ok=False))
        try:
            digest = await upload(client, token, zip_bytes())
            resp = await client.post(
                "/publish",
                json={"version": "1.0.0", "artifactDigest": digest},
                headers=bearer(token),
            )
            assert resp.status == 200
            verdict = await resp.json()
            assert verdict["state"] == "rejected"
            assert verdict["findings"]  # the why travels with the verdict
        finally:
            await client.close()

    asyncio.run(scenario())


def test_publish_http_errors_mean_admission_never_ran(tmp_path: Path) -> None:
    """401 no credential; 400 malformed body; 404 artifact not uploaded;
    422 unprobeable bytes; 403 token scoped to a different pack; 409 a
    different-bytes submission already pending for the (pack, version)."""

    def exploding_prober(archive: Path) -> ProbeResult:
        raise ProbeError("no manifest in archive")

    async def scenario() -> None:
        client, store, _, token = await make_client(tmp_path, prober=fake_prober())
        try:
            digest = await upload(client, token, zip_bytes())
            resp = await client.post(
                "/publish", json={"version": "1.0.0", "artifactDigest": digest}
            )
            assert resp.status == 401

            resp = await client.post("/publish", data=b"not json", headers=bearer(token))
            assert resp.status == 400
            resp = await client.post("/publish", json={"version": "1.0.0"}, headers=bearer(token))
            assert resp.status == 400
            resp = await client.post(
                "/publish",
                json={"version": "1.0.0", "artifactDigest": "sha256:../outside"},
                headers=bearer(token),
            )
            assert resp.status == 400
            assert "64 lowercase hex" in (await resp.json())["error"]

            resp = await client.post(
                "/publish",
                json={"version": "1.0.0", "artifactDigest": "sha256:" + "0" * 64},
                headers=bearer(token),
            )
            assert resp.status == 404

            scoped, _ = store.mint_token(
                "acme", minted_by="alice", at=T0, expires_at=EXPIRY, pack="other-pack"
            )
            resp = await client.post(
                "/publish",
                json={"version": "1.0.0", "artifactDigest": digest},
                headers=bearer(scoped),
            )
            assert resp.status == 403

            # A pending review exists for 1.0.0; different bytes conflict.
            resp = await client.post(
                "/publish",
                json={"version": "1.0.0", "artifactDigest": digest},
                headers=bearer(token),
            )
            assert resp.status == 200
            other = await upload(client, token, zip_bytes(b"different"))
            resp = await client.post(
                "/publish",
                json={"version": "1.0.0", "artifactDigest": other},
                headers=bearer(token),
            )
            assert resp.status == 409
        finally:
            await client.close()

        # 422: the probe cannot read the bytes as a pack at all.
        client, _, _, token = await make_client(tmp_path / "unprobeable", prober=exploding_prober)
        try:
            digest = await upload(client, token, zip_bytes())
            resp = await client.post(
                "/publish",
                json={"version": "1.0.0", "artifactDigest": digest},
                headers=bearer(token),
            )
            assert resp.status == 422
            assert "could not be probed" in (await resp.json())["error"]
        finally:
            await client.close()

    asyncio.run(scenario())


def test_publish_without_prober_refuses_501(tmp_path: Path) -> None:
    """A registry deployed without probe machinery (artifact mirror)
    refuses publishes loudly instead of admitting unprobed bytes."""

    async def scenario() -> None:
        client, _, _, token = await make_client(tmp_path)
        try:
            digest = await upload(client, token, zip_bytes())
            resp = await client.post(
                "/publish",
                json={"version": "1.0.0", "artifactDigest": digest},
                headers=bearer(token),
            )
            assert resp.status == 501
        finally:
            await client.close()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# The real prober
# ---------------------------------------------------------------------------


def test_artifact_prober_reads_claims_and_evidence_from_the_bytes(tmp_path: Path) -> None:
    """The app-layer prober unpacks a real artifact, reads the manifest's
    claims, and produces a doctor report over those exact bytes; garbage
    that unpacks but has no readable manifest raises ProbeError."""
    from dinkster_registry import DoctorEvidence
    from dinkster_registry.artifact import build_artifact
    from dinkster_registry_sqlite.cli import artifact_prober

    pack_dir = tmp_path / "healthy"
    pack_dir.mkdir()
    (pack_dir / "dinkster-pack.toml").write_text(
        '[pack]\nname = "healthy-pack"\nnamespaces = ["healthy"]\n\n'
        '[pack.entry]\nnodes = "healthy_nodes:NODES"\n\n'
        "[[pack.templates]]\n"
        'id = "starter"\nname = "Starter"\nfile = "templates/starter.json"\n'
        'tags = ["demo"]\n'
    )
    (pack_dir / "templates").mkdir()
    template_bytes = b'{"nodes": []}'
    (pack_dir / "templates" / "starter.json").write_bytes(template_bytes)
    (pack_dir / "healthy_nodes.py").write_text(
        "from dinkster_api.v1 import InputSpec, Node, NodeSchema, OutputSpec, TypeExpr\n\n\n"
        "class Doubler(Node):\n"
        "    @classmethod\n"
        "    def define_schema(cls):\n"
        "        return NodeSchema(\n"
        '            node_type="healthy.doubler",\n'
        '            inputs=(InputSpec("value", TypeExpr.concrete("core.int")),),\n'
        '            outputs=(OutputSpec("doubled", TypeExpr.concrete("core.int")),),\n'
        "        )\n\n"
        "    @classmethod\n"
        "    def execute(cls, *, value):\n"
        "        return cls.outputs(doubled=value * 2)\n\n\n"
        "NODES = [Doubler]\n"
    )
    archive = tmp_path / "healthy.zip"
    build_artifact(pack_dir, archive)

    probe = artifact_prober()
    result = probe(archive)
    assert result.pack_name == "healthy-pack"
    assert result.namespaces == ("healthy",)
    evidence = DoctorEvidence.from_report_json(result.report_json)
    assert evidence.ok, result.report_json
    assert evidence.node_types == ("healthy.doubler",)
    # Template descriptors come from the probe's own manifest read, with
    # the artifact member path and the document digest recorded.
    assert result.templates == (
        ReleaseTemplate(
            id="starter",
            name="Starter",
            digest="sha256:" + hashlib.sha256(template_bytes).hexdigest(),
            path="templates/starter.json",
            tags=("demo",),
        ),
    )

    broken = tmp_path / "broken.zip"
    broken.write_bytes(zip_bytes(b"not = valid ["))  # zip yes, manifest no
    try:
        probe(broken)
        raise AssertionError("expected ProbeError")
    except ProbeError:
        pass


# ---------------------------------------------------------------------------
# The shipped client speaks this service
# ---------------------------------------------------------------------------


def test_http_registry_fetcher_round_trips_against_the_service(tmp_path: Path) -> None:
    """The installer's fetcher, pointed at a live instance of this app,
    downloads exactly the uploaded bytes - the client contract shipped in
    959f829 and this service agree without adaptation."""
    from dinkster.installer import http_registry_fetcher
    from dinkster_registry.install import LockedPack

    async def scenario() -> None:
        client, _, vault, _ = await make_client(tmp_path)
        try:
            data = zip_bytes()
            digest, _ = vault.admit(data)
            entry = LockedPack(
                pack="demo",
                version="1.0.0",
                artifact_digest=digest,
                publisher="acme",
                claims=("demo",),
                source="registry",
            )
            server = client.server
            endpoint = f"http://{server.host}:{server.port}"
            fetch = http_registry_fetcher(endpoint)
            assert await asyncio.to_thread(fetch, entry) == data
        finally:
            await client.close()

    asyncio.run(scenario())


def test_browse_client_round_trips_against_the_service(tmp_path: Path) -> None:
    """The manager's browse client (dinkster.registries.browse_packs /
    browse_templates), pointed at a live instance of this app, parses the
    real index wire shapes - fixture drift between client tests and this
    service cannot hide here."""
    from dinkster.registries import NamedRegistry, browse_packs, browse_templates

    async def scenario() -> None:
        client, store, _, _ = await make_client(tmp_path)
        try:
            seed_release(
                store,
                "img-tools",
                "1.0.0",
                templates=(template("starter", description="first", tags=("intro",)),),
            )
            server = client.server
            registry = NamedRegistry(
                name="live",
                endpoint=f"http://{server.host}:{server.port}",
                token_env="BROWSE_LIVE_T",
            )
            packs = await asyncio.to_thread(browse_packs, registry)
            assert [entry.pack for entry in packs.packs] == ["img-tools"]
            assert packs.packs[0].publisher == "acme"
            assert packs.packs[0].latest_version == "1.0.0"
            assert packs.packs[0].versions == 1
            assert packs.cursor == ""

            templates = await asyncio.to_thread(browse_templates, registry)
            assert [entry.id for entry in templates.templates] == ["starter"]
            row = templates.templates[0]
            assert row.pack == "img-tools" and row.version == "1.0.0"
            assert row.name == "Starter"
            assert row.description == "first"
            assert row.tags == ("intro",)
        finally:
            await client.close()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Index: the read side of admission
# ---------------------------------------------------------------------------


def seed_release(
    store: RegistryStore,
    pack: str,
    version: str,
    *,
    payload: bytes | None = None,
    node_types: tuple[str, ...] | None = None,
    templates: tuple[ReleaseTemplate, ...] = (),
) -> str:
    """Admit one accepted release directly through the store (the HTTP
    publish path is proven elsewhere); returns the artifact digest."""
    digest = artifact_digest(payload if payload is not None else f"{pack}@{version}".encode())
    resolved_types = node_types if node_types is not None else (f"{pack}.blur",)
    submission = Submission(
        publisher="acme",
        pack_name=pack,
        namespaces=(),
        version=version,
        artifact_digest=digest,
        evidence=DoctorEvidence(pack_name=pack, ok=True, node_types=resolved_types, error_codes=()),
        templates=templates,
    )
    verdict = store.publish(submission, actor="alice", at=T0)
    if verdict.state == "needs_review":
        store.resolve_review(pack, version, "accepted", "root", T1)
        assert store.release(pack, version) is not None
    else:
        assert verdict.state == "accepted"
    return digest


def test_token_list_and_revoke_refuses_the_token_immediately(tmp_path: Path) -> None:
    async def scenario() -> None:
        client, _, _, token = await make_client(tmp_path)
        try:
            resp = await client.get("/tokens", headers=bearer(token))
            assert resp.status == 200
            records = (await resp.json())["tokens"]
            assert len(records) == 1
            assert records[0]["mintedBy"] == "alice"
            assert records[0]["revoked"] is False
            assert "secretHash" not in records[0]

            token_id = records[0]["id"]
            resp = await client.post(
                f"/tokens/{token_id}/revoke",
                json={"reason": "rotation"},
                headers=bearer(token),
            )
            assert resp.status == 200

            data = zip_bytes()
            digest_hex = artifact_digest(data).partition(":")[2]
            resp = await client.put(
                f"/artifacts/{digest_hex}.zip", data=data, headers=bearer(token)
            )
            assert resp.status == 401
            assert await resp.json() == {"error": "unauthorized"}
        finally:
            await client.close()

    asyncio.run(scenario())


def test_yank_excludes_browse_and_range_candidates_but_exact_pin_warns(
    tmp_path: Path,
) -> None:
    from dinkster.registries import NamedRegistry, resolve_release

    async def scenario() -> None:
        client, store, _, token = await make_client(tmp_path)
        try:
            seed_release(store, "img-tools", "1.0.0", node_types=("img-tools.old",))
            digest = seed_release(
                store, "img-tools", "2.0.0", node_types=("img-tools.yanked-only",)
            )
            for invalid_reason in (
                "broken\nheader",
                "emoji \N{PILE OF POO}",
                "x" * 1025,
            ):
                resp = await client.post(
                    "/releases/img-tools/versions/2.0.0/yank",
                    json={"reason": invalid_reason},
                    headers=bearer(token),
                )
                assert resp.status == 400
            reason = 'q"\\' + "x" * 1021
            assert len(reason) == 1024
            resp = await client.post(
                "/releases/img-tools/versions/2.0.0/yank",
                json={"reason": reason},
                headers=bearer(token),
            )
            assert resp.status == 200

            resp = await client.get("/index/packs", params={"q": "yanked-only"})
            assert await resp.json() == {"packs": []}
            resp = await client.get("/index/packs")
            [summary] = (await resp.json())["packs"]
            assert summary["latestVersion"] == "1.0.0"
            assert summary["versions"] == 1
            resp = await client.get("/index/packs/img-tools")
            assert [entry["version"] for entry in (await resp.json())["releases"]] == ["1.0.0"]

            server = client.server
            registry = NamedRegistry(name="live", endpoint=f"http://{server.host}:{server.port}")
            with pytest.warns(UserWarning, match="img-tools@2.0.0"):
                pinned = await asyncio.to_thread(resolve_release, registry, "img-tools", "2.0.0")
            assert pinned.artifact_digest == digest
        finally:
            await client.close()

    asyncio.run(scenario())


def test_review_resolution_accepts_or_rejects_and_preserves_findings(tmp_path: Path) -> None:
    async def scenario() -> None:
        client, store, _, _ = await make_client(tmp_path)
        try:
            store.add_member("acme", "root", "member", actor="alice", at=T0)
            operator_token, _ = store.mint_token("acme", minted_by="root", at=T0, expires_at=EXPIRY)
            for pack in ("accept-me", "reject-me"):
                pending = Submission(
                    publisher="acme",
                    pack_name=pack,
                    namespaces=(),
                    version="1.0.0",
                    artifact_digest=artifact_digest(pack.encode()),
                    evidence=DoctorEvidence(
                        pack_name=pack,
                        ok=True,
                        node_types=(f"{pack}.node",),
                        error_codes=(),
                    ),
                )
                verdict = store.publish(pending, actor="alice", at=T0)
                assert verdict.state == "needs_review"

            resp = await client.post(
                "/reviews/accept-me/versions/1.0.0/resolve",
                json={"decision": "accepted", "reason": "identity verified"},
                headers=bearer(operator_token),
            )
            accepted = await resp.json()
            assert resp.status == 200 and accepted["state"] == "accepted"
            assert [finding["code"] for finding in accepted["findings"]] == ["registry.first-claim"]
            assert store.release("accept-me", "1.0.0") is not None

            resp = await client.post(
                "/reviews/reject-me/versions/1.0.0/resolve",
                json={"decision": "rejected", "reason": "identity failed"},
                headers=bearer(operator_token),
            )
            rejected = await resp.json()
            assert resp.status == 200 and rejected["state"] == "rejected"
            assert [finding["code"] for finding in rejected["findings"]] == ["registry.first-claim"]
            assert store.release("reject-me", "1.0.0") is None
        finally:
            await client.close()

    asyncio.run(scenario())


def test_new_administration_endpoints_refuse_unauthenticated_and_unauthorized(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        client, store, _, owner_token = await make_client(tmp_path)
        try:
            seed_release(store, "img-tools", "1.0.0")
            pending = Submission(
                publisher="acme",
                pack_name="review-me",
                namespaces=(),
                version="1.0.0",
                artifact_digest=artifact_digest(b"review-me"),
                evidence=DoctorEvidence(
                    pack_name="review-me",
                    ok=True,
                    node_types=("review-me.node",),
                    error_codes=(),
                ),
            )
            store.publish(pending, actor="alice", at=T0)
            store.register_user("bob")
            store.add_member("acme", "bob", "member", actor="alice", at=T0)
            member_token, _ = store.mint_token("acme", minted_by="bob", at=T0, expires_at=EXPIRY)
            store.add_member("acme", "root", "member", actor="alice", at=T0)
            scoped_owner, _ = store.mint_token(
                "acme", minted_by="alice", at=T0, expires_at=EXPIRY, pack="img-tools"
            )
            scoped_operator, _ = store.mint_token(
                "acme", minted_by="root", at=T0, expires_at=EXPIRY, pack="review-me"
            )
            owner_id = store.verify_token(owner_token, T0).token_id
            requests = (
                ("get", "/tokens", None),
                ("post", f"/tokens/{owner_id}/revoke", {"reason": "not yours"}),
                (
                    "post",
                    "/releases/img-tools/versions/1.0.0/yank",
                    {"reason": "not an owner"},
                ),
                (
                    "post",
                    "/reviews/review-me/versions/1.0.0/resolve",
                    {"decision": "rejected", "reason": "not an operator"},
                ),
            )
            for method, path, body in requests:
                resp = await client.request(method, path, json=body)
                assert resp.status == 401, path
                resp = await client.request(method, path, json=body, headers=bearer(member_token))
                assert resp.status == 403, path

            resp = await client.get("/tokens", headers=bearer(scoped_owner))
            assert resp.status == 403
            member_id = store.verify_token(member_token, T0).token_id
            resp = await client.post(
                f"/tokens/{member_id}/revoke",
                json={"reason": "too much authority"},
                headers=bearer(scoped_owner),
            )
            assert resp.status == 403
            resp = await client.post(
                "/reviews/review-me/versions/1.0.0/resolve",
                json={"decision": "accepted"},
                headers=bearer(scoped_operator),
            )
            assert resp.status == 403
            resp = await client.post(
                "/releases/img-tools/versions/1.0.0/yank",
                json={"reason": "matching scope remains valid"},
                headers=bearer(scoped_owner),
            )
            assert resp.status == 200
        finally:
            await client.close()

    asyncio.run(scenario())


def test_index_serves_accepted_releases_only(tmp_path: Path) -> None:
    """The index is what admission recorded: accepted releases appear,
    pending reviews and rejected attempts never do, and an empty registry
    answers an empty page, not an error."""

    async def scenario() -> None:
        client, store, _, _ = await make_client(tmp_path)
        try:
            resp = await client.get("/index/packs")
            assert resp.status == 200
            assert await resp.json() == {"packs": []}

            seed_release(store, "img-tools", "1.0.0")
            # Pending: first claim of a new name, left unresolved.
            pending = Submission(
                publisher="acme",
                pack_name="pending-pack",
                namespaces=(),
                version="1.0.0",
                artifact_digest=artifact_digest(b"pending"),
                evidence=DoctorEvidence(
                    pack_name="pending-pack",
                    ok=True,
                    node_types=("pending-pack.node",),
                    error_codes=(),
                ),
            )
            assert store.publish(pending, actor="alice", at=T0).state == "needs_review"

            resp = await client.get("/index/packs")
            body = await resp.json()
            assert [entry["pack"] for entry in body["packs"]] == ["img-tools"]
            assert "cursor" not in body

            resp = await client.get("/index/packs/pending-pack")
            assert resp.status == 404
        finally:
            await client.close()

    asyncio.run(scenario())


def test_index_pack_detail_orders_versions_semantically(tmp_path: Path) -> None:
    """10.0.0 outranks 2.0.0 - version ordering is parsed, never lexical -
    and the pack path segment canonicalizes like every other name."""

    async def scenario() -> None:
        client, store, _, _ = await make_client(tmp_path)
        try:
            seed_release(store, "img-tools", "1.0.0")
            seed_release(store, "img-tools", "2.0.0")
            seed_release(store, "img-tools", "10.0.0")

            resp = await client.get("/index/packs/Img_Tools")
            assert resp.status == 200
            body = await resp.json()
            assert body["pack"] == "img-tools"
            assert body["publisher"] == "acme"
            assert [r["version"] for r in body["releases"]] == ["10.0.0", "2.0.0", "1.0.0"]

            resp = await client.get("/index/packs")
            entry = (await resp.json())["packs"][0]
            assert entry["latestVersion"] == "10.0.0"
            assert entry["versions"] == 3
        finally:
            await client.close()

    asyncio.run(scenario())


def test_index_exact_release_is_lock_material_or_404(tmp_path: Path) -> None:
    """The resolution target for install pack@version: the exact record
    with digest/publisher/claims/nodeTypes, and an unknown version is a
    404 - never a substituted neighbor."""

    async def scenario() -> None:
        client, store, _, _ = await make_client(tmp_path)
        try:
            digest = seed_release(store, "img-tools", "1.0.0")
            seed_release(store, "img-tools", "2.0.0")

            resp = await client.get("/index/packs/img-tools/versions/1.0.0")
            assert resp.status == 200
            body = await resp.json()
            assert body == {
                "pack": "img-tools",
                "version": "1.0.0",
                "artifactDigest": digest,
                "publisher": "acme",
                "claims": ["img-tools"],
                "nodeTypes": ["img-tools.blur"],
                "templates": [],
            }

            for missing in (
                "/index/packs/img-tools/versions/3.0.0",
                "/index/packs/no-such-pack/versions/1.0.0",
            ):
                resp = await client.get(missing)
                assert resp.status == 404
        finally:
            await client.close()

    asyncio.run(scenario())


def test_index_query_searches_names_and_node_types(tmp_path: Path) -> None:
    """q matches pack-name substrings and probed node types, case-
    insensitively - the index searches provenance, not marketing text."""

    async def scenario() -> None:
        client, store, _, _ = await make_client(tmp_path)
        try:
            seed_release(store, "img-tools", "1.0.0", node_types=("img-tools.Blur",))
            seed_release(store, "audio-kit", "1.0.0", node_types=("audio-kit.Mix",))

            for query, expected in (
                ("IMG", ["img-tools"]),
                ("mix", ["audio-kit"]),
                ("kit", ["audio-kit"]),
                ("nothing-matches", []),
                ("", ["audio-kit", "img-tools"]),
            ):
                resp = await client.get("/index/packs", params={"q": query})
                body = await resp.json()
                assert [e["pack"] for e in body["packs"]] == expected, query
        finally:
            await client.close()

    asyncio.run(scenario())


def test_index_pagination_is_stable_and_query_bound(tmp_path: Path) -> None:
    """Keyset pages walk the corpus with no duplicates or omissions; a
    cursor replayed under a different query - or tampered bytes - is a
    loud 400, never a silently wrong page."""

    async def scenario() -> None:
        client, store, _, _ = await make_client(tmp_path)
        try:
            names = [f"pack-{index:02d}" for index in range(5)]
            for name in names:
                seed_release(store, name, "1.0.0")

            walked: list[str] = []
            cursor: str | None = None
            pages = 0
            while True:
                params = {"limit": "2"}
                if cursor is not None:
                    params["cursor"] = cursor
                resp = await client.get("/index/packs", params=params)
                assert resp.status == 200
                body = await resp.json()
                walked.extend(entry["pack"] for entry in body["packs"])
                pages += 1
                cursor = body.get("cursor")
                if cursor is None:
                    break
            assert walked == names
            assert pages == 3

            # A cursor minted for one query refuses to serve another.
            resp = await client.get("/index/packs", params={"limit": "2"})
            bound_cursor = (await resp.json())["cursor"]
            resp = await client.get("/index/packs", params={"q": "pack", "cursor": bound_cursor})
            assert resp.status == 400

            for bad in ("not-base64!", "AAAA", ""):
                if not bad:
                    continue
                resp = await client.get("/index/packs", params={"cursor": bad})
                assert resp.status == 400

            resp = await client.get("/index/packs", params={"limit": "abc"})
            assert resp.status == 400
        finally:
            await client.close()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Index: the remote template catalog
# ---------------------------------------------------------------------------


def template(
    template_id: str = "starter",
    *,
    data: bytes = b'{"nodes": []}',
    path: str = "templates/starter.json",
    description: str = "",
    tags: tuple[str, ...] = (),
    assets: tuple[str, ...] = (),
) -> ReleaseTemplate:
    return ReleaseTemplate(
        id=template_id,
        name=template_id.title(),
        digest="sha256:" + hashlib.sha256(data).hexdigest(),
        path=path,
        description=description,
        tags=tags,
        assets=assets,
    )


def test_index_templates_catalog_browses_latest_releases(tmp_path: Path) -> None:
    """The remote template catalog: one row per template of each pack's
    LATEST release, filtered query-first (q substring, tag exact, pack
    exact), descriptors in the same vocabulary the composed server's
    /api/templates speaks (no artifact path on the wire), keyset-paged
    with a cursor that binds the query that minted it."""

    async def scenario() -> None:
        client, store, _, _ = await make_client(tmp_path)
        try:
            resp = await client.get("/index/templates")
            assert await resp.json() == {"templates": []}

            old = template("legacy", data=b'{"v": 1}')
            new = template("starter", data=b'{"v": 2}', description="start here", tags=("video",))
            seed_release(store, "img-tools", "1.0.0", templates=(old,))
            seed_release(store, "img-tools", "1.1.0", templates=(new,))
            seed_release(
                store, "aud-tools", "1.0.0", templates=(template("mixdown", tags=("audio",)),)
            )

            resp = await client.get("/index/templates")
            rows = (await resp.json())["templates"]
            # Latest release only: img-tools 1.0.0's "legacy" is gone.
            assert [(row["pack"], row["id"]) for row in rows] == [
                ("aud-tools", "mixdown"),
                ("img-tools", "starter"),
            ]
            starter = rows[1]
            assert starter["version"] == "1.1.0"
            assert starter["description"] == "start here"
            assert starter["tags"] == ["video"]
            assert starter["digest"] == new.digest
            assert "path" not in starter  # the serving locator never rides the wire

            resp = await client.get("/index/templates", params={"q": "mix"})
            assert [row["id"] for row in (await resp.json())["templates"]] == ["mixdown"]
            resp = await client.get("/index/templates", params={"tag": "video"})
            assert [row["id"] for row in (await resp.json())["templates"]] == ["starter"]
            resp = await client.get("/index/templates", params={"pack": "img-tools"})
            assert [row["id"] for row in (await resp.json())["templates"]] == ["starter"]

            resp = await client.get("/index/templates", params={"limit": "1"})
            page1 = await resp.json()
            assert [row["id"] for row in page1["templates"]] == ["mixdown"]
            resp = await client.get(
                "/index/templates", params={"limit": "1", "cursor": page1["cursor"]}
            )
            page2 = await resp.json()
            assert [row["id"] for row in page2["templates"]] == ["starter"]
            assert "cursor" not in page2
            resp = await client.get(
                "/index/templates", params={"q": "mix", "cursor": page1["cursor"]}
            )
            assert resp.status == 400
        finally:
            await client.close()

    asyncio.run(scenario())


def test_release_template_body_serves_verified_artifact_bytes(tmp_path: Path) -> None:
    """Template bodies come out of the release's immutable artifact,
    verified against the digest the probe recorded, with the rendition
    caching contract (quoted digest ETag, If-None-Match -> 304, forever
    lifetime). Unknown releases and template ids are plain 404s; a
    descriptor the artifact bytes cannot honor is a loud 500, never
    silently wrong bytes."""

    async def scenario() -> None:
        client, store, vault, _ = await make_client(tmp_path)
        try:
            document = b'{"nodes": ["starter"]}'
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.writestr("dinkster-pack.toml", b"[pack]")
                archive.writestr("templates/starter.json", document)
            artifact = buffer.getvalue()
            vault.admit(artifact)
            liar = template("liar", data=b"other bytes", path="templates/starter.json")
            seed_release(
                store,
                "img-tools",
                "1.0.0",
                payload=artifact,
                templates=(template("starter", data=document), liar),
            )

            base = "/index/packs/img-tools/versions/1.0.0/templates"
            resp = await client.get(f"{base}/starter")
            assert resp.status == 200
            assert await resp.read() == document
            digest = "sha256:" + hashlib.sha256(document).hexdigest()
            assert resp.headers["ETag"] == f'"{digest}"'
            assert "immutable" in resp.headers["Cache-Control"]
            resp = await client.get(f"{base}/starter", headers={"If-None-Match": f'"{digest}"'})
            assert resp.status == 304

            resp = await client.get(f"{base}/nope")
            assert resp.status == 404
            resp = await client.get("/index/packs/img-tools/versions/9.9.9/templates/starter")
            assert resp.status == 404
            resp = await client.get("/index/packs/no-such/versions/1.0.0/templates/starter")
            assert resp.status == 404
            # The artifact cannot honor this descriptor's digest: refuse loudly.
            resp = await client.get(f"{base}/liar")
            assert resp.status == 500
        finally:
            await client.close()

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# Publish-probe isolation (DESIGN M8): the jail seam and the serve posture
# ---------------------------------------------------------------------------


def test_artifact_prober_passes_the_jail_into_diagnose(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The prober hands its ProbeJail straight to diagnose: the one stage
    that executes publisher code is the one that gets jailed, over the
    exact unpacked artifact bytes as before."""
    from dinkster_registry.artifact import build_artifact
    from dinkster_registry_sqlite.cli import artifact_prober
    from dinkster_workers import ProbeJail
    from dinkster_workers.doctor import diagnose as real_diagnose

    pack_dir = tmp_path / "pack"
    pack_dir.mkdir()
    (pack_dir / "dinkster-pack.toml").write_text(
        '[pack]\nname = "jailed-pack"\nnamespaces = ["jailed"]\n\n'
        '[pack.entry]\nnodes = "jailed_nodes:NODES"\n'
    )
    (pack_dir / "jailed_nodes.py").write_text("NODES = []\n")
    archive = tmp_path / "pack.zip"
    build_artifact(pack_dir, archive)

    jail = ProbeJail(bwrap="/fake/bwrap", user_namespaces=True)
    received: list[object] = []

    def spy(path: Path, *, probe_jail: object = None) -> object:
        received.append(probe_jail)
        return real_diagnose(path)  # real report, unjailed - wiring under test

    monkeypatch.setattr("dinkster_registry_sqlite.cli.diagnose", spy)
    result = artifact_prober(jail)(archive)
    assert received == [jail]
    assert result.pack_name == "jailed-pack"
    # and the default stays unjailed (lab posture), explicitly None
    received.clear()
    artifact_prober()(archive)
    assert received == [None]


def _serve_args(tmp_path: Path, probe_sandbox: str) -> argparse.Namespace:
    return argparse.Namespace(
        data=str(tmp_path / "data"),
        host="127.0.0.1",
        port=0,
        probe_sandbox=probe_sandbox,
    )


def test_serve_required_refuses_startup_when_jail_unavailable(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--probe-sandbox required either serves jailed or does not serve:
    detection failure is a startup refusal, before the store opens, never
    a silent unjailed fallback."""
    from dinkster_registry_sqlite import cli as registry_service
    from dinkster_workers import SandboxUnavailable

    def refuse() -> object:
        raise SandboxUnavailable("kernel blocks user namespaces")

    monkeypatch.setattr(registry_service, "detect_probe_jail", refuse)
    monkeypatch.setattr(
        registry_service,
        "_open",
        lambda args: pytest.fail("required-mode refusal must precede _open"),
    )
    monkeypatch.setattr(
        registry_service.web,
        "run_app",
        lambda *a, **k: pytest.fail("server must not start"),
    )
    with pytest.raises(SystemExit) as excinfo:
        registry_service._cmd_serve(_serve_args(tmp_path, "required"))
    assert excinfo.value.code == 1
    err = capsys.readouterr().err
    assert "refused" in err and "kernel blocks user namespaces" in err
    assert "--probe-sandbox off" in err  # the lab escape hatch is named


def test_serve_required_probes_through_the_detected_jail(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dinkster_registry_sqlite import cli as registry_service
    from dinkster_workers import ProbeJail

    jail = ProbeJail(bwrap="/fake/bwrap", user_namespaces=True)
    monkeypatch.setattr(registry_service, "detect_probe_jail", lambda: jail)
    received: list[object] = []

    def fake_prober(probe_jail: object = None) -> object:
        received.append(probe_jail)
        return lambda archive: pytest.fail("no publish in this test")

    monkeypatch.setattr(registry_service, "artifact_prober", fake_prober)
    monkeypatch.setattr(registry_service.web, "run_app", lambda *a, **k: None)
    registry_service._cmd_serve(_serve_args(tmp_path, "required"))
    assert received == [jail]
    assert "probe sandbox OFF" not in capsys.readouterr().err


def test_serve_off_warns_loudly_and_probes_unjailed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from dinkster_registry_sqlite import cli as registry_service

    monkeypatch.setattr(
        registry_service,
        "detect_probe_jail",
        lambda: pytest.fail("off mode must not touch detection"),
    )
    received: list[object] = []

    def fake_prober(probe_jail: object = None) -> object:
        received.append(probe_jail)
        return lambda archive: pytest.fail("no publish in this test")

    monkeypatch.setattr(registry_service, "artifact_prober", fake_prober)
    monkeypatch.setattr(registry_service.web, "run_app", lambda *a, **k: None)
    registry_service._cmd_serve(_serve_args(tmp_path, "off"))
    assert received == [None]
    err = capsys.readouterr().err
    assert "probe sandbox OFF" in err and "unjailed" in err


def test_serve_cli_defaults_to_required_with_off_as_explicit_opt_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The parser exposes exactly {required, off}, defaulting to the
    fail-closed jail while retaining an explicit lab-only opt-out."""
    import sys

    from dinkster_registry_sqlite import cli as registry_service

    captured: list[str] = []

    def capture(args: argparse.Namespace) -> None:
        captured.append(args.probe_sandbox)

    monkeypatch.setattr(registry_service, "_cmd_serve", capture)

    monkeypatch.setattr(sys, "argv", ["dinkster-registry", "--data", "unused", "serve"])
    registry_service.main()
    assert captured == ["required"]

    monkeypatch.setattr(
        sys,
        "argv",
        ["dinkster-registry", "--data", "unused", "serve", "--probe-sandbox", "off"],
    )
    registry_service.main()
    assert captured == ["required", "off"]

    monkeypatch.setattr(
        sys,
        "argv",
        ["dinkster-registry", "--data", "unused", "serve", "--probe-sandbox", "maybe"],
    )
    with pytest.raises(SystemExit):
        registry_service.main()


def test_registry_cli_lists_and_revokes_tokens(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys

    from dinkster_registry_sqlite import cli as registry_service

    data = tmp_path / "registry"
    store, token = store_with_token(data / "registry.db")
    record = store.verify_token(token, T0)
    store.close()

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dinkster-registry",
            "--data",
            str(data),
            "admin",
            "list-tokens",
            "acme",
            "--user",
            "alice",
        ],
    )
    registry_service.main()
    listing = capsys.readouterr().out
    assert record.token_id in listing
    assert "alice" in listing and "active" in listing

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "dinkster-registry",
            "--data",
            str(data),
            "admin",
            "revoke-token",
            record.token_id,
            "--user",
            "alice",
            "--reason",
            "rotation",
        ],
    )
    registry_service.main()
    assert capsys.readouterr().out == f"revoked token {record.token_id}\n"

    reopened = RegistryStore(data / "registry.db")
    with pytest.raises(RegistryError, match="revoked"):
        reopened.verify_token(token, T1)
    reopened.close()
