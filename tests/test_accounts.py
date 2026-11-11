import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import httpx
import pytest
from dinkster_token_verifier import TokenVerifier
from fastapi.testclient import TestClient
from joserfc import jwt
from joserfc.jwk import OKPKey
from sqlalchemy import select

from dinkster_registry_service import accounts
from dinkster_registry_service.admission import AdmissionService
from dinkster_registry_service.app import create_app
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.database import PublisherBindingRecord, PublisherTokenRecord
from dinkster_registry_service.object_store import LocalFilesystemObjectStore
from dinkster_registry_service.seed import FIXTURE_ROOT
from dinkster_registry_service.settings import ServerSettings


@pytest.mark.parametrize("backend", ["sqlite", "postgresql"])
def test_human_identity_claims_mints_and_revokes_without_operator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest, backend: str
) -> None:
    key = OKPKey.generate_key("Ed25519", auto_kid=True)
    jwk = {**key.as_dict(private=False), "alg": "Ed25519", "use": "sig"}
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"keys": [jwk]}))
    )
    verifier = TokenVerifier(
        issuer="https://id.example",
        audience="dinkster-registry",
        jwks_url="https://id.example/.well-known/jwks.json",
        client=client,
    )
    monkeypatch.setattr(accounts, "TokenVerifier", lambda **kwargs: verifier)
    if backend == "postgresql":
        request.getfixturevalue("database")
        database_url = request.getfixturevalue("database_url")
    else:
        database_url = f"sqlite:///{tmp_path / 'registry.db'}"
    app = create_app(
        ServerSettings(
            database_url=database_url,
            object_store_root=tmp_path / "objects",
            identity_issuer="https://id.example",
        )
    )
    alice, bob, project = (uuid4() for _ in range(3))

    def credential(user: object, name: str, **overrides: Any) -> dict[str, str]:
        now = int(datetime.now(UTC).timestamp())
        claims = {
            "iss": "https://id.example",
            "aud": "dinkster-registry",
            "sub": f"u_{user}",
            "kind": "human",
            "org": None,
            "acct": str(user),
            "key": None,
            "key_scopes": None,
            "grants": {f"project:{project}": ["registry:manage", f"registry:publisher:{name}"]},
            "iat": now,
            "exp": now + 60,
            "jti": str(uuid4()),
            **overrides,
        }
        token = jwt.encode({"alg": "Ed25519", "kid": key.kid}, claims, key, algorithms=["Ed25519"])
        return {"Authorization": f"Bearer {token}", "Origin": "https://id.example"}

    with TestClient(app) as browser:
        alice_headers = credential(alice, "alice")
        bob_headers = credential(bob, "bob")
        path = "/v1/account"
        assert browser.post(f"{path}/publisher").status_code == 401
        assert (
            browser.post(
                f"{path}/publisher", headers=credential(alice, "alice", aud="unrelated-service")
            ).status_code
            == 401
        )
        assert (
            browser.post(
                f"{path}/publisher",
                headers=credential(
                    alice, "alice", grants={f"project:{project}": ["settings:write"]}
                ),
            ).status_code
            == 403
        )
        assert browser.post(f"{path}/publisher", headers=alice_headers).json() == {
            "publisher": "alice"
        }
        assert (
            browser.post(f"{path}/publisher", headers=credential(bob, "alice")).status_code == 409
        )
        assert (
            browser.post(f"{path}/publisher", headers=credential(bob, "dinkster")).status_code
            == 409
        )
        assert browser.post(f"{path}/publisher", headers=bob_headers).status_code == 201
        expires = (datetime.now(UTC) + timedelta(days=2)).isoformat()
        for expiry in (
            "2000-01-01T00:00:00Z",
            (datetime.now(UTC) + timedelta(days=91)).isoformat(),
        ):
            assert (
                browser.post(
                    f"{path}/tokens", headers=alice_headers, json={"expires_at": expiry}
                ).status_code
                == 400
            )
        created = browser.post(
            f"{path}/tokens",
            headers=alice_headers,
            json={"expires_at": expires, "pack": "alice-pack"},
        )
        assert created.status_code == 201, created.text
        data = created.json()
        secret, token_id = data["secret"], data["id"]
        assert created.headers["cache-control"] == "no-store"
        listed = browser.get(f"{path}/tokens", headers=alice_headers)
        assert secret not in listed.text and "secret_hash" not in listed.text
        assert listed.json()["tokens"][0]["pack"] == "alice-pack"
        publish_headers = {"Authorization": f"Bearer {secret}"}
        source = tmp_path / "alice-pack"
        shutil.copytree(FIXTURE_ROOT / "example-pack", source)
        manifest = source / "dinkster-pack.toml"
        manifest.write_text(
            manifest.read_text()
            .replace('publisher = "dinkster"', 'publisher = "alice"')
            .replace('name = "example-pack"', 'name = "alice-pack"')
            .replace('namespaces = ["example"]', 'namespaces = ["alice-pack"]')
        )
        nodes = source / "nodes.py"
        nodes.write_text(nodes.read_text().replace("example.", "alice-pack."))
        submitted = browser.post(
            "/v1/publish/alice-pack/versions/1.2.3",
            content=build_registry_fixture_archive(source),
            headers=publish_headers,
        )
        assert submitted.status_code == 202, submitted.text
        scanner = AdmissionService(
            app.state.database,
            LocalFilesystemObjectStore(tmp_path / "objects"),
            require_isolation=False,
        )
        assert scanner.run_once()
        assert scanner.status(UUID(submitted.json()["candidateId"])).status == "accepted"
        published = browser.get("/v1/packs/alice-pack/versions/1.2.3")
        assert published.status_code == 200 and published.json()["state"] == "active"
        assert browser.get("/v1/tokens", headers=publish_headers).status_code == 404
        assert (
            browser.post(
                f"/v1/tokens/{token_id}/revoke",
                headers=publish_headers,
                json={"reason": "publish token is not an account session"},
            ).status_code
            == 404
        )
        assert (
            browser.post(
                f"{path}/tokens", headers=publish_headers, json={"expires_at": expires}
            ).status_code
            == 401
        )
        assert (
            browser.post(
                "/v1/publish/other-pack/versions/1.0",
                headers=publish_headers,
                content=b"not reached",
            ).status_code
            == 403
        )
        revoke_path = f"{path}/tokens/{token_id}/revoke"
        assert (
            browser.post(
                revoke_path, headers=bob_headers, json={"reason": "not my token"}
            ).status_code
            == 403
        )
        assert (
            browser.post(revoke_path, headers=alice_headers, json={"reason": "rotate"}).status_code
            == 200
        )
        assert (
            browser.post(
                "/v1/publish/alice-pack/versions/1.0",
                headers=publish_headers,
                content=b"not reached",
            ).status_code
            == 401
        )
        assert (
            browser.options(
                f"{path}/tokens",
                headers={"Origin": "https://id.example", "Access-Control-Request-Method": "POST"},
            ).headers["access-control-allow-origin"]
            == "https://id.example"
        )
        assert (
            browser.get(
                f"{path}/tokens", headers={**alice_headers, "Origin": "https://attacker.example"}
            ).status_code
            == 403
        )
        with app.state.database.session() as session:
            binding = session.get(PublisherBindingRecord, "alice")
            assert binding is not None and binding.identity_subject == f"u_{alice}"
            stored = session.scalar(select(PublisherTokenRecord))
            assert stored is not None and stored.revoked and stored.secret_hash != secret
