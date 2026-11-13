from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from dinkster_registry.archive_admission import StageResult
from fastapi import FastAPI
from runtime_fixture import RuntimeFixture

import dinkster_registry_service.scanner_worker as scanner_worker
from dinkster_registry_service.admission import AdmissionService, CandidateClaim
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.database import Database
from dinkster_registry_service.digests import artifact_digest
from dinkster_registry_service.principals import PrincipalRepository
from dinkster_registry_service.scan_control import scanner_router
from dinkster_registry_service.scan_execution import run_prepared_probe
from dinkster_registry_service.seed import FIXTURE_ROOT


def test_worker_runs_locked_probe_over_http_and_delivery_never_claims(
    tmp_path: Path, runtime: RuntimeFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    token = "disposable-worker-capability"
    settings = runtime.settings(tmp_path, database_url=f"sqlite:///{tmp_path / 'catalog.db'}")
    database = Database(settings.database_url)
    service = AdmissionService(
        database, settings.create_object_store(), settings=settings, lease_seconds=3
    )
    principals = PrincipalRepository(database)
    principals.register_user("operator")
    principals.register_publisher("dinkster", "operator", "2026-11-12T00:00:00Z")
    archive = build_registry_fixture_archive(FIXTURE_ROOT / "example-pack")
    locks = {
        variant: {
            "baseId": runtime.base_ids[variant],
            "artifactDigest": artifact_digest(archive),
            "lock": {
                "format": "dinkster.pack-lock/1",
                "pack": "example-pack",
                "variant": variant,
                "requiresPython": ">=3.12",
                "requirements": [],
                "indexes": [],
                "packages": [],
            },
        }
        for variant in ("linux-cpu", "win-cpu")
    }
    candidate_id = service.submit(
        archive,
        pack_name="example-pack",
        version="1.2.3",
        publisher="dinkster",
        locks=json.dumps(locks).encode(),
    )
    assert not service.deliver_once()
    assert service.status(candidate_id).status == "queued"
    assert service.status(candidate_id).attempts == 0

    def no_web_probe(*args: object, **kwargs: object) -> StageResult:
        raise AssertionError("Web delivery must never execute submitted code")

    monkeypatch.setattr(AdmissionService, "_probe_with_dependencies", no_web_probe)
    app = FastAPI()
    app.include_router(scanner_router(service, hashlib.sha256(token.encode()).hexdigest()))
    renewed = threading.Event()
    leased_claim = service.leased_claim

    def renew(candidate: Any, lease: Any, *, renew: bool = False) -> CandidateClaim:
        result = leased_claim(candidate, lease, renew=renew)
        if renew:
            renewed.set()
        return result

    monkeypatch.setattr(service, "leased_claim", renew)

    def probe(*args: Any, **kwargs: Any) -> StageResult:
        assert renewed.wait(10), "worker did not renew during execution"
        # Container tests cover the full jail; host tests use the real probe without it.
        return run_prepared_probe(*args, **{**kwargs, "require_isolation": False})

    monkeypatch.setattr(scanner_worker, "run_prepared_probe", probe)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        origin = f"http://127.0.0.1:{listener.getsockname()[1]}"
        server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]}, daemon=True)
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while not server.started:
                assert thread.is_alive() and time.monotonic() < deadline
                time.sleep(0.01)
            worker = scanner_worker.ScannerWorker(
                origin,
                token,
                tmp_path / "worker-runtime",
                development=True,
                development_runtime=runtime.mirror,
            )
            assert worker.run_once()
            assert not worker.run_once()
            assert service.status(candidate_id).status == "accepted", service.status(candidate_id)
            assert service.status(candidate_id).attempts == 1
            while service.deliver_once():
                assert time.monotonic() < deadline + 30
            assert service.object_store.exists("static/packs/index.json")
            index = json.loads(service.object_store.read("static/packs/index.json"))
            assert any(item["name"] == "example-pack" for item in index["items"])
            rescan_id = service.schedule_rescan("example-pack", "1.2.3")
            assert worker.run_once()
            assert service.status(rescan_id).status == "accepted"
            broken = tmp_path / "broken-pack"
            shutil.copytree(FIXTURE_ROOT / "example-pack", broken)
            (broken / "nodes.py").unlink()
            manifest_path = broken / "dinkster-pack.toml"
            manifest_path.write_text(
                manifest_path.read_text().replace("[pack]\n", '[pack]\nversion = "1.2.4"\n')
            )
            rejected_id = service.submit(
                build_registry_fixture_archive(broken),
                pack_name="example-pack",
                version="1.2.4",
                publisher="dinkster",
            )
            assert worker.run_once()
            assert service.status(rejected_id).status == "rejected", service.status(rejected_id)
            assert not worker.run_once()
        finally:
            server.should_exit = True
            thread.join(timeout=10)
            assert not thread.is_alive()
            database.dispose()


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.com",
        "https://name:secret@example.com",
        "https://example.com/path",
        "https://example.com?key=value",
    ],
)
def test_worker_does_not_send_capabilities_to_unsafe_origins(tmp_path: Path, origin: str) -> None:
    with pytest.raises(ValueError):
        scanner_worker.ScannerWorker(origin, "test-capability", tmp_path)


@pytest.mark.parametrize("failure", ["isolation", "authority"])
def test_scanner_entrypoint_fails_before_claiming_without_isolation_or_with_authority(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    class UnavailableJail:
        user_namespaces = failure == "authority"

    constructed = []

    def worker(*args: object, **kwargs: object) -> None:
        constructed.append(True)
        raise AssertionError("Worker must not be constructed after a failed preflight")

    monkeypatch.setattr(scanner_worker, "ScannerWorker", worker)
    monkeypatch.setattr(scanner_worker, "detect_probe_jail", UnavailableJail)
    monkeypatch.setattr(sys, "argv", ["dinkster-scanner"])
    for name in tuple(os.environ):
        monkeypatch.delenv(name)
    if failure == "authority":
        monkeypatch.setenv("DINKSTER_DATABASE_URL", "nonsecret-test-sentinel")
    with pytest.raises(SystemExit) as exc:
        scanner_worker.main()
    assert "assignment will recover" in str(exc.value)
    assert "nonsecret-test-sentinel" not in str(exc.value)
    assert not constructed


def test_worker_never_follows_a_control_plane_redirect(tmp_path: Path) -> None:
    reached = []

    class Redirect(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            reached.append(self.path)
            self.send_response(307 if self.path.endswith("/claim") else 204)
            self.send_header("Location", "/credential-sink")
            self.end_headers()

        def log_message(self, *args: object) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        worker = scanner_worker.ScannerWorker(
            f"http://127.0.0.1:{server.server_port}",
            "disposable-capability",
            tmp_path,
            development=True,
        )
        with pytest.raises(scanner_worker.ScannerUnavailable, match="HTTP 307"):
            worker.run_once()
        assert reached == ["/internal/scanner/claim"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
