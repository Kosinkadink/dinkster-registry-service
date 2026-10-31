from __future__ import annotations

import io
import shutil
import subprocess
import sys
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID

import pytest
from dinkster_workers.sandbox import ProbeJail
from fastapi.testclient import TestClient
from sqlalchemy import func, select

import dinkster_registry_service.admission as admission_module
from dinkster_registry_service.admission import AdmissionService, quarantine_object_key
from dinkster_registry_service.admission_checks import (
    extracted_archive,
    run_doctor_static,
    run_executable_probe,
    run_fast_security,
    run_ingest_integrity,
    run_manifest_admission,
)
from dinkster_registry_service.app import create_app
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.database import (
    Database,
    NamespaceGrantRecord,
    OutboxRecord,
    PackRecord,
    ReleaseCandidateRecord,
    ReleaseDependencyRecord,
    ReleaseRecord,
    ReleaseScanRunRecord,
)
from dinkster_registry_service.digests import artifact_digest
from dinkster_registry_service.object_store import LocalFilesystemObjectStore, ObjectStoreError
from dinkster_registry_service.principals import PrincipalRepository
from dinkster_registry_service.seed import FIXTURE_ROOT, seed_fixtures
from dinkster_registry_service.settings import ServerSettings


def _fixture_source(tmp_path: Path, name: str = "example-pack") -> Path:
    source = tmp_path / name
    shutil.copytree(FIXTURE_ROOT / "example-pack", source)
    manifest_path = source / "dinkster-pack.toml"
    manifest = manifest_path.read_text()
    manifest = manifest.replace('name = "example-pack"', f'name = "{name}"')
    manifest = manifest.replace('namespaces = ["example"]', f'namespaces = ["{name}"]')
    manifest_path.write_text(manifest)
    nodes_path = source / "nodes.py"
    nodes_path.write_text(nodes_path.read_text().replace("example.", f"{name}."))
    return source


def _archive(tmp_path: Path, name: str = "example-pack") -> bytes:
    return build_registry_fixture_archive(_fixture_source(tmp_path, name))


def _service(
    database: Database,
    tmp_path: Path,
    *,
    worker_id: str = "test-worker",
    lease_seconds: int = 60,
    max_attempts: int = 3,
) -> AdmissionService:
    return AdmissionService(
        database,
        LocalFilesystemObjectStore(tmp_path / "objects"),
        settings=ServerSettings(scanner_max_attempts=max_attempts),
        worker_id=worker_id,
        lease_seconds=lease_seconds,
        require_isolation=False,
    )


def _client(database_url: str, object_root: Path) -> TestClient:
    return TestClient(
        create_app(
            ServerSettings(
                database_url=database_url,
                object_store_root=object_root,
                public_base_url="http://testserver",
                cursor_secret=b"admission-test-cursor-secret",
            )
        ),
        raise_server_exceptions=False,
    )


def _assert_rejected(service: AdmissionService, candidate_id: UUID, code: str) -> None:
    assert service.run_once()
    status = service.status(candidate_id)
    assert status.status == "rejected"
    assert any(finding.code == code and finding.effect == "block" for finding in status.findings)
    with service.database.session() as session:
        candidate = session.get(ReleaseCandidateRecord, candidate_id)
        assert candidate is not None and candidate.release_id is None


def test_mandatory_stage_functions_accept_the_registry_fixture(
    database: Database, tmp_path: Path
) -> None:
    archive = _archive(tmp_path)
    assert not run_ingest_integrity(archive, len(archive), artifact_digest(archive)).blocked
    with extracted_archive(archive) as root:
        with database.session() as session:
            manifest = run_manifest_admission(root, "example-pack", "1.2.3", session)
        doctor = run_doctor_static(root)
        probe = run_executable_probe(root, require_isolation=False)
    security = run_fast_security(archive)
    assert not manifest.blocked
    assert not doctor.blocked
    assert not probe.blocked
    assert probe.data is not None and len(probe.data["schemas"]) == 2
    assert not security.blocked


def test_isolated_probe_refuses_to_degrade_on_macos(tmp_path: Path) -> None:
    if sys.platform == "linux":
        pytest.skip("the container smoke test covers Linux isolation")
    source = _fixture_source(tmp_path)
    result = run_executable_probe(source, require_isolation=True)
    assert result.blocked
    assert result.findings[0].code == "probe.isolation-unavailable"


def test_probe_refuses_degraded_bubblewrap_jail(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        "dinkster_registry_service.admission_checks.detect_probe_jail",
        lambda: ProbeJail(bwrap="/usr/bin/true", user_namespaces=False),
    )
    result = run_executable_probe(_fixture_source(tmp_path), require_isolation=True)
    assert result.blocked
    assert result.findings[0].code == "probe.isolation-unavailable"
    assert result.operator_details == {"jail": "degraded"}


def test_configured_probe_timeout_is_honored(tmp_path: Path) -> None:
    source = _fixture_source(tmp_path)
    nodes = source / "nodes.py"
    nodes.write_text("import time\ntime.sleep(2)\n" + nodes.read_text())
    result = run_executable_probe(
        source,
        settings=ServerSettings(probe_timeout_seconds=1),
        require_isolation=False,
    )
    assert result.blocked
    assert result.findings[0].code == "probe.timeout"
    assert result.findings[0].message == "Executable probe exceeded 1s."


def test_probe_output_limit_blocks_without_buffering_unbounded_output(tmp_path: Path) -> None:
    source = _fixture_source(tmp_path)
    nodes = source / "nodes.py"
    nodes.write_text('import os\nos.write(1, b"x" * 4097)\n' + nodes.read_text())
    result = run_executable_probe(
        source,
        settings=ServerSettings(
            probe_output_limit_bytes=4096,
            probe_operator_tail_bytes=512,
        ),
        require_isolation=False,
    )
    assert result.blocked
    assert result.findings[0].code == "probe.output-limit"
    assert result.operator_details is not None
    assert result.operator_details["limitedStream"] == "stdout"
    assert len(result.operator_details["stdoutTail"]) <= 512


def test_configured_probe_operator_tail_is_honored(tmp_path: Path) -> None:
    source = _fixture_source(tmp_path)
    nodes = source / "nodes.py"
    nodes.write_text(
        'import os\nos.write(2, b"x" * 1024)\nraise RuntimeError("probe failure")\n'
        + nodes.read_text()
    )
    result = run_executable_probe(
        source,
        settings=ServerSettings(
            probe_output_limit_bytes=4096,
            probe_operator_tail_bytes=512,
        ),
        require_isolation=False,
    )
    assert result.blocked
    assert result.operator_details is not None
    assert result.operator_details["stderrTail"] == "x" * 512


def test_non_utf8_probe_stderr_becomes_block_finding(tmp_path: Path) -> None:
    source = _fixture_source(tmp_path)
    nodes = source / "nodes.py"
    nodes.write_text('import os\nos.write(2, b"\\xff")\n' + nodes.read_text())
    result = run_executable_probe(source, require_isolation=False)
    assert result.blocked
    assert result.findings[0].code == "probe.failed"
    assert result.operator_details is not None
    assert "\ufffd" in result.operator_details["stderrTail"]


def test_probe_output_is_operator_only_and_finding_is_sanitized(
    database: Database, tmp_path: Path
) -> None:
    source = _fixture_source(tmp_path)
    nodes = source / "nodes.py"
    nodes.write_text(
        "import os\n"
        'PROBE_ECHO = "ENV_ECHO:" + os.environ["PATH"]\n'
        "os.write(2, PROBE_ECHO.encode())\n"
        "raise RuntimeError(PROBE_ECHO)\n" + nodes.read_text()
    )
    service = _service(database, tmp_path)
    candidate_id = service.submit(
        build_registry_fixture_archive(source), pack_name="example-pack", version="1.2.3"
    )
    _assert_rejected(service, candidate_id, "probe.failed")
    status = service.status(candidate_id)
    assert all("ENV_ECHO" not in finding.message for finding in status.findings)
    with database.session() as session:
        run = session.scalar(
            select(ReleaseScanRunRecord).where(
                ReleaseScanRunRecord.candidate_id == candidate_id,
                ReleaseScanRunRecord.stage == "executable_probe",
            )
        )
        assert run is not None and run.operator_details is not None
        assert "ENV_ECHO" in run.operator_details["stderrTail"]


def test_accepted_probe_signal_cannot_publish_pack_output(
    database: Database, tmp_path: Path
) -> None:
    source = _fixture_source(tmp_path)
    nodes = source / "nodes.py"
    nodes.write_text('import os\nprint("ENV_ECHO:" + os.environ["PATH"])\n' + nodes.read_text())
    service = _service(database, tmp_path)
    candidate_id = service.submit(
        build_registry_fixture_archive(source), pack_name="example-pack", version="1.2.3"
    )
    assert service.run_once()
    status = service.status(candidate_id)
    assert status.status == "accepted"
    assert any(finding.code == "import.side-effect-output" for finding in status.findings)
    assert all("ENV_ECHO" not in finding.message for finding in status.findings)
    with database.session() as session:
        candidate_run = session.scalar(
            select(ReleaseScanRunRecord).where(
                ReleaseScanRunRecord.candidate_id == candidate_id,
                ReleaseScanRunRecord.stage == "executable_probe",
            )
        )
        assert candidate_run is not None and candidate_run.operator_details is not None
        assert "ENV_ECHO" in candidate_run.operator_details["stdoutTail"]
        public_runs = list(
            session.scalars(
                select(ReleaseScanRunRecord).where(
                    ReleaseScanRunRecord.release_id.is_not(None),
                    ReleaseScanRunRecord.accepted.is_(True),
                )
            )
        )
        assert public_runs
        assert all(run.operator_details is None for run in public_runs)


def test_probe_structured_failure_exposes_only_allowed_exception_type(tmp_path: Path) -> None:
    source = _fixture_source(tmp_path)
    nodes = source / "nodes.py"
    nodes.write_text(
        nodes.read_text().replace(
            "PACK_NODES = [Resize, Save]\n",
            "class ProbeNodes(list):\n"
            "    iterations = 0\n\n"
            "    def __iter__(self):\n"
            "        self.iterations += 1\n"
            "        if self.iterations == 2:\n"
            '            raise RuntimeError("ENV_ECHO:pack-controlled")\n'
            "        return super().__iter__()\n\n\n"
            "PACK_NODES = ProbeNodes([Resize, Save])\n",
        )
    )
    result = run_executable_probe(source, require_isolation=False)
    assert result.blocked
    assert result.findings[0].code == "probe.failed"
    assert result.findings[0].message == "Executable probe failed with RuntimeError."
    assert "ENV_ECHO" not in result.findings[0].message


def test_good_candidate_is_private_until_promoted_and_then_uses_catalog_reads(
    database: Database, database_url: str, tmp_path: Path
) -> None:
    service = _service(database, tmp_path)
    archive = _archive(tmp_path)
    candidate_id = service.submit(archive, pack_name="example-pack", version="1.2.3")
    with _client(database_url, tmp_path / "objects") as client:
        assert client.get("/v1/packs/example-pack").status_code == 404
        assert client.get("/v1/packs/example-pack/versions/1.2.3").status_code == 404
        assert client.get(f"/v1/artifacts/{artifact_digest(archive)}").status_code == 404
        assert service.status(candidate_id).status == "queued"

        assert service.run_once()

        status = service.status(candidate_id)
        assert status.status == "accepted"
        assert client.get("/v1/packs/example-pack").status_code == 200
        assert client.get("/v1/packs/example-pack/versions/1.2.3").status_code == 200
        schemas = client.get("/v1/packs/example-pack/versions/1.2.3/schemas")
        assert schemas.status_code == 200
        assert len(schemas.json()["schemas"]) == 2
        ticket = client.post("/v1/packs/example-pack/versions/1.2.3/download-tickets")
        assert ticket.status_code == 200
        assert client.get(ticket.json()["url"]).content == archive
        assert not (tmp_path / "objects" / quarantine_object_key(candidate_id)).exists()


def test_failed_object_promotion_is_retried_without_exposing_release(
    database: Database, database_url: str, tmp_path: Path
) -> None:
    class FailOnceObjectStore(LocalFilesystemObjectStore):
        fail_promotion = True

        def put(self, key: str, data: bytes) -> None:
            if self.fail_promotion and key.startswith("artifacts/"):
                self.fail_promotion = False
                raise ObjectStoreError("synthetic promotion failure")
            super().put(key, data)

    store = FailOnceObjectStore(tmp_path / "objects")
    service = AdmissionService(database, store, require_isolation=False)
    archive = _archive(tmp_path)
    candidate_id = service.submit(archive, pack_name="example-pack", version="1.2.3")

    assert service.run_once()
    status = service.status(candidate_id)
    assert (status.status, status.reason) == ("promoting", "artifact-promotion-retry")
    with _client(database_url, tmp_path / "objects") as client:
        assert client.get("/v1/packs/example-pack").status_code == 404
    with database.session() as session, session.begin():
        outbox = session.scalar(select(OutboxRecord))
        assert outbox is not None
        assert (outbox.state, outbox.attempts) == ("pending", 1)
        outbox.available_at = outbox.created_at

    assert service.run_once()
    assert service.status(candidate_id).status == "accepted"
    with _client(database_url, tmp_path / "objects") as client:
        assert client.get("/v1/packs/example-pack").status_code == 200


def test_tampered_object_rejects_on_digest_and_stays_private(
    database: Database, database_url: str, tmp_path: Path
) -> None:
    service = _service(database, tmp_path)
    archive = _archive(tmp_path)
    candidate_id = service.submit(archive, pack_name="example-pack", version="1.2.3")
    path = tmp_path / "objects" / quarantine_object_key(candidate_id)
    tampered = bytearray(path.read_bytes())
    tampered[len(tampered) // 2] ^= 1
    path.write_bytes(tampered)
    _assert_rejected(service, candidate_id, "integrity.digest-mismatch")
    with _client(database_url, tmp_path / "objects") as client:
        assert client.get("/v1/packs/example-pack").status_code == 404


def test_malformed_zip_rejects(database: Database, tmp_path: Path) -> None:
    service = _service(database, tmp_path)
    data = b"not a zip archive"
    candidate_id = service.submit(data, pack_name="broken-pack", version="1.0")
    _assert_rejected(service, candidate_id, "integrity.invalid-archive")


def test_path_traversal_entry_rejects(database: Database, tmp_path: Path) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, payload in (
            ("../escape.py", b"pass\n"),
            ("dinkster-pack.toml", b"[pack]\nname='unsafe-pack'\n"),
        ):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, payload)
    service = _service(database, tmp_path)
    candidate_id = service.submit(output.getvalue(), pack_name="unsafe-pack", version="1.0")
    _assert_rejected(service, candidate_id, "integrity.invalid-archive")


@pytest.mark.parametrize(
    ("submitted_name", "submitted_version", "accepted"),
    (("other-pack", "1.2.3", False), ("example-pack", "1.2.4", True)),
)
def test_manifest_name_matches_and_submission_owns_version(
    database: Database,
    tmp_path: Path,
    submitted_name: str,
    submitted_version: str,
    accepted: bool,
) -> None:
    service = _service(database, tmp_path)
    archive = _archive(tmp_path)
    candidate_id = service.submit(archive, pack_name=submitted_name, version=submitted_version)
    if accepted:
        assert service.run_once()
        assert service.status(candidate_id).status == "accepted"
        with database.session() as session:
            release = session.scalar(select(ReleaseRecord))
            assert release is not None and release.version == submitted_version
    else:
        _assert_rejected(service, candidate_id, "manifest.invalid")


@pytest.mark.parametrize("publisher", (None, "dinkster"))
def test_official_claims_require_registry_publisher_and_keep_exact_ids(
    database: Database, tmp_path: Path, publisher: str | None
) -> None:
    principals = PrincipalRepository(database)
    principals.register_user("operator")
    principals.register_publisher("dinkster", "operator", datetime.now(UTC).isoformat())
    source = _fixture_source(tmp_path, "official-pack")
    manifest = source / "dinkster-pack.toml"
    manifest.write_text(
        manifest.read_text().replace(
            'namespaces = ["official-pack"]',
            'namespaces = ["std", "ExampleResize", "ExampleSave"]',
        )
    )
    nodes = source / "nodes.py"
    nodes.write_text(
        nodes.read_text()
        .replace("official-pack.resize", "ExampleResize")
        .replace("official-pack.save", "ExampleSave")
    )
    service = _service(database, tmp_path)
    candidate_id = service.submit(
        build_registry_fixture_archive(source),
        pack_name="official-pack",
        version="2.0",
        publisher=publisher,
    )
    if publisher is None:
        _assert_rejected(service, candidate_id, "manifest.invalid")
    else:
        assert service.run_once()
        assert service.status(candidate_id).status == "accepted"
        with database.session() as session:
            assert set(session.scalars(select(NamespaceGrantRecord.claim))) == {
                "official-pack",
                "std",
                "ExampleResize",
                "ExampleSave",
            }


def test_node_outside_declared_namespace_rejects(database: Database, tmp_path: Path) -> None:
    source = _fixture_source(tmp_path)
    manifest = source / "dinkster-pack.toml"
    manifest.write_text(
        manifest.read_text().replace(
            'namespaces = ["example-pack"]', 'namespaces = ["example-pack.other"]'
        )
    )
    service = _service(database, tmp_path)
    candidate_id = service.submit(
        build_registry_fixture_archive(source), pack_name="example-pack", version="1.2.3"
    )
    _assert_rejected(service, candidate_id, "namespace.uncovered")


def test_duplicate_semantic_version_rejects(database: Database, tmp_path: Path) -> None:
    store = LocalFilesystemObjectStore(tmp_path / "objects")
    seed_fixtures(database, store)
    service = AdmissionService(database, store, require_isolation=False)
    archive = _archive(tmp_path)
    candidate_id = service.submit(archive, pack_name="example-pack", version="1.2.3.0")
    _assert_rejected(service, candidate_id, "manifest.invalid")
    with database.session() as session:
        assert session.scalar(select(func.count()).select_from(ReleaseRecord)) == 2


def test_active_dependency_is_validated_and_recorded(database: Database, tmp_path: Path) -> None:
    store = LocalFilesystemObjectStore(tmp_path / "objects")
    seed_fixtures(database, store)
    source = _fixture_source(tmp_path, "dependent-pack")
    manifest = source / "dinkster-pack.toml"
    manifest.write_text(manifest.read_text() + '\n[pack.dependencies]\nexample-pack = ">=1,<2"\n')
    service = AdmissionService(database, store, require_isolation=False)
    candidate_id = service.submit(
        build_registry_fixture_archive(source), pack_name="dependent-pack", version="1.2.3"
    )
    assert service.run_once()
    assert service.status(candidate_id).status == "accepted"
    with database.session() as session:
        release = session.scalar(
            select(ReleaseRecord)
            .join(PackRecord, PackRecord.id == ReleaseRecord.pack_id)
            .where(PackRecord.name == "dependent-pack")
        )
        assert release is not None
        dependency = session.scalar(
            select(ReleaseDependencyRecord).where(ReleaseDependencyRecord.release_id == release.id)
        )
        assert dependency is not None
        assert (dependency.pack_name, dependency.version_range) == ("example-pack", "<2,>=1")


def test_missing_dependency_rejects(database: Database, tmp_path: Path) -> None:
    source = _fixture_source(tmp_path, "dependent-pack")
    manifest = source / "dinkster-pack.toml"
    manifest.write_text(manifest.read_text() + '\n[pack.dependencies]\nmissing-pack = ">=1,<2"\n')
    service = _service(database, tmp_path)
    candidate_id = service.submit(
        build_registry_fixture_archive(source), pack_name="dependent-pack", version="1.2.3"
    )
    _assert_rejected(service, candidate_id, "manifest.invalid")


def test_doctor_error_rejects(database: Database, tmp_path: Path) -> None:
    source = _fixture_source(tmp_path, "doctor-error")
    nodes = source / "nodes.py"
    nodes.write_text("import dinkster_workers\n" + nodes.read_text())
    service = _service(database, tmp_path)
    candidate_id = service.submit(
        build_registry_fixture_archive(source), pack_name="doctor-error", version="1.2.3"
    )
    _assert_rejected(service, candidate_id, "imports.host-machinery")


def test_confirmed_secret_rejects(database: Database, tmp_path: Path) -> None:
    source = _fixture_source(tmp_path, "secret-pack")
    nodes = source / "nodes.py"
    fake_key = "AK" + "IA" + "1234567890ABCDEF"
    nodes.write_text(nodes.read_text() + f'\nFAKE_ACCESS_KEY = "{fake_key}"\n')
    service = _service(database, tmp_path)
    candidate_id = service.submit(
        build_registry_fixture_archive(source), pack_name="secret-pack", version="1.2.3"
    )
    _assert_rejected(service, candidate_id, "security.confirmed-secret")


def test_ambiguous_native_file_waits_for_operator_review(
    database: Database, database_url: str, tmp_path: Path
) -> None:
    source = _fixture_source(tmp_path, "native-pack")
    (source / "extension.so").write_bytes(b"synthetic native inventory fixture")
    service = _service(database, tmp_path)
    candidate_id = service.submit(
        build_registry_fixture_archive(source), pack_name="native-pack", version="1.2.3"
    )
    assert service.run_once()
    status = service.status(candidate_id)
    assert status.status == "review"
    assert any(
        finding.code == "security.native-binary" and finding.effect == "review"
        for finding in status.findings
    )
    with database.session() as session:
        assert session.scalar(select(func.count()).select_from(ReleaseRecord)) == 0
    with _client(database_url, tmp_path / "objects") as client:
        assert client.get("/v1/packs/native-pack").status_code == 404


def test_nested_archive_waits_for_operator_review(database: Database, tmp_path: Path) -> None:
    nested = io.BytesIO()
    with zipfile.ZipFile(nested, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("native.so", b"\x7fELF synthetic nested executable")
    source = _fixture_source(tmp_path, "nested-pack")
    (source / "payload.bin").write_bytes(nested.getvalue())
    service = _service(database, tmp_path)
    candidate_id = service.submit(
        build_registry_fixture_archive(source), pack_name="nested-pack", version="1.2.3"
    )
    assert service.run_once()
    status = service.status(candidate_id)
    assert status.status == "review"
    assert any(
        finding.code == "security.nested-archive" and finding.effect == "review"
        for finding in status.findings
    )


def test_unexpected_scanner_exception_becomes_block_finding(
    monkeypatch: pytest.MonkeyPatch, database: Database, tmp_path: Path
) -> None:
    service = _service(database, tmp_path)
    candidate_id = service.submit(_archive(tmp_path), pack_name="example-pack", version="1.2.3")

    def fail_integrity(data: bytes, declared_size: int, declared_digest: str) -> None:
        raise RuntimeError("pack-controlled detail")

    monkeypatch.setattr(admission_module, "run_ingest_integrity", fail_integrity)
    assert service.run_once()
    status = service.status(candidate_id)
    assert (status.status, status.reason) == ("rejected", "scanner.unexpected-error")
    assert all("pack-controlled" not in finding.message for finding in status.findings)


def test_configured_candidate_claim_limit_is_honored(database: Database, tmp_path: Path) -> None:
    service = _service(database, tmp_path, lease_seconds=60, max_attempts=1)
    candidate_id = service.submit(_archive(tmp_path), pack_name="example-pack", version="1.2.3")
    first = service.claim()
    assert first is not None and first.attempt == 1
    with database.session() as session, session.begin():
        candidate = session.get(ReleaseCandidateRecord, candidate_id)
        assert candidate is not None
        candidate.lease_expires_at = datetime.now(UTC) - timedelta(seconds=1)

    assert service.claim() is None
    status = service.status(candidate_id)
    assert (status.status, status.reason, status.attempts) == (
        "rejected",
        "scanner.attempt-limit",
        1,
    )
    assert any(finding.code == "scanner.attempt-limit" for finding in status.findings)


def test_expired_lease_is_taken_over_after_scanner_sigkill(
    database: Database, database_url: str, tmp_path: Path
) -> None:
    service = _service(database, tmp_path, lease_seconds=1)
    source = _fixture_source(tmp_path, "lease-pack")
    nodes = source / "nodes.py"
    nodes.write_text(nodes.read_text().replace("from dinkster_api.v1", "from dinkster_schema"))
    archive = build_registry_fixture_archive(source)
    candidate_id = service.submit(archive, pack_name="lease-pack", version="1.2.3")
    object_root = str(tmp_path / "objects")
    code = f"""
import time
import dinkster_registry_service.admission as admission
from dinkster_registry_service.database import Database
from dinkster_registry_service.object_store import LocalFilesystemObjectStore

def wait_probe(root, *, settings=None, require_isolation=True):
    time.sleep(30)
    raise AssertionError("scanner should have been killed")

admission.run_executable_probe = wait_probe
database = Database({database_url!r})
service = admission.AdmissionService(
    database,
    LocalFilesystemObjectStore(__import__('pathlib').Path({object_root!r})),
    worker_id='killed-worker',
    lease_seconds=1,
    require_isolation=False,
)
service.run_once()
"""
    process = subprocess.Popen([sys.executable, "-c", code])
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with database.session() as session:
            doctor_runs = session.scalar(
                select(func.count())
                .select_from(ReleaseScanRunRecord)
                .where(
                    ReleaseScanRunRecord.candidate_id == candidate_id,
                    ReleaseScanRunRecord.stage == "doctor_static",
                    ReleaseScanRunRecord.attempt == 1,
                )
            )
        if doctor_runs == 1:
            break
        time.sleep(0.02)
    else:
        process.kill()
        process.wait()
        pytest.fail("first scanner did not persist doctor evidence")
    process.kill()
    assert process.wait(timeout=5) < 0
    time.sleep(1.1)

    assert service.run_once()
    status = service.status(candidate_id)
    assert status.status == "accepted"
    assert sum(finding.code == "imports.internal-module" for finding in status.findings) == 2
    with database.session() as session:
        assert (
            session.scalar(
                select(func.count())
                .select_from(ReleaseRecord)
                .where(ReleaseRecord.version == "1.2.3")
            )
            == 1
        )
        attempts = set(
            session.scalars(
                select(ReleaseScanRunRecord.attempt).where(
                    ReleaseScanRunRecord.candidate_id == candidate_id
                )
            )
        )
        assert attempts == {1, 2}
        assert session.scalar(select(func.count()).select_from(OutboxRecord)) == 1
        candidate = session.get(ReleaseCandidateRecord, candidate_id)
        assert candidate is not None and candidate.release_id is not None


def test_two_workers_promote_ten_candidates_without_duplicates(
    database: Database, tmp_path: Path
) -> None:
    service = _service(database, tmp_path)
    candidate_ids = [
        service.submit(
            _archive(tmp_path, f"concurrent-{index}"),
            pack_name=f"concurrent-{index}",
            version="1.2.3",
        )
        for index in range(10)
    ]

    def work(worker_id: str) -> None:
        worker = _service(database, tmp_path, worker_id=worker_id)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            worker.run_once()
            with database.session() as session:
                terminal = session.scalar(
                    select(func.count())
                    .select_from(ReleaseCandidateRecord)
                    .where(
                        ReleaseCandidateRecord.id.in_(candidate_ids),
                        ReleaseCandidateRecord.status == "accepted",
                    )
                )
            if terminal == 10:
                return
            time.sleep(0.01)
        raise AssertionError("concurrent scanners did not finish")

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(work, f"worker-{index}") for index in range(2)]
        for future in futures:
            future.result()

    with database.session() as session:
        assert session.scalar(select(func.count()).select_from(ReleaseRecord)) == 10
        assert session.scalar(select(func.count()).select_from(OutboxRecord)) == 10
        assert (
            session.scalar(
                select(func.count(func.distinct(ReleaseRecord.pack_id))).select_from(ReleaseRecord)
            )
            == 10
        )


def test_rescan_records_new_evidence_without_changing_bytes(
    database: Database, tmp_path: Path
) -> None:
    service = _service(database, tmp_path)
    archive = _archive(tmp_path)
    candidate_id = service.submit(archive, pack_name="example-pack", version="1.2.3")
    assert service.run_once()
    assert service.status(candidate_id).status == "accepted"
    rescan_id = service.schedule_rescan("example-pack", "1.2.3")
    assert service.run_once()
    assert service.status(rescan_id).status == "accepted"
    with database.session() as session:
        release = session.scalar(select(ReleaseRecord))
        assert release is not None
        assert release.artifact_digest == artifact_digest(archive)
        assert release.next_scan_at is not None
        assert (
            session.scalar(
                select(func.count())
                .select_from(ReleaseScanRunRecord)
                .where(ReleaseScanRunRecord.release_id == release.id)
            )
            == 2
        )


def _assert_reviewed_rescan_decision(
    database: Database,
    database_url: str,
    tmp_path: Path,
    *,
    accepted: bool,
) -> None:
    nested = io.BytesIO()
    with zipfile.ZipFile(nested, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("native.so", b"\x7fELF synthetic nested executable")
    source = _fixture_source(tmp_path, "reviewed-rescan-pack")
    (source / "payload.bin").write_bytes(nested.getvalue())
    service = _service(database, tmp_path)
    candidate_id = service.submit(
        build_registry_fixture_archive(source),
        pack_name="reviewed-rescan-pack",
        version="1.2.3",
    )
    assert service.run_once()
    assert service.status(candidate_id).status == "review"
    assert (
        service.resolve_review(
            candidate_id,
            accepted=True,
            actor="operator",
            reason="initial artifact reviewed",
        ).status
        == "accepted"
    )

    rescan_id = service.schedule_rescan("reviewed-rescan-pack", "1.2.3")
    assert service.run_once()
    assert service.status(rescan_id).status == "review"
    status = service.resolve_review(
        rescan_id,
        accepted=accepted,
        actor="operator",
        reason="rescan reviewed",
    )

    assert status.status == ("accepted" if accepted else "rejected")
    assert status.reason == (None if accepted else "rescan reviewed")
    assert all(finding.code != "manifest.version-conflict" for finding in status.findings)
    with database.session() as session:
        release = session.scalar(select(ReleaseRecord))
        assert release is not None
        assert release.state == ("active" if accepted else "quarantined")
        assert release.state_reason == (None if accepted else "rescan reviewed")
        assert session.scalar(select(func.count()).select_from(OutboxRecord)) == 1
    with _client(database_url, tmp_path / "objects") as client:
        response = client.get("/v1/packs/reviewed-rescan-pack")
        assert response.status_code == (200 if accepted else 404)


@pytest.mark.parametrize("accepted", (True, False), ids=("accept", "reject"))
def test_postgresql_reviewed_rescan_decision_controls_release_visibility(
    database: Database,
    database_url: str,
    tmp_path: Path,
    accepted: bool,
) -> None:
    _assert_reviewed_rescan_decision(database, database_url, tmp_path, accepted=accepted)


@pytest.mark.parametrize("accepted", (True, False), ids=("accept", "reject"))
def test_sqlite_reviewed_rescan_decision_controls_release_visibility(
    tmp_path: Path, accepted: bool
) -> None:
    database_url = f"sqlite:///{tmp_path / 'registry.db'}"
    database = Database(database_url)
    try:
        _assert_reviewed_rescan_decision(database, database_url, tmp_path, accepted=accepted)
    finally:
        database.dispose()
