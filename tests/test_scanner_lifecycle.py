from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event
from typing import Any

import pytest
from sqlalchemy import select

import dinkster_registry_service.scanner_lifecycle as lifecycle
from dinkster_registry_service.admission import AdmissionService
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.database import AuditEventRecord, Database, ReleaseCandidateRecord
from dinkster_registry_service.scanner_lifecycle import (
    MachineUnavailable,
    ScannerLifecycle,
    ScannerMachines,
)
from dinkster_registry_service.seed import FIXTURE_ROOT
from dinkster_registry_service.settings import ServerSettings


class Machines(ScannerMachines):
    def __init__(self, database: Database) -> None:
        self.app = "disposable-scanners"
        self.database = database
        self.states = {"a" * 14: "stopped", "b" * 14: "stopped"}
        self.started: list[str] = []
        self.entered = Event()
        self.release = Event()
        self.block = False
        self.lost_response = False
        self.restart = "no"

    def list(self) -> list[dict[str, Any]]:
        return [
            {
                "id": key,
                "state": value,
                "config": {
                    "restart": {"policy": self.restart},
                    "init": {"exec": ["dinkster-scanner"]},
                },
            }
            for key, value in self.states.items()
        ]

    def start(self, machine_id: str) -> None:
        with self.database.session() as session:
            assert (
                session.scalar(
                    select(AuditEventRecord.id).where(AuditEventRecord.subject_id == machine_id)
                )
                is not None
            ), "start intent must be committed before calling the provider"
        self.started.append(machine_id)
        self.entered.set()
        if self.block:
            assert self.release.wait(10)
        if self.lost_response:
            raise MachineUnavailable("Simulated lost provider response")
        self.states[machine_id] = "starting"


@pytest.mark.parametrize("backend", ["postgresql", "sqlite"])
def test_replicas_reserve_starts_and_recover_lost_response_and_idle_exit(
    database: Database, tmp_path: Path, backend: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    if backend == "sqlite":
        database = Database(f"sqlite:///{tmp_path / 'queue.db'}")
    settings = ServerSettings(
        database_url=str(database.engine.url.render_as_string(hide_password=False)),
        object_store_root=tmp_path / "objects",
    )
    service = AdmissionService(database, settings.create_object_store(), settings=settings)
    machines = Machines(database)
    owners = [ScannerLifecycle(database, machines, tuple(machines.states), 1) for _ in range(2)]
    assert owners[0].reconcile() == 0
    archive = build_registry_fixture_archive(FIXTURE_ROOT / "example-pack")
    candidate_id = service.submit(archive, pack_name="example-pack", version="1.2.3")
    machines.block = True
    machines.lost_response = True
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(owners[0].reconcile)
        try:
            assert machines.entered.wait(10)
            assert executor.submit(owners[1].reconcile).result(timeout=10) == 0
        finally:
            machines.release.set()
        assert first.result(timeout=10) == 0
    assert machines.started == ["a" * 14]
    assert service.status(candidate_id).status == "queued"
    assert service.status(candidate_id).attempts == 0
    assert owners[1].reconcile() == 0
    machines.block = False
    machines.lost_response = False
    now = datetime.now(UTC)

    class Clock:
        @staticmethod
        def now(tz: object) -> datetime:
            return now + timedelta(seconds=121)

    monkeypatch.setattr(lifecycle, "datetime", Clock)
    assert owners[1].reconcile() == 1
    assert machines.started == ["a" * 14, "a" * 14]
    assert owners[0].reconcile() == 0
    claimed = service.claim()
    assert claimed is not None
    with database.session() as session, session.begin():
        candidate = session.get(ReleaseCandidateRecord, candidate_id)
        assert candidate is not None
        candidate.lease_expires_at = now + timedelta(seconds=6000)
    machines.states["a" * 14] = "stopped"
    assert owners[0].reconcile() == 0
    with database.session() as session, session.begin():
        candidate = session.get(ReleaseCandidateRecord, candidate_id)
        assert candidate is not None
        candidate.lease_expires_at = now - timedelta(seconds=1)
    now += timedelta(seconds=121)
    assert owners[0].reconcile() == 1
    recovered = service.claim()
    assert recovered is not None and recovered.lease_token != claimed.lease_token
    assert service.status(candidate_id).status == "scanning"
    assert service.status(candidate_id).attempts == 2
    assert set(machines.started) == {"a" * 14}, (
        "a stale caller cannot start a different pool member"
    )


@pytest.mark.parametrize("invalid", ["restart", "missing", "unregistered-running"])
def test_pool_mismatch_and_running_unregistered_machines_do_not_start_more(
    tmp_path: Path, invalid: str
) -> None:
    settings = ServerSettings(
        database_url=f"sqlite:///{tmp_path / 'queue.db'}", object_store_root=tmp_path / "objects"
    )
    database = Database(settings.database_url)
    service = AdmissionService(database, settings.create_object_store(), settings=settings)
    service.submit(
        build_registry_fixture_archive(FIXTURE_ROOT / "example-pack"),
        pack_name="example-pack",
        version="1.2.3",
    )
    machines = Machines(database)
    if invalid == "restart":
        machines.restart = "always"
    elif invalid == "missing":
        del machines.states["a" * 14]
    else:
        machines.states["c" * 14] = "started"
    owner = ScannerLifecycle(database, machines, ("a" * 14,), 1)
    if invalid == "unregistered-running":
        assert owner.reconcile() == 0
    else:
        with pytest.raises(MachineUnavailable):
            owner.reconcile()
    assert not machines.started
    database.dispose()


def test_capacity_two_and_arrival_during_idle_exit_recover(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = ServerSettings(
        database_url=f"sqlite:///{tmp_path / 'queue.db'}", object_store_root=tmp_path / "objects"
    )
    database = Database(settings.database_url)
    service = AdmissionService(database, settings.create_object_store(), settings=settings)
    machines = Machines(database)
    owner = ScannerLifecycle(database, machines, tuple(machines.states), 2)
    archive = build_registry_fixture_archive(FIXTURE_ROOT / "example-pack")
    first = service.submit(archive, pack_name="example-pack", version="1.2.3")
    assert owner.reconcile() == 1
    second = service.submit(archive, pack_name="example-pack", version="1.2.4")
    assert owner.reconcile() == 1
    assert machines.started == ["a" * 14, "b" * 14]
    assert owner.reconcile() == 0

    # A candidate arriving after an empty claim can see a worker still exiting.
    # Neither the active inventory nor its recent intent permits an extra start.
    machines.states = {key: "stopping" for key in machines.states}
    assert owner.reconcile() == 0
    machines.states = {key: "stopped" for key in machines.states}
    assert owner.reconcile() == 0
    future = datetime.now(UTC) + timedelta(seconds=121)

    class Clock:
        @staticmethod
        def now(tz: object) -> datetime:
            return future

    monkeypatch.setattr(lifecycle, "datetime", Clock)
    assert owner.reconcile() == 2
    assert machines.started == ["a" * 14, "b" * 14, "a" * 14, "b" * 14]
    assert service.status(first).status == service.status(second).status == "queued"
    assert service.status(first).attempts == service.status(second).attempts == 0
    database.dispose()


def test_slow_machine_provider_does_not_block_outbox_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = ServerSettings(
        database_url=f"sqlite:///{tmp_path / 'queue.db'}",
        object_store_root=tmp_path / "objects",
        scanner_fly_app="disposable-scanners",
        scanner_machine_ids=("a" * 14,),
        scanner_fly_token="disposable-management-capability",
        scanner_token_sha256="a" * 64,
    )
    database = Database(settings.database_url)
    service = AdmissionService(database, settings.create_object_store(), settings=settings)
    entered, release = Event(), Event()
    archive = build_registry_fixture_archive(FIXTURE_ROOT / "example-pack")
    service.submit(archive, pack_name="example-pack", version="1.2.3")
    machines = Machines(database)

    class DeliveryComplete(Exception):
        pass

    def inventory(self: ScannerMachines) -> list[dict[str, Any]]:
        entered.set()
        assert release.wait(10), "delivery must progress while provider is blocked"
        return machines.list()

    def deliver(self: AdmissionService) -> bool:
        try:
            assert entered.wait(10)
            # Real catalog writes must remain possible while inventory is blocked.
            candidate = self.submit(archive, pack_name="example-pack", version="1.2.4")
            assert self.status(candidate).status == "queued"
        finally:
            release.set()
        raise DeliveryComplete

    monkeypatch.setattr(ScannerMachines, "list", inventory)
    monkeypatch.setattr(ScannerMachines, "start", machines.start)
    monkeypatch.setattr(AdmissionService, "deliver_once", deliver)
    with pytest.raises(DeliveryComplete):
        service.run_delivery()
    database.dispose()
