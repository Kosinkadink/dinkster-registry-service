from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from http.client import HTTPException
from typing import Any
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from sqlalchemy import and_, func, or_, select, text

from .database import AuditEventRecord, Database, ReleaseCandidateRecord, ReleaseSetRecord
from .ids import uuid7

START_GRACE_SECONDS = 120


class MachineUnavailable(RuntimeError):
    """Machine state is unknown; retain the queue and any start reservations."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class ScannerMachines:
    def __init__(self, app: str, token: str) -> None:
        self.app = app
        self._token = token
        self._opener = build_opener(ProxyHandler({}), NoRedirect())

    def _request(self, method: str, path: str) -> bytes:
        request = Request(
            f"https://api.machines.dev/v1/apps/{self.app}/machines{path}",
            data=b"{}" if method == "POST" else None,
            headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"},
            method=method,
        )
        try:
            with self._opener.open(request, timeout=10) as response:
                data: bytes = response.read(4 * 1024 * 1024 + 1)
        except HTTPError as exc:
            exc.close()
            raise MachineUnavailable("Scanner Machine API refused the request") from None
        except (OSError, HTTPException):
            raise MachineUnavailable("Scanner Machine API is unavailable") from None
        if len(data) > 4 * 1024 * 1024:
            raise MachineUnavailable("Scanner Machine API response exceeds its bound")
        return data

    def list(self) -> list[dict[str, Any]]:
        try:
            values = json.loads(self._request("GET", ""))
            if not isinstance(values, list) or any(
                not isinstance(item, dict)
                or not isinstance(item.get("id"), str)
                or not isinstance(item.get("state"), str)
                or not isinstance(item.get("config"), dict)
                or not isinstance(item["config"].get("restart", {}), dict)
                or not isinstance(item["config"].get("init", {}), dict)
                for item in values
            ):
                raise ValueError("Invalid Machine inventory")
            return values
        except (ValueError, TypeError):
            raise MachineUnavailable("Scanner Machine inventory is malformed") from None

    def start(self, machine_id: str) -> None:
        self._request("POST", f"/{machine_id}/start")


class ScannerLifecycle:
    def __init__(
        self,
        database: Database,
        machines: ScannerMachines,
        machine_ids: tuple[str, ...],
        limit: int,
    ) -> None:
        self.database = database
        self.machines = machines
        # A fixed subset bounds starts even if a paused caller resumes after its
        # reservation expires. Reservations alone cannot fence a provider API call.
        self.machine_ids = machine_ids[:limit]
        self.limit = limit

    def reconcile(self) -> int:
        requested: list[str] = []
        now = datetime.now(UTC)
        waiting_query = (
            select(func.count())
            .select_from(ReleaseCandidateRecord)
            .where(
                or_(
                    ReleaseCandidateRecord.status.in_(("queued", "retrying")),
                    and_(
                        ReleaseCandidateRecord.status == "scanning",
                        ReleaseCandidateRecord.lease_expires_at <= now,
                    ),
                ),
                or_(
                    ReleaseCandidateRecord.set_id.is_(None),
                    select(ReleaseSetRecord.id)
                    .where(
                        ReleaseSetRecord.id == ReleaseCandidateRecord.set_id,
                        ReleaseSetRecord.status == "queued",
                        ReleaseSetRecord.expires_at > now,
                    )
                    .exists(),
                ),
            )
        )
        with self.database.session() as session:
            if not session.scalar(waiting_query):
                return 0
        # Network latency must not hold SQLite's database-wide writer lock.
        inventory = self.machines.list()
        with self.database.session() as session, session.begin():
            if self.database.is_postgresql:
                if not session.scalar(
                    text("SELECT pg_try_advisory_xact_lock(hashtext('registry-scanner-lifecycle'))")
                ):
                    return 0
            else:
                session.connection().exec_driver_sql("BEGIN IMMEDIATE")
            now = datetime.now(UTC)
            waiting = session.scalar(waiting_query) or 0
            if not waiting:
                return 0
            by_id = {item["id"]: item for item in inventory}
            if len(by_id) != len(inventory) or not set(self.machine_ids) <= by_id.keys():
                raise MachineUnavailable("Registered scanner pool differs from Machine inventory")
            for machine_id in self.machine_ids:
                config = by_id[machine_id]["config"]
                if (
                    config.get("restart", {}).get("policy") != "no"
                    or config.get("services")
                    or config.get("auto_destroy")
                    or config.get("init", {}).get("exec") != ["dinkster-scanner"]
                ):
                    raise MachineUnavailable(
                        "Scanner Machines require isolated worker startup and restart policy no"
                    )
            active = {
                item["id"]
                for item in inventory
                if item.get("state") not in {"stopped", "suspended", "destroyed"}
            }
            recent = session.scalars(
                select(AuditEventRecord.subject_id).where(
                    AuditEventRecord.event_type == "scanner.machine_start_requested",
                    AuditEventRecord.subject_type == self.machines.app,
                    AuditEventRecord.created_at >= now - timedelta(seconds=START_GRACE_SECONDS),
                )
            )
            reserved = active | set(recent)
            for machine_id in self.machine_ids:
                if len(requested) >= waiting or len(reserved) >= self.limit:
                    break
                if machine_id in reserved or by_id[machine_id].get("state") not in {
                    "stopped",
                    "suspended",
                }:
                    continue
                session.add(
                    AuditEventRecord(
                        id=uuid7(),
                        created_at=now,
                        event_type="scanner.machine_start_requested",
                        subject_type=self.machines.app,
                        subject_id=machine_id,
                        data={},
                    )
                )
                session.flush()
                reserved.add(machine_id)
                requested.append(machine_id)
        # Persist every intent before any start request, including a process crash
        # or a response lost after the provider accepted the request.
        started = 0
        for machine_id in requested:
            try:
                self.machines.start(machine_id)
            except MachineUnavailable:
                continue
            started += 1
        return started
