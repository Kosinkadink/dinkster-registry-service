"""Prove scanner lifecycle against disposable Fly apps, never production.

Provisioning is separate: create the priced PostgreSQL/bucket/apps first and
install this file only on the disposable web Machine. The worker runs the
unmodified dinkster-scanner entry point. --serve adds authenticated fixture
controls to the real web app; --check drives those controls and the real
Machines API. Fixture submission bypasses publisher authentication; fixture
timings are not representative official-pack benchmarks. Provisioning must
enforce the cumulative spend/runtime cap and teardown in its own finally block,
including when this checker fails. Save evidence before destroying resources.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import statistics
import subprocess
import tempfile
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from fastapi import FastAPI
from fastapi import Request as WebRequest
from sqlalchemy import select, text
from starlette.responses import Response

from dinkster_registry_service.admission import AdmissionService
from dinkster_registry_service.app import ProtocolError, create_app
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.database import (
    AuditEventRecord,
    Database,
    PublisherRecord,
    ReleaseCandidateRecord,
    ReleaseScanRunRecord,
)
from dinkster_registry_service.principals import PrincipalRepository
from dinkster_registry_service.scanner_lifecycle import NoRedirect
from dinkster_registry_service.seed import FIXTURE_ROOT
from dinkster_registry_service.settings import ServerSettings

WEB_PREFIX = "dinkster-scan-web-821-"
WORKER_PREFIX = "dinkster-scan-worker-821-"


def create_proof_app(settings: ServerSettings, capability: str) -> FastAPI:
    if not capability or not settings.database_url.startswith("postgresql+psycopg://"):
        raise ValueError("Proof requires its own operator capability and PostgreSQL queue")
    database = Database(settings.database_url)
    service = AdmissionService(database, settings.create_object_store(), settings=settings)
    principals = PrincipalRepository(database)
    principals.register_user("scanner-proof")
    with database.session() as session:
        exists = session.get(PublisherRecord, "dinkster")
    if exists is None:
        principals.register_publisher("dinkster", "scanner-proof", datetime.now(UTC).isoformat())
    app = create_app(settings)
    app.state.proof_arrival = False
    app.state.proof_arrivals = []
    app.state.proof_inputs_read = set()

    def authenticate(request: WebRequest) -> None:
        if not secrets.compare_digest(
            request.headers.get("authorization", ""), "Bearer " + capability
        ):
            raise ProtocolError(403, "forbidden", "Disposable proof operator required")

    def submit(kind: str) -> str:
        if kind not in {"accepted", "legacy", "import-failure", "slow", "timeout"}:
            raise ProtocolError(400, "invalid_request", "Unknown fixture")
        with database.session() as session:
            sequence = len(list(session.scalars(select(ReleaseCandidateRecord.id)))) + 1
        version = f"1.2.{sequence}"
        if kind == "legacy":
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("dinkster-pack.toml", '[pack]\nname = "old-pack"\n')
            data, name = buffer.getvalue(), "old-pack"
        else:
            with tempfile.TemporaryDirectory(prefix="scanner-proof-fixture-") as directory:
                source = Path(directory) / "pack"
                shutil.copytree(FIXTURE_ROOT / "example-pack", source)
                manifest = source / "dinkster-pack.toml"
                manifest.write_text(
                    manifest.read_text().replace(
                        'name = "example-pack"',
                        f'name = "example-pack"\nversion = "{version}"\nengine = ">=0.9,<1"',
                    )
                )
                nodes = source / "nodes.py"
                prefix = {
                    "accepted": "",
                    "slow": "import time\ntime.sleep(12)\n",
                    "timeout": "import time\ntime.sleep(45)\n",
                    "import-failure": "raise RuntimeError('intentional fixture import failure')\n",
                }[kind]
                nodes.write_text(prefix + nodes.read_text())
                data, name = build_registry_fixture_archive(source), "example-pack"
        candidate = service.submit(data, pack_name=name, version=version, publisher="dinkster")
        return str(candidate)

    @app.post("/proof/queue/{kind}")
    def queue(kind: str, request: WebRequest) -> dict[str, str]:
        authenticate(request)
        return {"candidateId": submit(kind)}

    @app.post("/proof/arm-arrival")
    def arm_arrival(request: WebRequest) -> dict[str, bool]:
        authenticate(request)
        app.state.proof_arrival = True
        return {"armed": True}

    @app.middleware("http")
    async def arrival_after_empty_claim(request: WebRequest, call_next: Any) -> Response:
        response: Response = await call_next(request)
        if (
            request.url.path.startswith("/internal/scanner/")
            and request.url.path.endswith("/locks")
            and response.status_code == 200
        ):
            app.state.proof_inputs_read.add(request.url.path.split("/")[-2])
        if (
            request.url.path == "/internal/scanner/claim"
            and response.status_code == 204
            and app.state.proof_arrival
        ):
            app.state.proof_arrival = False
            # The real claim has already decided empty, but the worker has not
            # received that response or exited. No claim/lifecycle mock is used.
            app.state.proof_arrivals.append(submit("accepted"))
        return response

    @app.get("/proof/state")
    def state(request: WebRequest) -> dict[str, Any]:
        authenticate(request)
        with database.session() as session:
            rows = list(session.scalars(select(ReleaseCandidateRecord)))
            runs = list(session.scalars(select(ReleaseScanRunRecord)))
            intents = list(
                session.scalars(
                    select(AuditEventRecord).where(
                        AuditEventRecord.event_type == "scanner.machine_start_requested"
                    )
                )
            )
            return {
                "database": "postgresql",
                "databaseRole": session.scalar(text("SELECT current_user")),
                "probeTimeoutSeconds": settings.probe_timeout_seconds,
                "dependencyTimeoutSeconds": settings.probe_dependency_timeout_seconds,
                "maxAttempts": settings.scanner_max_attempts,
                "canCreateSchemaObjects": session.scalar(
                    text("SELECT has_schema_privilege(current_user, 'public', 'CREATE')")
                ),
                "arrivals": list(app.state.proof_arrivals),
                "candidates": [
                    {
                        "id": str(row.id),
                        "status": row.status,
                        "reason": row.status_reason,
                        "version": row.version,
                        "pack": row.pack_name,
                        "attempts": row.attempt_count,
                        "inputsRead": str(row.id) in app.state.proof_inputs_read,
                        "submittedAt": row.submitted_at.isoformat(),
                        "fenceHash": hashlib.sha256(str(row.lease_token).encode()).hexdigest()
                        if row.lease_token
                        else None,
                        "runs": [
                            {
                                "stage": run.stage,
                                "attempt": run.attempt,
                                "at": run.created_at.isoformat(),
                                "accepted": run.accepted,
                                "probeSeconds": (run.operator_details or {}).get("elapsedSeconds"),
                                "jail": (run.operator_details or {}).get("jail"),
                                "scannerHost": (run.operator_details or {}).get("scannerHost"),
                            }
                            for run in runs
                            if run.candidate_id == row.id
                        ],
                    }
                    for row in rows
                ],
                "startIntents": [
                    {"machine": row.subject_id, "at": row.created_at.isoformat()} for row in intents
                ],
            }

    return app


class Proof:
    def __init__(
        self, origin: str, app: str, machine: str, evidence: Path, expires_at: float
    ) -> None:
        if (
            not re.fullmatch(r"https://" + WEB_PREFIX + r"[a-z0-9-]+\.fly\.dev", origin)
            or not re.fullmatch(WORKER_PREFIX + r"[a-z0-9-]+", app)
            or not re.fullmatch(r"[0-9a-f]{14,16}", machine)
        ):
            raise ValueError("Only named disposable proof apps/Machines are allowed")
        self.origin, self.app, self.machine = origin, app, machine
        self.operator = os.environ["DINKSTER_PROOF_TOKEN"]
        self.fly_token = os.environ["FLY_API_TOKEN"]
        self.worker_token = os.environ["DINKSTER_PROOF_WORKER_TOKEN"]
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        # One absolute deadline is shared across sizes and invocations. Counting
        # all wall time is conservative even when a short run escapes polling.
        remaining = expires_at - time.time()
        if not 0 < remaining <= 3000:
            raise ValueError("Use the original experiment deadline, at most 3000 seconds away")
        self.deadline = time.monotonic() + remaining
        self.output = evidence.open("x")

    def record(self, event: str, data: Any) -> None:
        line = json.dumps({"at": datetime.now(UTC).isoformat(), "event": event, "data": data})
        if any(value in line for value in (self.operator, self.fly_token, self.worker_token)):
            raise RuntimeError("Refusing credential-bearing evidence")
        self.output.write(line + "\n")
        self.output.flush()
        print(line, flush=True)

    def request(
        self,
        method: str,
        path: str,
        data: Any = None,
        *,
        provider: bool = False,
        credential: str | None = None,
    ) -> Any:
        if time.monotonic() >= self.deadline:
            raise TimeoutError("Proof wall-clock bound reached")
        base = "https://api.machines.dev/v1/apps/" + self.app if provider else self.origin
        token = credential or (self.fly_token if provider else self.operator)
        request = Request(
            base + path,
            method=method,
            data=json.dumps(data).encode() if data is not None else None,
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        )
        with self.opener.open(request, timeout=30) as response:
            body = response.read(4 * 1024 * 1024)
            return json.loads(body) if body else None

    def machine_state(self) -> dict[str, Any]:
        value = self.request("GET", "/machines/" + self.machine, provider=True)
        config = value["config"]
        guest = config["guest"]
        assert value["region"] == "sjc"
        assert (guest["cpu_kind"], guest["cpus"], guest["memory_mb"]) in {
            ("shared", 2, 2048),
            ("performance", 1, 2048),
        }
        assert config["init"]["exec"] == ["dinkster-scanner"]
        assert config["restart"]["policy"] == "no"
        assert not any(config.get(key) for key in ("services", "mounts", "auto_destroy"))
        names = sorted(config.get("env", {}))
        assert not any(
            name.startswith(("AWS_", "S3_"))
            or name
            in {
                "DATABASE_URL",
                "DINKSTER_DATABASE_URL",
                "DINKSTER_CURSOR_SECRET",
                "DINKSTER_SCANNER_FLY_TOKEN",
                "DINKSTER_SCANNER_TOKEN_SHA256",
                "DINKSTER_SECURITY_SIGNING_KEY_PATH",
                "FLY_API_TOKEN",
                "GH_TOKEN",
                "GITHUB_TOKEN",
            }
            for name in names
        )
        result = {
            key: value.get(key) for key in ("id", "state", "region", "instance_id", "image_ref")
        }
        result["events"] = [
            {key: event.get(key) for key in ("id", "type", "status", "timestamp", "source")}
            for event in value.get("events", [])
        ]
        result.update(guest=guest, environmentNames=names)
        return result

    def wait(self, predicate: Any, seconds: int = 240) -> Any:
        deadline = min(self.deadline, time.monotonic() + seconds)
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            self.machine_state()
            time.sleep(0.5)
        raise TimeoutError("Observed state did not reach its expected value")

    def candidate(self, candidate: str) -> dict[str, Any]:
        rows = self.request("GET", "/proof/state")["candidates"]
        return next(row for row in rows if row["id"] == candidate)

    def accepted(self, candidate: str) -> dict[str, Any]:
        row = self.candidate(candidate)
        if row["status"] in {"rejected", "review"}:
            raise AssertionError("Candidate refused: " + str(row["reason"]))
        return row if row["status"] == "accepted" else {}

    def status(self, candidate: str, status: str, *, attempt: int = 1) -> dict[str, Any]:
        row = self.candidate(candidate)
        return row if row["status"] == status and row["attempts"] >= attempt else {}

    def prepared(self, candidate: str) -> dict[str, Any]:
        row = self.status(candidate, "scanning")
        return row if row.get("inputsRead") else {}

    def public_index(self, version: str) -> dict[str, Any]:
        try:
            index = self.request("GET", "/static/packs/index.json")
        except HTTPError as error:
            if error.code != 404:
                raise
            error.close()
            return {}
        return (
            index
            if any(
                row["name"] == "example-pack" and row["latestVersion"] == version
                for row in index["items"]
            )
            else {}
        )

    def idle(self) -> None:
        self.wait(lambda: self.machine_state()["state"] == "stopped")
        self.record("scanner-stopped", self.machine_state())

    def run(self, *, measurements_only: bool = False, samples: int = 3) -> None:
        initial = self.request("GET", "/proof/state")
        assert initial["database"] == "postgresql" and initial["databaseRole"] == "scanner_writer"
        assert not initial["canCreateSchemaObjects"]
        assert initial["probeTimeoutSeconds"] == 30
        assert initial["dependencyTimeoutSeconds"] == 300 and initial["maxAttempts"] == 3
        self.record("initial-queue", initial)
        inventory = self.request("GET", "/machines", provider=True)
        assert [machine["id"] for machine in inventory] == [self.machine]
        self.idle()
        for method, path in (
            ("GET", "/proof/state"),
            ("POST", "/v1/publish/example-pack/versions/9.9.9"),
        ):
            try:
                self.request(method, path, credential=self.worker_token)
            except HTTPError as error:
                assert error.code in {401, 403}
                self.record("worker-authority-denied", {"path": path, "status": error.code})
                error.close()
            else:
                raise AssertionError("Worker gained control-plane write/read authority")
        timings: list[float] = []
        for _ in range(samples):
            started = time.monotonic()
            candidate = self.request("POST", "/proof/queue/accepted")["candidateId"]
            row = self.wait(lambda candidate=candidate: self.accepted(candidate))
            assert any(run["jail"] == "user-pid-namespace" for run in row["runs"])
            timings.append(time.monotonic() - started)
            self.record("accepted-fixture", row)
            schemas = self.request(
                "GET", f"/v1/packs/example-pack/versions/{row['version']}/schemas"
            )
            assert sorted(item["nodeType"] for item in schemas["schemas"]) == [
                "example.resize",
                "example.save",
            ]
            self.record(
                "web-published-index",
                self.wait(lambda version=row["version"]: self.public_index(version)),
            )
            self.idle()
        self.record(
            "fixture-end-to-end-seconds",
            {
                "samples": timings,
                "median": statistics.median(timings),
                "includesQueueAndStartup": True,
            },
        )
        index = self.request("GET", "/static/packs/index.json")
        try:
            self.request("PUT", "/static/packs/index.json", {}, credential=self.worker_token)
        except HTTPError as error:
            # The app normalizes unsupported HTTP methods to protocol HTTP 400.
            assert error.code == 400
            error.close()
        else:
            raise AssertionError("Worker wrote through the static index route")
        assert self.request("GET", "/static/packs/index.json") == index
        self.record("index-write-route-refused-and-content-unchanged", True)
        if measurements_only:
            return
        for kind, reason in (
            ("legacy", "wheel.required"),
            ("import-failure", "entry.unresolvable"),
        ):
            candidate = self.request("POST", "/proof/queue/" + kind)["candidateId"]
            row = self.wait(lambda candidate=candidate: self.status(candidate, "rejected"))
            assert row["attempts"] == 1 and row["reason"] == reason
            self.record("permanent-rejection", row)
            self.idle()
        self.request("POST", "/proof/arm-arrival")
        candidate = self.request("POST", "/proof/queue/accepted")["candidateId"]
        self.wait(lambda: self.accepted(candidate))
        arrivals = self.wait(lambda: self.request("GET", "/proof/state")["arrivals"])
        self.record("arrival-after-empty-decision", self.wait(lambda: self.accepted(arrivals[0])))
        self.idle()
        for signal in ("SIGTERM", "SIGKILL"):
            candidate = self.request("POST", "/proof/queue/slow")["candidateId"]
            before = self.wait(lambda candidate=candidate: self.prepared(candidate))
            assert before["fenceHash"]
            self.record("before-mid-scan-stop", before)
            self.request(
                "POST",
                "/machines/" + self.machine + "/stop",
                {"signal": signal, "timeout": "1s"},
                provider=True,
            )
            self.idle()
            reclaimed = self.wait(
                lambda candidate=candidate: self.status(candidate, "scanning", attempt=2)
            )
            assert reclaimed["fenceHash"] and reclaimed["fenceHash"] != before["fenceHash"]
            self.record("replacement-fence-" + signal, reclaimed)
            after = self.wait(lambda candidate=candidate: self.accepted(candidate))
            assert after["attempts"] >= 2
            self.record("recovered-" + signal, after)
            self.idle()
        candidate = self.request("POST", "/proof/queue/timeout")["candidateId"]
        retry = self.wait(lambda: self.status(candidate, "scanning", attempt=2))
        self.record("timeout-reclaimed-without-resubmission", retry)
        exhausted = self.wait(lambda: self.status(candidate, "rejected"))
        assert exhausted["attempts"] == 3 and "timeout" in exhausted["reason"]
        self.record("timeout-exhausted", exhausted)
        self.idle()
        self.record("final-queue", self.request("GET", "/proof/state"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--serve", action="store_true")
    mode.add_argument("--check", action="store_true")
    parser.add_argument("--origin")
    parser.add_argument("--scanner-app")
    parser.add_argument("--machine")
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--expires-at", type=float, help="Original experiment UNIX deadline")
    parser.add_argument("--measurements-only", action="store_true")
    parser.add_argument("--samples", type=int, choices=(1, 3), default=3)
    args = parser.parse_args()
    if args.serve:
        import uvicorn

        app_name = os.getenv("FLY_APP_NAME", "")
        if app_name and not app_name.startswith(WEB_PREFIX):
            raise ValueError("Never install proof controls on a production app")
        for destination, source in {
            "S3_ENDPOINT_URL": "AWS_ENDPOINT_URL_S3",
            "S3_BUCKET": "BUCKET_NAME",
            "S3_REGION": "AWS_REGION",
            "S3_ACCESS_KEY_ID": "AWS_ACCESS_KEY_ID",
            "S3_SECRET_ACCESS_KEY": "AWS_SECRET_ACCESS_KEY",
        }.items():
            if source in os.environ:
                os.environ[destination] = os.environ[source]
        url = os.environ.get("DATABASE_URL", os.environ.get("DINKSTER_DATABASE_URL", ""))
        os.environ["DINKSTER_DATABASE_URL"] = re.sub(
            r"^postgres(?:ql)?://", "postgresql+psycopg://", url
        )
        settings = ServerSettings.from_environment()
        app = create_proof_app(settings, os.environ["DINKSTER_PROOF_TOKEN"])
        delivery = subprocess.Popen(["dinkster-registry", "deliver"])
        try:
            uvicorn.run(app, host="0.0.0.0", port=8000, access_log=False)
        finally:
            delivery.terminate()
            delivery.wait(timeout=10)
    else:
        if not all((args.origin, args.scanner_app, args.machine, args.evidence, args.expires_at)):
            parser.error("--check requires origin, scanner-app, machine, evidence and expires-at")
        proof = Proof(args.origin, args.scanner_app, args.machine, args.evidence, args.expires_at)
        try:
            proof.run(measurements_only=args.measurements_only, samples=args.samples)
        finally:
            proof.output.close()


if __name__ == "__main__":
    main()
