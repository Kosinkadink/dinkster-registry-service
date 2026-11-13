from __future__ import annotations

import base64
import hashlib
import json
import math
import secrets
from dataclasses import asdict
from typing import Annotated, Any, Literal
from uuid import UUID

from dinkster_registry.archive_admission import AdmissionFinding, StageResult
from dinkster_schema import SCHEMA_WIRE_VERSION, claim_covers, schema_from_wire, schema_signature
from dinkster_workers.manifest import ManifestError, load_manifest
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from starlette.responses import JSONResponse, Response

from .admission import AdmissionService, CandidateClaim, LeaseLost
from .artifacts import EXPANDED_LIMIT
from .object_store import MAX_ARTIFACT_SIZE, ObjectStoreError
from .scan_execution import ProbeDependencies
from .wheels import extracted_wheel, inspect_wheel, run_wheel_integrity

NO_STORE = {"Cache-Control": "no-store"}
MAX_RESULT_BYTES = 16 * 1024 * 1024


class ScannerFinding(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    code: str = Field(min_length=1, max_length=256)
    severity: Literal["info", "warning", "error", "critical"]
    effect: Literal["block", "review", "signal"]
    message: str = Field(max_length=65536)


class ScannerProbeResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    findings: list[ScannerFinding] = Field(max_length=10000)
    data: dict[str, Any] | None
    operator_details: dict[str, Any] | None

    def stage_result(self) -> StageResult:
        result = StageResult(
            tuple(
                AdmissionFinding(value.code, value.severity, value.effect, value.message)
                for value in self.findings
            ),
            self.data,
            self.operator_details,
        )
        if self.data is None:
            if not result.blocked:
                raise ValueError("Successful probes require schema evidence")
            return result
        if set(self.data) != {"schemas"} or not isinstance(self.data["schemas"], list):
            raise ValueError("Probe data must contain schemas")
        seen = set()
        for entry in self.data["schemas"]:
            if not isinstance(entry, dict) or set(entry) != {
                "nodeType",
                "schemaVersion",
                "schemaWireVersion",
                "schemaSignature",
                "role",
                "schema",
            }:
                raise ValueError("Incomplete probe schema evidence")
            schema = schema_from_wire(entry["schema"])
            if (
                entry["nodeType"] != schema.node_type
                or type(entry["schemaVersion"]) is not int
                or entry["schemaVersion"] != schema.version
                or type(entry["schemaWireVersion"]) is not int
                or entry["schemaWireVersion"] != SCHEMA_WIRE_VERSION
                or entry["schemaSignature"] != schema_signature(schema)
                or entry["role"] not in {"schema-only", "executing"}
                or schema.node_type in seen
            ):
                raise ValueError("Probe schema identity differs from its wire schema")
            seen.add(schema.node_type)
        return result


class ScannerResultSubmission(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    artifactDigest: str
    probe: ScannerProbeResult | None


class ScannerError(HTTPException):
    """Scanner clients need distinct authentication, lease and transient statuses."""


def scanner_router(service: AdmissionService, token_sha256: str | None) -> APIRouter:
    async def authenticate(request: Request) -> None:
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if (
            token_sha256 is None
            or scheme != "Bearer"
            or not 1 <= len(token) <= 4096
            or not secrets.compare_digest(hashlib.sha256(token.encode()).hexdigest(), token_sha256)
        ):
            raise ScannerError(401, "Scanner authentication required.")
        if request.query_params:
            raise ScannerError(400, "Scanner endpoints do not accept query parameters.")
        result_request = request.method == "POST" and request.url.path.endswith("/result")
        body = bytearray()
        async for chunk in request.stream():
            if chunk and not result_request:
                raise ScannerError(400, "This scanner endpoint does not accept a request body.")
            if len(body) + len(chunk) > MAX_RESULT_BYTES:
                raise ScannerError(413, "Scanner result exceeds its size limit.")
            body.extend(chunk)
        if result_request:
            request.state.scanner_body = bytes(body)

    router = APIRouter(
        prefix="/internal/scanner", dependencies=[Depends(authenticate)], include_in_schema=False
    )

    def assignment(candidate_id: UUID, lease_token: UUID, *, renew: bool = False) -> CandidateClaim:
        try:
            return service.leased_claim(candidate_id, lease_token, renew=renew)
        except LeaseLost as exc:
            raise ScannerError(409, str(exc)) from exc

    @router.post("/claim")
    def claim() -> Response:
        claimed = service.claim()
        if claimed is None:
            return Response(status_code=204, headers=NO_STORE)
        return JSONResponse(
            {
                "candidateId": str(claimed.id),
                "leaseToken": str(claimed.lease_token),
                "leaseSeconds": service.lease_seconds,
                "kind": claimed.kind,
                "packName": claimed.pack_name,
                "version": claimed.version,
                "artifactDigest": claimed.declared_digest,
                "artifactSize": claimed.declared_size,
                "attempt": claimed.attempt,
                "scanEngine": claimed.scan_engine,
                "installLocks": claimed.install_locks,
                "probeSettings": asdict(service.settings.probe_settings()),
            },
            headers=NO_STORE,
        )

    def input_bytes(claimed: CandidateClaim) -> bytes:
        try:
            data = service.object_store.read(claimed.object_key, max_size=MAX_ARTIFACT_SIZE)
        except (FileNotFoundError, ObjectStoreError) as exc:
            raise ScannerError(503, "Assigned scan input is unavailable.") from exc
        return data

    @router.get("/{candidate_id}/input")
    def scan_input(candidate_id: UUID, x_scanner_lease: Annotated[UUID, Header()]) -> Response:
        claimed = assignment(candidate_id, x_scanner_lease)
        data = input_bytes(claimed)
        assignment(candidate_id, x_scanner_lease)
        return Response(data, media_type="application/octet-stream", headers=NO_STORE)

    @router.get("/{candidate_id}/locks")
    def locks(candidate_id: UUID, x_scanner_lease: Annotated[UUID, Header()]) -> Response:
        claimed = assignment(candidate_id, x_scanner_lease)
        try:
            resolved = service.probe_install_locks(claimed)
        except (ValueError, OSError, ObjectStoreError) as exc:
            raise ScannerError(503, "Assigned dependency locks are unavailable.") from exc
        assignment(candidate_id, x_scanner_lease)
        return JSONResponse(
            {variant: base64.b64encode(data).decode() for variant, data in resolved.items()},
            headers=NO_STORE,
        )

    @router.get("/{candidate_id}/dependencies")
    def dependencies(candidate_id: UUID, x_scanner_lease: Annotated[UUID, Header()]) -> Response:
        claimed = assignment(candidate_id, x_scanner_lease)
        data = input_bytes(claimed)
        integrity = run_wheel_integrity(
            data, claimed.declared_size, claimed.declared_digest, claimed.pack_name, claimed.version
        )
        if integrity.blocked:
            raise ScannerError(422, "Assigned scan input failed integrity checks.")
        try:
            wheel = inspect_wheel(data, claimed.pack_name, claimed.version)
            resolved: ProbeDependencies | StageResult
            if wheel.library or claimed.kind == "rescan":
                resolved = ProbeDependencies((), (), ())
            else:
                with extracted_wheel(data, wheel) as root:
                    resolved = service.probe_dependencies(root, claimed.set_id)
        except (ValueError, FileNotFoundError, ObjectStoreError) as exc:
            raise ScannerError(503, "Assigned scan dependencies are unavailable.") from exc
        assignment(candidate_id, x_scanner_lease)
        if isinstance(resolved, StageResult):
            return JSONResponse({"failure": asdict(resolved)}, headers=NO_STORE)
        size = sum(len(value) for value in resolved.helper_wheels) + sum(
            len(value) for _, value in resolved.library_wheels
        )
        if size > EXPANDED_LIMIT:
            raise ScannerError(503, "Assigned scan dependencies exceed the transfer limit.")
        return JSONResponse(
            {
                "helperWheels": [
                    base64.b64encode(value).decode() for value in resolved.helper_wheels
                ],
                "libraryWheels": [
                    {"filename": name, "data": base64.b64encode(value).decode()}
                    for name, value in resolved.library_wheels
                ],
                "requirements": list(resolved.requirements),
                "bindings": list(resolved.bindings),
            },
            headers=NO_STORE,
        )

    @router.post("/{candidate_id}/heartbeat")
    def heartbeat(candidate_id: UUID, x_scanner_lease: Annotated[UUID, Header()]) -> Response:
        assignment(candidate_id, x_scanner_lease, renew=True)
        return Response(status_code=204, headers=NO_STORE)

    @router.post("/{candidate_id}/result")
    def result(
        request: Request, candidate_id: UUID, x_scanner_lease: Annotated[UUID, Header()]
    ) -> Response:
        claimed = assignment(candidate_id, x_scanner_lease)
        try:

            def reject_constant(value: str) -> None:
                raise ValueError("Non-finite JSON numbers are not supported")

            def finite_float(value: str) -> float:
                number = float(value)
                if not math.isfinite(number):
                    raise ValueError("Non-finite JSON numbers are not supported")
                return number

            submitted = ScannerResultSubmission.model_validate(
                json.loads(
                    request.state.scanner_body,
                    parse_constant=reject_constant,
                    parse_float=finite_float,
                )
            )
            probe = submitted.probe.stage_result() if submitted.probe is not None else None
        except (
            ValidationError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            RecursionError,
        ) as exc:
            raise ScannerError(400, "Malformed scanner result.") from exc
        if submitted.artifactDigest != claimed.declared_digest:
            raise ScannerError(409, "Scanner result differs from the assigned archive.")
        data = input_bytes(claimed)
        integrity = run_wheel_integrity(
            data, claimed.declared_size, claimed.declared_digest, claimed.pack_name, claimed.version
        )
        if not integrity.blocked:
            wheel = inspect_wheel(data, claimed.pack_name, claimed.version)
            needs_probe = claimed.kind == "upload" and not wheel.library
            if needs_probe != (probe is not None):
                raise ScannerError(400, "Scanner result has incomplete or unexpected probe stages.")
            if probe is not None and not probe.blocked:
                assert probe.data is not None
                with extracted_wheel(data, wheel) as root:
                    try:
                        manifest = load_manifest(root / "dinkster-pack.toml")
                    except ManifestError:
                        # Shared admission records malformed manifests before the probe stage.
                        manifest = None
                schemas = probe.data["schemas"]
                if (
                    manifest is not None
                    and not schemas
                    and manifest.node_source != "remote-gateway-catalog"
                ):
                    raise ScannerError(400, "Successful scanner result is missing schemas.")
                if manifest is not None and any(
                    (
                        entry["nodeType"] not in manifest.executes
                        and not any(
                            claim_covers(namespace, entry["nodeType"])
                            for namespace in manifest.namespaces
                        )
                    )
                    or entry["role"]
                    != ("schema-only" if entry["nodeType"] in manifest.schema_only else "executing")
                    for entry in schemas
                ):
                    raise ScannerError(400, "Scanner schemas differ from the assigned manifest.")
        try:
            service.accept_probe_result(claimed, probe)
        except LeaseLost as exc:
            raise ScannerError(409, str(exc)) from exc
        return Response(status_code=204, headers=NO_STORE)

    return router
