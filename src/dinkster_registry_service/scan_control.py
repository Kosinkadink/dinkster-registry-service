from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import asdict
from typing import Annotated
from uuid import UUID

from dinkster_registry.archive_admission import StageResult
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from starlette.responses import JSONResponse, Response

from .admission import AdmissionService, CandidateClaim, LeaseLost
from .artifacts import EXPANDED_LIMIT
from .object_store import MAX_ARTIFACT_SIZE, ObjectStoreError
from .scan_execution import ProbeDependencies
from .wheels import extracted_wheel, inspect_wheel, run_wheel_integrity

NO_STORE = {"Cache-Control": "no-store"}


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
        async for chunk in request.stream():
            if chunk:
                raise ScannerError(400, "This scanner endpoint does not accept a request body.")

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
                    resolved = service.probe_dependencies(root)
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
            },
            headers=NO_STORE,
        )

    @router.post("/{candidate_id}/heartbeat")
    def heartbeat(candidate_id: UUID, x_scanner_lease: Annotated[UUID, Header()]) -> Response:
        assignment(candidate_id, x_scanner_lease, renew=True)
        return Response(status_code=204, headers=NO_STORE)

    return router
