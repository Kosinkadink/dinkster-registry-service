from __future__ import annotations

import hashlib
import secrets
from dataclasses import asdict
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from starlette.responses import JSONResponse, Response

from .admission import AdmissionService, CandidateClaim, LeaseLost
from .object_store import MAX_ARTIFACT_SIZE, ObjectStoreError

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
                "probeSettings": asdict(service.settings.probe_settings()),
            },
            headers=NO_STORE,
        )

    @router.get("/{candidate_id}/input")
    def scan_input(candidate_id: UUID, x_scanner_lease: Annotated[UUID, Header()]) -> Response:
        claimed = assignment(candidate_id, x_scanner_lease)
        try:
            data = service.object_store.read(claimed.object_key, max_size=MAX_ARTIFACT_SIZE)
        except (FileNotFoundError, ObjectStoreError) as exc:
            raise ScannerError(503, "Assigned scan input is unavailable.") from exc
        assignment(candidate_id, x_scanner_lease)
        return Response(data, media_type="application/octet-stream", headers=NO_STORE)

    @router.post("/{candidate_id}/heartbeat")
    def heartbeat(candidate_id: UUID, x_scanner_lease: Annotated[UUID, Header()]) -> Response:
        assignment(candidate_id, x_scanner_lease, renew=True)
        return Response(status_code=204, headers=NO_STORE)

    return router
