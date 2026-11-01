from __future__ import annotations

import hashlib
import io
import json
import logging
import zipfile
from collections.abc import Mapping
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from blake3 import blake3
from dinkster_registry import RegistryError, TokenRecord
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from pydantic.alias_generators import to_camel
from sqlalchemy.exc import SQLAlchemyError
from starlette.background import BackgroundTask
from starlette.datastructures import UploadFile
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response, StreamingResponse

from .admission import AdmissionError, AdmissionService, CandidateStatus
from .cursors import CursorCodec, CursorError
from .database import Database, ReleaseCandidateRecord
from .digests import DigestError, require_blake3_digest
from .identifiers import IdentifierError, require_canonical_pack_name
from .ids import uuid7
from .object_store import MAX_ARTIFACT_SIZE, ObjectStoreError
from .pack_locks import MAX_LOCKS_SIZE, PackLocksError, lock_object_key
from .principals import PrincipalRepository
from .repository import CatalogDataError, CatalogRepository
from .settings import ServerSettings
from .versioning import VersionError, require_public_version
from .wire import ErrorCode, ErrorResponse, ResponseModel

logger = logging.getLogger(__name__)

PUBLIC_CACHE = "public, max-age=60, stale-while-revalidate=300"
NEGATIVE_CACHE = "public, max-age=30"
ARTIFACT_CACHE = "public, max-age=31536000, immutable"
NO_STORE = "no-store"
MAX_TEMPLATE_ASSET_SIZE = 1024 * 1024


class RequestModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")


class EmptyQuery(RequestModel):
    pass


class LockQuery(RequestModel):
    base_id: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class BrowseQuery(RequestModel):
    q: str | None = Field(default=None, max_length=200)
    owner_type: Literal["user", "org"] | None = None
    owner: str | None = Field(default=None, min_length=1, max_length=64)
    node_type: str | None = Field(default=None, min_length=1, max_length=512)
    visibility: Literal["public", "org_private", "all"] = "public"
    sort: Literal["relevance", "updated", "downloads", "name"] | None = None
    limit: int = Field(default=25, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=4096)


class VersionsQuery(RequestModel):
    include_yanked: bool = False
    limit: int = Field(default=100, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=4096)


class ProvidersQuery(RequestModel):
    dinkster_version: str | None = Field(default=None, min_length=1, max_length=128)
    include_prerelease: bool = False


class BlocksQuery(RequestModel):
    since: str | None = Field(default=None, min_length=1, max_length=4096)


class TemplatesQuery(RequestModel):
    q: str = Field(default="", max_length=200)
    tag: str = Field(default="", max_length=128)
    pack: str = Field(default="", max_length=64)
    limit: int = Field(default=50, ge=1, le=200)
    cursor: str | None = Field(default=None, min_length=1, max_length=4096)


class ReviewRequest(RequestModel):
    decision: Literal["accept", "reject"]
    reason: str = Field(min_length=1, max_length=1024)


class RevokeTokenRequest(RequestModel):
    reason: str = Field(min_length=1, max_length=1024)


class ProtocolError(Exception):
    def __init__(
        self,
        status_code: int,
        code: ErrorCode,
        message: str,
        *,
        retryable: bool = False,
        detail: Mapping[str, Any] | None = None,
        cache_control: str = NO_STORE,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.retryable = retryable
        self.detail = None if detail is None else dict(detail)
        self.cache_control = cache_control


def _request_id(request: Request) -> UUID:
    value = getattr(request.state, "request_id", None)
    if isinstance(value, UUID):
        return value
    request_id = uuid7()
    request.state.request_id = request_id
    return request_id


def _validation_message(error: ValidationError | RequestValidationError) -> str:
    errors = error.errors()
    if not errors:
        return "The request is invalid."
    first = errors[0]
    location = ".".join(str(item) for item in first.get("loc", ()))
    message = str(first.get("msg", "invalid value"))
    return f"{location}: {message}" if location else message


def _query[QueryModel: BaseModel](request: Request, model_type: type[QueryModel]) -> QueryModel:
    pairs = request.query_params.multi_items()
    names = [name for name, _ in pairs]
    if len(names) != len(set(names)):
        raise ProtocolError(400, "invalid_request", "Query parameters must not be repeated.")
    try:
        return model_type.model_validate_strings(dict(pairs))
    except ValidationError as exc:
        raise ProtocolError(400, "invalid_request", _validation_message(exc)) from exc


def _etag_matches(header: str, etag: str) -> bool:
    opaque = etag.removeprefix("W/")
    return any(
        candidate.strip() == "*" or candidate.strip().removeprefix("W/") == opaque
        for candidate in header.split(",")
    )


def _json_body(payload: ResponseModel | Mapping[str, object]) -> bytes:
    if isinstance(payload, BaseModel):
        return payload.model_dump_json(by_alias=True).encode("utf-8")
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _json_response(
    request: Request,
    payload: ResponseModel | Mapping[str, object],
    *,
    cache_control: str,
    status_code: int = 200,
    etag_context: Mapping[str, object] | None = None,
    conditional: bool = True,
    include_etag: bool = True,
) -> Response:
    body = _json_body(payload)
    headers = {"Cache-Control": cache_control, "X-Request-Id": str(_request_id(request))}
    if include_etag:
        validator = body
        if etag_context is not None:
            context = json.dumps(
                etag_context, ensure_ascii=True, separators=(",", ":"), sort_keys=True
            ).encode("ascii")
            validator = context + b"\0" + body
        etag = f'"{blake3(validator).hexdigest()}"'
        headers["ETag"] = etag
        if (
            conditional
            and request.method == "GET"
            and _etag_matches(request.headers.get("if-none-match", ""), etag)
        ):
            return Response(status_code=304, headers=headers)
    return Response(
        content=body,
        status_code=status_code,
        media_type="application/json",
        headers=headers,
    )


def _error_response(request: Request, error: ProtocolError) -> Response:
    response = ErrorResponse.model_validate(
        {
            "error": {
                "code": error.code,
                "message": error.message,
                "retryable": error.retryable,
                "requestId": _request_id(request),
                "detail": error.detail,
            }
        }
    )
    return _json_response(
        request,
        response,
        status_code=error.status_code,
        cache_control=error.cache_control,
        conditional=False,
        include_etag=error.cache_control != NO_STORE,
    )


def _pack_name(value: str) -> str:
    try:
        return require_canonical_pack_name(value)
    except IdentifierError as exc:
        raise ProtocolError(400, "invalid_request", str(exc)) from exc


def _version(value: str) -> str:
    try:
        return require_public_version(value)
    except VersionError as exc:
        raise ProtocolError(400, "invalid_request", str(exc)) from exc


def _node_type(value: str) -> str:
    if len(value) > 512 or not value or "/" in value or "\x00" in value:
        raise ProtocolError(400, "invalid_request", "nodeType is not a valid path identifier")
    return value


def _not_found(message: str, **detail: object) -> ProtocolError:
    return ProtocolError(
        404,
        "not_found",
        message,
        detail=detail,
        cache_control=NEGATIVE_CACHE,
    )


def _authenticate(request: Request, principals: PrincipalRepository) -> TokenRecord:
    scheme, _, credential = request.headers.get("authorization", "").partition(" ")
    if scheme != "Bearer" or not credential:
        raise ProtocolError(401, "unauthenticated", "A valid bearer token is required.")
    try:
        return principals.verify_token(credential, datetime.now(UTC).isoformat())
    except RegistryError:
        raise ProtocolError(401, "unauthenticated", "A valid bearer token is required.") from None


def _candidate_payload(status: CandidateStatus) -> dict[str, object]:
    return {
        "candidateId": str(status.id),
        "packName": status.pack_name,
        "version": status.version,
        "artifactDigest": status.digest,
        "artifactSize": status.size,
        "status": status.status,
        "reason": status.reason,
        "attempts": status.attempts,
        "findings": [
            {
                "code": finding.code,
                "severity": finding.severity,
                "effect": finding.effect,
                "message": finding.message,
            }
            for finding in status.findings
        ],
    }


def create_app(settings: ServerSettings | None = None) -> FastAPI:
    configured = settings or ServerSettings.from_environment()
    database = Database(configured.database_url)
    object_store = configured.create_object_store()
    repository = CatalogRepository(database, CursorCodec(configured.cursor_secret))
    principals = PrincipalRepository(database)
    admission = AdmissionService(database, object_store, settings=configured)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> Any:
        del application
        yield
        database.dispose()

    app = FastAPI(title="Dinkster Registry", lifespan=lifespan)
    app.state.database = database
    app.state.object_store = object_store

    @app.middleware("http")
    async def request_metadata(request: Request, call_next: Any) -> Response:
        request.state.request_id = uuid7()
        response: Response = await call_next(request)
        response.headers.setdefault("X-Request-Id", str(request.state.request_id))
        return response

    @app.exception_handler(ProtocolError)
    async def protocol_error_handler(request: Request, error: ProtocolError) -> Response:
        return _error_response(request, error)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, error: RequestValidationError) -> Response:
        return _error_response(
            request,
            ProtocolError(400, "invalid_request", _validation_message(error)),
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(request: Request, error: StarletteHTTPException) -> Response:
        if error.status_code == 404:
            protocol_error = _not_found("The requested endpoint was not found.")
        else:
            protocol_error = ProtocolError(400, "invalid_request", "The request is not supported.")
        return _error_response(request, protocol_error)

    @app.exception_handler(SQLAlchemyError)
    async def database_error_handler(request: Request, error: SQLAlchemyError) -> Response:
        logger.exception("Catalog database request failed", exc_info=error)
        return _error_response(
            request,
            ProtocolError(
                500, "internal", "The catalog is not currently available.", retryable=True
            ),
        )

    @app.exception_handler(ValidationError)
    @app.exception_handler(CatalogDataError)
    async def stored_data_error_handler(
        request: Request, error: ValidationError | CatalogDataError
    ) -> Response:
        logger.exception("Stored catalog data is invalid", exc_info=error)
        return _error_response(
            request,
            ProtocolError(
                500, "internal", "The catalog is not currently available.", retryable=True
            ),
        )

    @app.exception_handler(Exception)
    async def unexpected_error_handler(request: Request, error: Exception) -> Response:
        request_id = _request_id(request)
        logger.exception("Unhandled request failed (request_id=%s)", request_id, exc_info=error)
        return _error_response(
            request,
            ProtocolError(
                500, "internal", "The catalog is not currently available.", retryable=True
            ),
        )

    @app.get("/healthz")
    def readiness() -> Response:
        with database.engine.connect() as connection:
            connection.exec_driver_sql("SELECT 1")
        return Response(status_code=200, headers={"Cache-Control": NO_STORE})

    @app.get("/v1/health")
    def health(request: Request) -> Response:
        _query(request, EmptyQuery)
        return _json_response(
            request,
            repository.health(),
            cache_control=PUBLIC_CACHE,
            etag_context={"endpoint": "health"},
        )

    @app.get("/packs/index.json")
    @app.get("/translations/index.json")
    def static_index(request: Request) -> Response:
        _query(request, EmptyQuery)
        try:
            body = object_store.read(request.url.path.lstrip("/"))
        except FileNotFoundError:
            raise _not_found("The static index has not been published.") from None
        etag = f'"{blake3(body).hexdigest()}"'
        headers = {"ETag": etag, "Cache-Control": PUBLIC_CACHE}
        if _etag_matches(request.headers.get("if-none-match", ""), etag):
            return Response(status_code=304, headers=headers)
        return Response(body, media_type="application/json", headers=headers)

    @app.post("/v1/publish/{canonical_name}/versions/{canonical_version}")
    async def publish(request: Request, canonical_name: str, canonical_version: str) -> Response:
        _query(request, EmptyQuery)
        name = _pack_name(canonical_name)
        version = _version(canonical_version)
        token = _authenticate(request, principals)
        try:
            principals.authorize(token.minted_by, token.publisher, "publish")
            principals.authorize_token(token, token.publisher, name)
        except RegistryError as exc:
            raise ProtocolError(403, "forbidden", str(exc)) from None
        locks = None
        limit = MAX_ARTIFACT_SIZE
        multipart = (
            request.headers.get("content-type", "").split(";", 1)[0] == "multipart/form-data"
        )
        if multipart:
            limit += MAX_LOCKS_SIZE + 16384
        chunks = bytearray()
        async for chunk in request.stream():
            chunks.extend(chunk)
            if len(chunks) > limit:
                raise ProtocolError(
                    413, "artifact_too_large", "Publication body exceeds size limit."
                )
        if multipart:

            async def receive_body() -> dict[str, Any]:
                return {"type": "http.request", "body": bytes(chunks), "more_body": False}

            bounded = Request(request.scope, receive=receive_body)
            async with bounded.form(
                max_files=1, max_fields=1, max_part_size=MAX_LOCKS_SIZE
            ) as form:
                if [key for key, _ in form.multi_items()].count("archive") != 1 or (
                    len(form.multi_items()) != 2 or "locks" not in form
                ):
                    raise ProtocolError(
                        400, "invalid_request", "Expected one archive and one locks part."
                    )
                upload, raw_locks = form["archive"], form["locks"]
                if not isinstance(upload, UploadFile) or not isinstance(raw_locks, str):
                    raise ProtocolError(400, "invalid_request", "Invalid archive or locks part.")
                archive = await upload.read()
                locks = raw_locks.encode("utf-8")
        else:
            archive = bytes(chunks)
        if not 1 <= len(archive) <= MAX_ARTIFACT_SIZE:
            raise ProtocolError(
                413,
                "artifact_too_large",
                f"Artifact size must be between 1 and {MAX_ARTIFACT_SIZE} bytes.",
            )
        try:
            candidate_id = admission.submit(
                archive,
                pack_name=name,
                version=version,
                submitted_by=token.minted_by,
                publisher=token.publisher,
                locks=locks,
            )
            principals.record(
                token.minted_by,
                "submit-release",
                str(candidate_id),
                datetime.now(UTC).isoformat(),
                f"{name} {version}",
            )
        except PackLocksError as exc:
            raise ProtocolError(400, "invalid_request", str(exc)) from None
        except (AdmissionError, RegistryError) as exc:
            raise ProtocolError(409, "publish_in_progress", str(exc)) from None
        return _json_response(
            request,
            {"candidateId": str(candidate_id), "status": "queued"},
            cache_control=NO_STORE,
            status_code=202,
            conditional=False,
            include_etag=False,
        )

    @app.get("/v1/publish/{candidate_id}")
    def publish_status(request: Request, candidate_id: UUID) -> Response:
        _query(request, EmptyQuery)
        token = _authenticate(request, principals)
        with database.session() as session:
            candidate = session.get(ReleaseCandidateRecord, candidate_id)
            if candidate is None:
                raise _not_found("The requested publish candidate was not found.")
            if candidate.publisher_id != token.publisher and not principals.is_operator(
                token.minted_by
            ):
                raise ProtocolError(403, "forbidden", "The publish candidate is not accessible.")
        return _json_response(
            request,
            _candidate_payload(admission.status(candidate_id)),
            cache_control=NO_STORE,
            conditional=False,
            include_etag=False,
        )

    @app.post("/v1/reviews/{candidate_id}")
    def resolve_review(request: Request, candidate_id: UUID, body: ReviewRequest) -> Response:
        _query(request, EmptyQuery)
        token = _authenticate(request, principals)
        if token.pack is not None or not principals.is_operator(token.minted_by):
            raise ProtocolError(403, "forbidden", "Registry operator authority is required.")
        try:
            status = admission.resolve_review(
                candidate_id,
                accepted=body.decision == "accept",
                actor=token.minted_by,
                reason=body.reason,
            )
            principals.record(
                token.minted_by,
                f"review-{body.decision}",
                str(candidate_id),
                datetime.now(UTC).isoformat(),
                body.reason,
            )
        except (AdmissionError, RegistryError) as exc:
            raise ProtocolError(409, "admission_rejected", str(exc)) from None
        return _json_response(
            request,
            _candidate_payload(status),
            cache_control=NO_STORE,
            conditional=False,
            include_etag=False,
        )

    @app.get("/v1/tokens")
    def list_tokens(request: Request) -> Response:
        _query(request, EmptyQuery)
        token = _authenticate(request, principals)
        if token.pack is not None:
            raise ProtocolError(
                403, "forbidden", "Token administration requires an unscoped token."
            )
        try:
            records = principals.administered_tokens(token.publisher, token.minted_by)
        except RegistryError as exc:
            raise ProtocolError(403, "forbidden", str(exc)) from None
        return _json_response(
            request,
            {
                "tokens": [
                    {
                        "id": record.token_id,
                        "publisher": record.publisher,
                        "mintedBy": record.minted_by,
                        "pack": record.pack,
                        "createdAt": record.created_at,
                        "expiresAt": record.expires_at,
                        "revoked": record.revoked,
                        "revokedReason": record.revoked_reason,
                    }
                    for record in records
                ]
            },
            cache_control=NO_STORE,
            conditional=False,
            include_etag=False,
        )

    @app.post("/v1/tokens/{token_id}/revoke")
    def revoke_token(request: Request, token_id: str, body: RevokeTokenRequest) -> Response:
        _query(request, EmptyQuery)
        token = _authenticate(request, principals)
        try:
            principals.revoke_token(
                token_id,
                token.minted_by,
                datetime.now(UTC).isoformat(),
                body.reason,
            )
        except RegistryError:
            raise ProtocolError(403, "forbidden", "Token revocation is forbidden.") from None
        return _json_response(
            request,
            {"revoked": token_id},
            cache_control=NO_STORE,
            conditional=False,
            include_etag=False,
        )

    @app.get("/v1/packs")
    def browse(request: Request) -> Response:
        query = _query(request, BrowseQuery)
        if query.visibility != "public":
            raise ProtocolError(
                401,
                "unauthenticated",
                "Authenticated organization context is required for private catalog visibility.",
            )
        search_query = query.q or None
        sort = query.sort or ("relevance" if search_query is not None else "updated")
        try:
            payload = repository.browse(
                q=search_query,
                owner_type=query.owner_type,
                owner=query.owner,
                node_type=query.node_type,
                sort=sort,
                limit=query.limit,
                cursor=query.cursor,
            )
        except CursorError as exc:
            raise ProtocolError(400, "invalid_request", str(exc)) from exc
        return _json_response(
            request,
            payload,
            cache_control=PUBLIC_CACHE,
            etag_context={"endpoint": "packs", "query": query.model_dump(by_alias=True)},
        )

    @app.get("/v1/packs/{canonical_name}")
    def pack_detail(request: Request, canonical_name: str) -> Response:
        _query(request, EmptyQuery)
        name = _pack_name(canonical_name)
        payload = repository.pack_detail(name)
        if payload is None:
            raise _not_found("The requested pack was not found.", packName=name)
        return _json_response(
            request,
            payload,
            cache_control=PUBLIC_CACHE,
            etag_context={"endpoint": "pack", "name": name},
        )

    @app.get("/v1/packs/{canonical_name}/versions")
    def versions(request: Request, canonical_name: str) -> Response:
        query = _query(request, VersionsQuery)
        name = _pack_name(canonical_name)
        try:
            payload = repository.versions(
                name,
                include_yanked=query.include_yanked,
                limit=query.limit,
                cursor=query.cursor,
            )
        except CursorError as exc:
            raise ProtocolError(400, "invalid_request", str(exc)) from exc
        if payload is None:
            raise _not_found("The requested pack was not found.", packName=name)
        return _json_response(
            request,
            payload,
            cache_control=PUBLIC_CACHE,
            etag_context={
                "endpoint": "versions",
                "name": name,
                "query": query.model_dump(by_alias=True),
            },
        )

    @app.get("/v1/packs/{canonical_name}/versions/{canonical_version}")
    def release_detail(request: Request, canonical_name: str, canonical_version: str) -> Response:
        _query(request, EmptyQuery)
        name = _pack_name(canonical_name)
        version = _version(canonical_version)
        payload = repository.release_detail(name, version)
        if payload is None:
            raise _not_found("The requested release was not found.", packName=name, version=version)
        return _json_response(
            request,
            payload,
            cache_control=PUBLIC_CACHE,
            etag_context={"endpoint": "release", "name": name, "version": version},
        )

    @app.get("/v1/packs/{canonical_name}/versions/{canonical_version}/schemas")
    def schemas(request: Request, canonical_name: str, canonical_version: str) -> Response:
        _query(request, EmptyQuery)
        name = _pack_name(canonical_name)
        version = _version(canonical_version)
        payload = repository.schemas(name, version)
        if payload is None:
            raise _not_found("The requested release was not found.", packName=name, version=version)
        return _json_response(
            request,
            payload,
            cache_control=PUBLIC_CACHE,
            etag_context={"endpoint": "schemas", "name": name, "version": version},
        )

    @app.get("/index/templates")
    def templates(request: Request) -> Response:
        query = _query(request, TemplatesQuery)
        try:
            payload = repository.templates(
                q=query.q.strip().casefold(),
                tag=query.tag,
                pack_filter=query.pack,
                limit=query.limit,
                cursor=query.cursor,
            )
        except CursorError as exc:
            raise ProtocolError(400, "invalid_request", str(exc)) from exc
        return _json_response(
            request,
            payload,
            cache_control=PUBLIC_CACHE,
            etag_context={"endpoint": "templates", "query": query.model_dump(by_alias=True)},
        )

    def template_asset_response(
        request: Request,
        canonical_name: str,
        canonical_version: str,
        template_id: str,
        *,
        thumbnail: bool,
    ) -> Response:
        _query(request, EmptyQuery)
        name = _pack_name(canonical_name)
        version = _version(canonical_version)
        result = repository.template_asset(name, version, template_id, thumbnail=thumbnail)
        if result is None:
            raise _not_found(
                "The requested release template asset was not found.",
                packName=name,
                version=version,
                templateId=template_id,
            )
        template, artifact = result
        try:
            archive_bytes = b"".join(
                object_store.open(
                    artifact.object_key,
                    expected_size=artifact.size,
                    expected_digest=artifact.digest,
                )
            )
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                member = archive.getinfo(template["path"])
                if member.file_size > MAX_TEMPLATE_ASSET_SIZE:
                    raise ObjectStoreError("template asset exceeds its size limit")
                data = archive.read(member)
        except FileNotFoundError as exc:
            raise ProtocolError(
                500, "internal", "The artifact is not currently available."
            ) from exc
        except (KeyError, OSError, zipfile.BadZipFile, ObjectStoreError) as exc:
            raise ProtocolError(500, "internal", "The template artifact is invalid.") from exc
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        if digest != template["digest"]:
            raise ProtocolError(
                500, "internal", "The template asset failed integrity verification."
            )
        etag = f'"{digest}"'
        headers = {"Cache-Control": ARTIFACT_CACHE, "ETag": etag}
        if _etag_matches(request.headers.get("if-none-match", ""), etag):
            return Response(status_code=304, headers=headers)
        return Response(content=data, media_type=str(template["mediaType"]), headers=headers)

    @app.get("/index/packs/{canonical_name}/versions/{canonical_version}/templates/{template_id}")
    def template_document(
        request: Request, canonical_name: str, canonical_version: str, template_id: str
    ) -> Response:
        return template_asset_response(
            request, canonical_name, canonical_version, template_id, thumbnail=False
        )

    @app.get(
        "/index/packs/{canonical_name}/versions/{canonical_version}/templates/{template_id}/thumbnail"
    )
    def template_thumbnail(
        request: Request, canonical_name: str, canonical_version: str, template_id: str
    ) -> Response:
        return template_asset_response(
            request, canonical_name, canonical_version, template_id, thumbnail=True
        )

    @app.get("/v1/nodes/{node_type}/providers")
    def providers(request: Request, node_type: str) -> Response:
        query = _query(request, ProvidersQuery)
        checked_node_type = _node_type(node_type)
        if query.dinkster_version is not None:
            try:
                Version(query.dinkster_version)
            except InvalidVersion as exc:
                raise ProtocolError(
                    400, "invalid_request", "dinksterVersion must be a valid PEP 440 version"
                ) from exc
        payload = repository.providers(
            checked_node_type, query.dinkster_version, query.include_prerelease
        )
        return _json_response(
            request,
            payload,
            cache_control=PUBLIC_CACHE,
            etag_context={
                "endpoint": "providers",
                "nodeType": checked_node_type,
                "query": query.model_dump(by_alias=True),
            },
        )

    @app.post("/v1/packs/{canonical_name}/versions/{canonical_version}/download-tickets")
    def download_ticket(request: Request, canonical_name: str, canonical_version: str) -> Response:
        _query(request, EmptyQuery)
        name = _pack_name(canonical_name)
        version = _version(canonical_version)
        payload = repository.download_ticket(name, version, configured.public_base_url)
        if payload is None:
            raise _not_found(
                "The requested release is not available for download.",
                packName=name,
                version=version,
            )
        return _json_response(
            request,
            payload,
            cache_control=NO_STORE,
            conditional=False,
            include_etag=False,
        )

    @app.get("/v1/packs/{canonical_name}/versions/{canonical_version}/locks/{variant}")
    def installation_lock(
        request: Request, canonical_name: str, canonical_version: str, variant: str
    ) -> Response:
        query = _query(request, LockQuery)
        release = repository.release_detail(_pack_name(canonical_name), _version(canonical_version))
        lock = release.install_locks.get(variant) if release is not None else None
        if lock is None:
            raise _not_found("The requested installation lock was not found.")
        if lock.base_id != query.base_id:
            raise ProtocolError(409, "invalid_request", "Installation lock base identity differs.")
        etag = f'"{lock.digest}"'
        headers = {"Cache-Control": ARTIFACT_CACHE, "ETag": etag}
        if _etag_matches(request.headers.get("if-none-match", ""), etag):
            return Response(status_code=304, headers=headers)
        try:
            stored = object_store.open(
                lock_object_key(lock.digest), expected_size=lock.size, expected_digest=lock.digest
            )
        except (FileNotFoundError, ObjectStoreError) as exc:
            raise ProtocolError(
                500, "internal", "Installation lock bytes are unavailable."
            ) from exc
        return StreamingResponse(
            stored,
            media_type="application/json",
            headers=headers,
            background=BackgroundTask(stored.close),
        )

    @app.get("/v1/artifacts/{digest}")
    def artifact(request: Request, digest: str) -> Response:
        _query(request, EmptyQuery)
        try:
            checked_digest = require_blake3_digest(digest)
        except DigestError as exc:
            raise ProtocolError(400, "invalid_request", str(exc)) from exc
        downloadable = repository.downloadable_artifact(checked_digest)
        if downloadable is None:
            raise _not_found("The requested artifact was not found.", artifactDigest=digest)
        metadata, pack, release = downloadable
        etag = f'"{metadata.digest}"'
        headers = {
            "Cache-Control": ARTIFACT_CACHE,
            "ETag": etag,
            "X-Dinkster-Artifact-Digest": metadata.digest,
            "X-Request-Id": str(_request_id(request)),
        }
        if _etag_matches(request.headers.get("if-none-match", ""), etag):
            return Response(status_code=304, headers=headers)
        try:
            stored_object = object_store.open(
                metadata.object_key,
                expected_size=metadata.size,
                expected_digest=metadata.digest,
            )
        except FileNotFoundError as exc:
            raise ProtocolError(
                500, "internal", "The artifact is not currently available.", retryable=True
            ) from exc
        except ObjectStoreError as exc:
            logger.exception(
                "Artifact integrity verification failed (request_id=%s)",
                _request_id(request),
                exc_info=exc,
            )
            raise ProtocolError(
                500, "internal", "The artifact failed integrity verification.", retryable=False
            ) from exc
        filename = f"{pack.name}-{release.version}.dinksterpack.zip"
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
        headers["Content-Length"] = str(metadata.size)
        return StreamingResponse(
            stored_object,
            media_type=metadata.media_type,
            headers=headers,
            background=BackgroundTask(stored_object.close),
        )

    @app.get("/v1/security/blocks")
    def security_blocks(request: Request) -> Response:
        query = _query(request, BlocksQuery)
        if query.since is not None:
            raise ProtocolError(
                400,
                "invalid_request",
                "No security block cursor has been issued by this catalog.",
            )
        return _json_response(
            request,
            repository.security_blocks(),
            cache_control=PUBLIC_CACHE,
            etag_context={"endpoint": "security-blocks", "query": {"since": None}},
        )

    return app
