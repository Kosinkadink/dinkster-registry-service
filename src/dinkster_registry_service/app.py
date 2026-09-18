from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from contextlib import asynccontextmanager
from typing import Any, Literal
from uuid import UUID

from blake3 import blake3
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ConfigDict, Field, ValidationError
from pydantic.alias_generators import to_camel
from sqlalchemy.exc import SQLAlchemyError
from starlette.background import BackgroundTask
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.responses import Response, StreamingResponse

from .cursors import CursorCodec, CursorError
from .database import Database
from .digests import DigestError, require_blake3_digest
from .identifiers import IdentifierError, require_canonical_pack_name
from .ids import uuid7
from .object_store import LocalFilesystemObjectStore, ObjectStoreError
from .repository import CatalogDataError, CatalogRepository
from .settings import ServerSettings
from .versioning import VersionError, require_public_version
from .wire import ErrorCode, ErrorResponse, ResponseModel

logger = logging.getLogger(__name__)

PUBLIC_CACHE = "public, max-age=60, stale-while-revalidate=300"
NEGATIVE_CACHE = "public, max-age=30"
ARTIFACT_CACHE = "public, max-age=31536000, immutable"
NO_STORE = "no-store"


class RequestModel(BaseModel):
    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True, extra="forbid")


class EmptyQuery(RequestModel):
    pass


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


def create_app(settings: ServerSettings | None = None) -> FastAPI:
    configured = settings or ServerSettings.from_environment()
    database = Database(configured.database_url)
    object_store = LocalFilesystemObjectStore(configured.object_store_root)
    repository = CatalogRepository(database, CursorCodec(configured.cursor_secret))

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

    @app.get("/v1/health")
    def health(request: Request) -> Response:
        _query(request, EmptyQuery)
        return _json_response(
            request,
            repository.health(),
            cache_control=PUBLIC_CACHE,
            etag_context={"endpoint": "health"},
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
