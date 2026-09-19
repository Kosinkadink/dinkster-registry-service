"""Registry HTTP surface: artifact bytes over bearer-token auth.

The wire half of the store. Two principles carried over from the client
side (``http_registry_fetcher`` in the dinkster app layer) and the pure
model, so the service can never weaken them:

- ARTIFACT IDENTITY IS THE DIGEST. Download is content-addressed
  (``GET /artifacts/<hex>.zip`` - the digest IS the whole request, no
  name/version resolution on this surface), and upload verifies the
  actual bytes against the declared digest before anything lands - a
  lying uploader gets a refusal, never storage. Bytes for a digest are
  immutable, hence the rendition-style caching contract the rest of the
  stack already speaks: quoted digest ETag, If-None-Match -> 304, and a
  forever cache lifetime.
- AUTH NEVER CONFIRMS CREDENTIALS. Uploads require a bearer token
  (``Authorization: Bearer dinkster_pat_...``) verified through the pure
  directory (hashed at rest, constant-time compare). Every credential
  failure - missing, malformed, unknown, revoked, expired, orphaned -
  is the same 401 with the same body: an attacker probing tokens learns
  nothing from the wire that the model didn't already refuse to tell.
  Plaintext tokens are never logged or persisted here.

Downloads are unauthenticated for now (public-registry semantics; a
digest is unguessable capability enough for code that admission will
publish anyway). Private registries wanting gated downloads need a
read-credential design - recorded as open work, not
improvised here.

Storage: ``ArtifactVault`` is content-addressed files on disk (one
``<hex>.zip`` per digest), NOT database rows - the store's SQLite file
holds metadata and evidence, never archive bytes. Admission is atomic
(temp file + fsync + rename) and idempotent: re-uploading identical
bytes is a no-op that answers 200 instead of 201.

Publish (``POST /publish``) binds an uploaded artifact to a
``Submission`` THROUGH THE REGISTRY'S OWN PROBE: the request carries
only the declared version and the artifact digest - pack name and
namespace claims are read from the registry's own probe of the vault
bytes, and the evidence fed to admission is that probe's doctor
report, so publisher-supplied claims never become registry evidence.
The prober itself is an injectable seam (``Prober``): the real one
lives in the app layer where doctor machinery is importable, keeping
this package's dependency surface at dinkster_registry + dinkster_schema.
A registry deployed without a prober refuses publishes with 501 -
artifact mirroring alone needs no probe machinery.

The index (``GET /index/packs...``) is the read side admission built:
it serves what the registry's own probes recorded (releases, claims,
node types), never manifest assertions. Listing follows the collection
contract every Dinkster listing surface speaks (mirroring
dinkster_server/paging.py, which this package cannot import): query-first,
keyset cursors that BIND the query that minted them, mismatch is a
loud 400 and the client restarts from page one. Resolution stays
explicit: one registry answers for its own corpus only - no fallback,
no federation - so the client-side rule ("resolution never searches
across registries") has nothing to fight here.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import io
import json
import os
import re
import tempfile
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from aiohttp import web
from dinkster_registry import (
    ARTIFACT_DIGEST_PREFIX,
    DoctorEvidence,
    RegistryError,
    Release,
    ReleaseTemplate,
    Submission,
    TokenRecord,
    Verdict,
    Version,
    artifact_digest,
)
from dinkster_schema import canonical_name

from .store import MAX_YANK_REASON_CHARS, RegistryStore

Clock = Callable[[], str]
"""() -> ISO 8601 UTC timestamp string. Injectable so token-expiry tests
never sleep; the default is real time."""


class ProbeError(Exception):
    """The registry's probe could not even read the artifact as a pack -
    no manifest to name it, no claims to admit. Distinct from a doctor
    report with error findings, which IS admissible evidence and lands
    as a rejected verdict with the findings visible."""


@dataclass(frozen=True)
class ProbeResult:
    """What the registry's own probe read from the artifact bytes: the
    manifest's claims (name, namespaces - claims, not grants) plus the
    doctor's report JSON over those exact bytes. Everything a
    ``Submission`` needs except what the publisher declares on the
    request (the version) and what the token proves (the publisher)."""

    pack_name: str
    namespaces: tuple[str, ...]
    report_json: str
    templates: tuple[ReleaseTemplate, ...] = ()
    """Template descriptors the probe read from the manifest inside the
    artifact - browse metadata for the index, pinned to these bytes."""
    executes: tuple[str, ...] = ()
    """Node types the manifest enrolls as an executor ([pack] executes) -
    covered by their owning pack's claim, not this pack's."""


Prober = Callable[[Path], ProbeResult]
"""(vault archive path) -> the registry's own reading of the bytes.
Raises ``ProbeError`` when the archive is not a pack at all. The real
prober unpacks and runs the doctor in the app layer; tests inject
fakes. Probe execution isolation (beyond the doctor's own subprocess
probe) is a deployment concern layered outside this seam."""

DEFAULT_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
"""Upload size cap. Pack artifacts are source trees (code + manifests,
ZIP_STORED), not model weights - 64 MiB is generous for code and small
enough that a runaway upload cannot fill the vault's disk quietly."""

_ARTIFACT_FILE_RE = re.compile(r"^[0-9a-f]{64}\.zip$")

STORE_KEY: web.AppKey[RegistryStore] = web.AppKey("registry_store")
VAULT_KEY: web.AppKey[ArtifactVault] = web.AppKey("artifact_vault")
CLOCK_KEY: web.AppKey[Clock] = web.AppKey("clock")
PROBER_KEY: web.AppKey[Prober | None] = web.AppKey("prober")


def utc_now() -> str:
    """The default clock: real UTC time, ISO 8601."""
    return datetime.now(UTC).isoformat()


class ArtifactVault:
    """Content-addressed artifact bytes on disk: one ``<hex>.zip`` per
    ``sha256:<hex>`` digest, admitted atomically.

    The vault stores bytes, full stop - it never interprets manifests or
    runs code (that is the publish prober's job, sandboxed, later). The
    only shape check is "is this a zip archive at all", which keeps the
    vault from becoming a generic authenticated blob host without
    duplicating admission's real validation.
    """

    def __init__(self, root: Path | str) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def path_of(self, digest_hex: str) -> Path | None:
        """The stored archive for a digest's hex half, or None."""
        if re.fullmatch(r"[0-9a-f]{64}", digest_hex) is None:
            raise RegistryError("artifact digest hex must be exactly 64 lowercase hex characters")
        root = self._root.resolve()
        path = (root / f"{digest_hex}.zip").resolve()
        if not path.is_relative_to(root):
            raise RegistryError("artifact path escapes the vault root")
        return path if path.is_file() else None

    def has(self, digest_hex: str) -> bool:
        return self.path_of(digest_hex) is not None

    def admit(self, data: bytes) -> tuple[str, bool]:
        """Store ``data`` under its own digest; returns (digest, created).

        Idempotent: identical bytes land once, ever. Atomic: a crash
        mid-write leaves a temp file, never a half-written final path -
        readers only ever see complete artifacts.
        """
        digest = artifact_digest(data)
        final = self._root / f"{digest.partition(':')[2]}.zip"
        if final.is_file():
            return digest, False
        fd, tmp_name = tempfile.mkstemp(dir=self._root, suffix=".part")
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, final)
        except BaseException:
            tmp.unlink(missing_ok=True)
            raise
        return digest, True


def _json_error(status: int, message: str) -> web.HTTPException:
    exceptions: dict[int, type[web.HTTPException]] = {
        400: web.HTTPBadRequest,
        401: web.HTTPUnauthorized,
        403: web.HTTPForbidden,
        404: web.HTTPNotFound,
        409: web.HTTPConflict,
        422: web.HTTPUnprocessableEntity,
        501: web.HTTPNotImplemented,
    }
    headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
    return exceptions[status](
        text=json.dumps({"error": message}),
        content_type="application/json",
        headers=headers,
    )


def _authenticate(request: web.Request) -> TokenRecord:
    """Resolve the bearer token or refuse with ONE indistinguishable 401.

    The pure model already refuses unknown/revoked/expired/orphaned
    tokens with distinct reasons for its own audit purposes; the wire
    deliberately flattens them so credential probing learns nothing.
    """
    header = request.headers.get("Authorization", "")
    scheme, _, credential = header.partition(" ")
    credential = credential.strip()
    if scheme != "Bearer" or not credential:
        raise _json_error(401, "unauthorized")
    store = request.app[STORE_KEY]
    at = request.app[CLOCK_KEY]()
    try:
        return store.verify_token(credential, at)
    except RegistryError:
        raise _json_error(401, "unauthorized") from None


async def _json_object(request: web.Request, what: str) -> dict[str, object]:
    try:
        decoded: object = await request.json()
    except json.JSONDecodeError:
        raise _json_error(400, f"{what} body must be a JSON object") from None
    if not isinstance(decoded, dict):
        raise _json_error(400, f"{what} body must be a JSON object")
    return cast("dict[str, object]", decoded)


def _token_wire(token: TokenRecord) -> dict[str, object]:
    """Administrative token metadata. The secret hash stays at rest."""
    return {
        "id": token.token_id,
        "publisher": token.publisher,
        "mintedBy": token.minted_by,
        "pack": token.pack,
        "createdAt": token.created_at,
        "expiresAt": token.expires_at,
        "revoked": token.revoked,
        "revokedReason": token.revoked_reason,
    }


async def handle_tokens(request: web.Request) -> web.Response:
    """List this token's publisher credentials. Publisher owners only."""
    token = _authenticate(request)
    if token.pack is not None:
        raise _json_error(403, "token administration requires an unscoped token")
    try:
        records = request.app[STORE_KEY].administered_tokens(token.publisher, token.minted_by)
    except RegistryError as exc:
        raise _json_error(403, str(exc)) from None
    return web.json_response({"tokens": [_token_wire(record) for record in records]})


async def handle_token_revoke(request: web.Request) -> web.Response:
    """Revoke a token immediately. A minter may revoke their own token;
    publisher owners may revoke any token, matching the principal model."""
    token = _authenticate(request)
    body = await _json_object(request, "token revocation")
    reason = body.get("reason")
    if not isinstance(reason, str) or not reason:
        raise _json_error(400, "token revocation requires a non-empty reason string")
    target = request.match_info["token_id"]
    if token.pack is not None and target != token.token_id:
        raise _json_error(403, "token revocation forbidden")
    try:
        request.app[STORE_KEY].revoke_token(
            target, token.minted_by, request.app[CLOCK_KEY](), reason
        )
    except RegistryError:
        raise _json_error(403, "token revocation forbidden") from None
    return web.json_response({"revoked": target})


def _artifact_hex(request: web.Request, *, status: int) -> str:
    name = request.match_info["file"]
    if not _ARTIFACT_FILE_RE.fullmatch(name):
        raise _json_error(status, "artifact path must be /artifacts/<64 lowercase hex>.zip")
    return name.removesuffix(".zip")


async def handle_artifact_download(request: web.Request) -> web.Response:
    """Content-addressed bytes back, immutable-cache headers. Unknown and
    malformed digests are both plain 404s (no probing contract)."""
    digest_hex = _artifact_hex(request, status=404)
    path = request.app[VAULT_KEY].path_of(digest_hex)
    if path is None:
        raise _json_error(404, "no such artifact")
    etag = f'"sha256:{digest_hex}"'
    if any(tag.value in (f"sha256:{digest_hex}", "*") for tag in (request.if_none_match or ())):
        return web.Response(status=304, headers={"ETag": etag})
    data = await asyncio.to_thread(path.read_bytes)
    return web.Response(
        body=data,
        content_type="application/zip",
        headers={
            "ETag": etag,
            "Cache-Control": "public, max-age=31536000, immutable",
        },
    )


async def handle_artifact_upload(request: web.Request) -> web.Response:
    """Authenticated, digest-verified upload. The declared digest in the
    path is a claim; the vault stores under the digest of the ACTUAL
    bytes, and a mismatch refuses without landing anything. Any valid
    token may upload - bytes are inert until a publish admission binds
    them, and content addressing means nothing can be clobbered."""
    _authenticate(request)
    declared_hex = _artifact_hex(request, status=400)
    data = await request.read()
    if not zipfile.is_zipfile(io.BytesIO(data)):
        raise _json_error(400, "artifact bytes are not a zip archive")
    digest = artifact_digest(data)
    if digest.partition(":")[2] != declared_hex:
        raise _json_error(
            400,
            f"digest mismatch: path declares sha256:{declared_hex} "
            f"but the uploaded bytes are {digest}; nothing was stored",
        )
    vault = request.app[VAULT_KEY]
    _, created = await asyncio.to_thread(vault.admit, data)
    return web.json_response({"digest": digest}, status=201 if created else 200)


# -- index: the read side admission built -----------------------------------


def _encode_cursor(query: str, after: str) -> str:
    """Opaque, query-bound keyset cursor (the collection contract; local
    mirror of dinkster_server/paging.py, whose package this one cannot
    import). ``after`` is the last page's final pack name."""
    payload = json.dumps({"q": query, "a": after})
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=")


def _decode_cursor(cursor: str, query: str) -> str:
    """The keyset position - if the cursor was minted for exactly this
    query. Tampered, malformed, and query-mismatched cursors are 400."""
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        data: object = json.loads(base64.urlsafe_b64decode(padded))
        if not isinstance(data, dict):
            raise TypeError("cursor must be an object")
        fields = cast("dict[object, object]", data)
        bound, after = str(fields["q"]), str(fields["a"])
    except (ValueError, KeyError, TypeError, binascii.Error) as exc:
        raise _json_error(400, "malformed cursor") from exc
    if bound != query:
        raise _json_error(400, "cursor does not match this query")
    return after


def _template_wire(template: ReleaseTemplate) -> dict[str, object]:
    """One template descriptor on the wire - the same shape the composed
    server's /api/templates serves, so a client browses installed and
    registry templates with one vocabulary. ``path`` stays internal: it
    locates bytes inside the artifact and never rides a descriptor."""
    wire: dict[str, object] = {"id": template.id, "name": template.name}
    if template.description:
        wire["description"] = template.description
    if template.tags:
        wire["tags"] = list(template.tags)
    if template.assets:
        wire["assets"] = list(template.assets)
    wire["digest"] = template.digest
    return wire


def _release_wire(release: Release) -> dict[str, object]:
    return {
        "version": release.version,
        "artifactDigest": release.artifact_digest,
        "publisher": release.publisher,
        "claims": list(release.claims),
        "nodeTypes": list(release.node_types),
        "templates": [_template_wire(template) for template in release.templates],
    }


def _releases_by_pack(store: RegistryStore) -> dict[str, list[Release]]:
    grouped: dict[str, list[Release]] = {}
    for release in store.releases():
        if store.yank_reason(release.pack, release.version) is not None:
            continue
        grouped.setdefault(release.pack, []).append(release)
    for versions in grouped.values():
        versions.sort(key=lambda r: Version.parse(r.version), reverse=True)
    return grouped


def _matches(query: str, pack: str, versions: list[Release]) -> bool:
    """Substring match on the pack name or any probed node type - the
    index searches what the registry saw load, so 'find the pack that
    ships node X' works from provenance, not marketing text."""
    if not query:
        return True
    if query in pack:
        return True
    return any(
        query in node_type.casefold() for release in versions for node_type in release.node_types
    )


async def handle_index_packs(request: web.Request) -> web.Response:
    """One entry per pack, name-ascending, keyset-paged. Unauthenticated
    like downloads: the index is the public face of the corpus."""
    query = request.query.get("q", "").strip().lower()
    try:
        limit = min(200, max(1, int(request.query.get("limit", "50"))))
    except ValueError:
        raise _json_error(400, "limit must be an integer") from None
    after = ""
    cursor = request.query.get("cursor", "")
    if cursor:
        after = _decode_cursor(cursor, query)
    grouped = await asyncio.to_thread(_releases_by_pack, request.app[STORE_KEY])
    names = sorted(
        pack
        for pack, versions in grouped.items()
        if pack > after and _matches(query, pack, versions)
    )
    page = names[:limit]
    wire: dict[str, object] = {
        "packs": [
            {
                "pack": pack,
                "publisher": grouped[pack][0].publisher,
                "latestVersion": grouped[pack][0].version,
                "versions": len(grouped[pack]),
            }
            for pack in page
        ]
    }
    if len(names) > limit:
        wire["cursor"] = _encode_cursor(query, page[-1])
    return web.json_response(wire)


def _template_matches(template: ReleaseTemplate, text: str, tag: str) -> bool:
    """Mirror of the composed server's template matching: q= is a
    substring over id/name/description/tags, tag= is an exact tag."""
    if tag and tag not in template.tags:
        return False
    if not text:
        return True
    hay = (template.id, template.name, template.description, *template.tags)
    return any(text in value.lower() for value in hay)


async def handle_index_templates(request: web.Request) -> web.Response:
    """The remote template catalog: browse starter workflows from packs
    you have NOT installed. One row per template of each pack's LATEST
    release (browse answers "what would I get today", exact versions
    ride the release document), ordered by qualified pack/id with the
    same query-bound keyset cursor every Dinkster listing speaks. Bodies
    never ride the listing - they hang off the release's template
    endpoint, digest-pinned."""
    text = request.query.get("q", "").strip().lower()
    tag = request.query.get("tag", "")
    pack_filter = request.query.get("pack", "")
    try:
        limit = min(200, max(1, int(request.query.get("limit", "50"))))
    except ValueError:
        raise _json_error(400, "limit must be an integer") from None
    bound = json.dumps({"q": text, "t": tag, "p": pack_filter}, sort_keys=True)
    after = ""
    cursor = request.query.get("cursor", "")
    if cursor:
        after = _decode_cursor(cursor, bound)
    grouped = await asyncio.to_thread(_releases_by_pack, request.app[STORE_KEY])
    # Collect-then-sort over the qualified "pack/template" id - the SAME
    # key the cursor carries, so resumption can never skip or repeat.
    rows: list[tuple[str, Release, ReleaseTemplate]] = []
    for pack, versions in grouped.items():
        if pack_filter and pack != pack_filter:
            continue
        latest = versions[0]
        for template in latest.templates:
            if not _template_matches(template, text, tag):
                continue
            qualified = f"{pack}/{template.id}"
            if after and qualified <= after:
                continue
            rows.append((qualified, latest, template))
    rows.sort(key=lambda row: row[0])
    wire: dict[str, object] = {
        "templates": [
            {"pack": release.pack, "version": release.version, **_template_wire(template)}
            for _, release, template in rows[:limit]
        ]
    }
    if len(rows) > limit:
        wire["cursor"] = _encode_cursor(bound, rows[limit - 1][0])
    return web.json_response(wire)


def _template_document_bytes(archive: Path, template: ReleaseTemplate) -> bytes:
    """The template's document bytes out of the release artifact,
    verified against the digest the probe recorded - the vault serving a
    release can never hand out bytes the descriptor didn't promise."""
    try:
        with zipfile.ZipFile(archive) as source:
            data = source.read(template.path)
    except (KeyError, OSError, zipfile.BadZipFile) as exc:
        raise _json_error(
            500, f"release artifact lost template member {template.path!r}: {exc}"
        ) from exc
    if ARTIFACT_DIGEST_PREFIX + hashlib.sha256(data).hexdigest() != template.digest:
        raise _json_error(500, "artifact bytes do not match the recorded template digest")
    return data


async def handle_index_release_template(request: web.Request) -> web.Response:
    """Template document bytes for one release descriptor - the same
    rendition contract as the composed server's template body endpoint:
    unknown release or template id is a plain 404, and bytes for a
    digest are immutable (quoted digest ETag, If-None-Match -> 304,
    forever cache lifetime)."""
    pack = canonical_name(request.match_info["pack"])
    version = request.match_info["version"]
    release = request.app[STORE_KEY].release(pack, version)
    if release is None:
        raise _json_error(404, f"no release {version} for pack {pack!r}")
    template_id = request.match_info["template_id"]
    template = next((entry for entry in release.templates if entry.id == template_id), None)
    if template is None:
        raise _json_error(404, "no such release template")
    etag = f'"{template.digest}"'
    if any(tag.value in (template.digest, "*") for tag in (request.if_none_match or ())):
        return web.Response(status=304, headers={"ETag": etag})
    archive = request.app[VAULT_KEY].path_of(release.artifact_digest.partition(":")[2])
    if archive is None:
        raise _json_error(404, "release artifact is not in this registry's vault")
    data = await asyncio.to_thread(_template_document_bytes, archive, template)
    return web.Response(
        body=data,
        content_type="application/json",
        headers={
            "ETag": etag,
            "Cache-Control": "public, max-age=31536000, immutable",
        },
    )


async def handle_index_pack(request: web.Request) -> web.Response:
    """Every release of one pack, newest first - a bounded detail
    document, not a paged listing (packs have few versions)."""
    pack = canonical_name(request.match_info["pack"])
    grouped = await asyncio.to_thread(_releases_by_pack, request.app[STORE_KEY])
    versions = grouped.get(pack)
    if versions is None:
        raise _json_error(404, f"no releases for pack {pack!r}")
    return web.json_response(
        {
            "pack": pack,
            "publisher": versions[0].publisher,
            "releases": [_release_wire(release) for release in versions],
        }
    )


async def handle_index_release(request: web.Request) -> web.Response:
    """Exact (pack, version) -> the release record: the resolution target
    for `dinkster-pack install pack@version`. The answer names the digest;
    acquisition stays digest-only and verifies the bytes, so this
    endpoint cannot substitute content even if it lies."""
    pack = canonical_name(request.match_info["pack"])
    release = request.app[STORE_KEY].release(pack, request.match_info["version"])
    if release is None:
        raise _json_error(404, f"no release {request.match_info['version']} for pack {pack!r}")
    response = web.json_response({"pack": pack, **_release_wire(release)})
    reason = request.app[STORE_KEY].yank_reason(pack, release.version)
    if reason is not None:
        quoted_reason = reason.replace("\\", "\\\\").replace('"', '\\"')
        response.headers["Warning"] = (
            f'299 Dinkster "release {pack}@{release.version} is yanked: {quoted_reason}"'
        )
    return response


def _verdict_wire(verdict: Verdict) -> dict[str, object]:
    """The admission answer on the wire: the full report, never a bare
    status - findings carry the same severity/code/message/fix vocabulary
    the doctor and pack CI already speak."""
    return {
        "state": verdict.state,
        "alreadyPublished": verdict.already_published,
        "newClaims": list(verdict.new_claims),
        "findings": [
            {
                "severity": finding.severity,
                "code": finding.code,
                "message": finding.message,
                "fix": finding.fix,
            }
            for finding in verdict.findings
        ],
    }


async def handle_publish(request: web.Request) -> web.Response:
    """One publish attempt over the wire. The request declares only the
    version and the artifact digest; the registry reads pack name and
    namespace claims from its OWN probe of the vault bytes and feeds
    admission that probe's doctor report - the publisher asserts nothing
    admission trusts. Every verdict state answers 200 with the report
    (a rejection is a reasoned record, not a transport error); HTTP
    errors mean admission never ran: 404 artifact not uploaded, 422
    unprobeable bytes, 403 the token cannot publish this pack, 409 a
    different-bytes submission is already pending review."""
    token = _authenticate(request)
    prober = request.app[PROBER_KEY]
    if prober is None:
        raise _json_error(501, "this registry does not accept publishes (no probe configured)")
    body = await _json_object(request, "publish")
    version = body.get("version")
    digest = body.get("artifactDigest")
    if not isinstance(version, str) or not isinstance(digest, str):
        raise _json_error(400, "publish requires version and artifactDigest strings")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise _json_error(
            400, "artifactDigest must be sha256: followed by 64 lowercase hex characters"
        )
    archive = request.app[VAULT_KEY].path_of(digest.partition(":")[2])
    if archive is None:
        raise _json_error(404, f"artifact {digest} is not in the vault; upload it first")
    try:
        probed = await asyncio.to_thread(prober, archive)
        evidence = DoctorEvidence.from_report_json(probed.report_json)
    except (ProbeError, RegistryError) as exc:
        raise _json_error(422, f"artifact could not be probed as a pack: {exc}") from None
    store = request.app[STORE_KEY]
    try:
        store.authorize_token(token, token.publisher, probed.pack_name)
        store.authorize(token.minted_by, token.publisher, "publish")
    except RegistryError as exc:
        raise _json_error(403, str(exc)) from None
    submission = Submission(
        publisher=token.publisher,
        pack_name=probed.pack_name,
        namespaces=probed.namespaces,
        version=version,
        artifact_digest=digest,
        evidence=evidence,
        templates=probed.templates,
        executes=probed.executes,
    )
    at = request.app[CLOCK_KEY]()
    try:
        verdict = await asyncio.to_thread(store.publish, submission, token.minted_by, at)
    except RegistryError as exc:
        raise _json_error(409, str(exc)) from None
    return web.json_response(_verdict_wire(verdict))


async def handle_release_yank(request: web.Request) -> web.Response:
    """Yank a release. Publisher owners only; exact records remain for
    reproducibility while browse/new resolution excludes them."""
    token = _authenticate(request)
    body = await _json_object(request, "release yank")
    reason = body.get("reason")
    if (
        not isinstance(reason, str)
        or not reason
        or len(reason) > MAX_YANK_REASON_CHARS
        or not reason.isascii()
        or not reason.isprintable()
    ):
        raise _json_error(
            400,
            f"release yank requires 1-{MAX_YANK_REASON_CHARS} printable ASCII characters",
        )
    pack = canonical_name(request.match_info["pack"])
    version = request.match_info["version"]
    store = request.app[STORE_KEY]
    release = store.release(pack, version)
    if release is None:
        raise _json_error(404, f"no release {version} for pack {pack!r}")
    try:
        store.authorize_token(token, release.publisher, pack)
        store.yank_release(pack, version, token.minted_by, request.app[CLOCK_KEY](), reason)
    except RegistryError as exc:
        raise _json_error(403, str(exc)) from None
    return web.json_response({"pack": pack, "version": version, "state": "yanked"})


async def handle_review_resolve(request: web.Request) -> web.Response:
    """Resolve a pending admission. Registry operators only."""
    token = _authenticate(request)
    if token.pack is not None:
        raise _json_error(403, "review resolution requires an unscoped token")
    body = await _json_object(request, "review resolution")
    decision = body.get("decision")
    reason = body.get("reason", "")
    if decision not in ("accepted", "rejected") or not isinstance(reason, str):
        raise _json_error(
            400, "review resolution requires decision accepted/rejected and an optional reason"
        )
    if decision == "rejected" and not reason:
        raise _json_error(400, "rejecting a review requires a non-empty reason")
    store = request.app[STORE_KEY]
    if not store.is_operator(token.minted_by):
        raise _json_error(403, f"user {token.minted_by!r} is not a registry operator")
    try:
        verdict = await asyncio.to_thread(
            store.resolve_review,
            request.match_info["pack"],
            request.match_info["version"],
            decision,
            token.minted_by,
            request.app[CLOCK_KEY](),
            reason,
        )
    except RegistryError as exc:
        raise _json_error(409, str(exc)) from None
    return web.json_response(_verdict_wire(verdict))


def create_registry_app(
    store: RegistryStore,
    vault: ArtifactVault,
    *,
    clock: Clock = utc_now,
    prober: Prober | None = None,
    max_artifact_bytes: int = DEFAULT_MAX_ARTIFACT_BYTES,
) -> web.Application:
    """The registry service HTTP app: artifact download/upload plus
    publish admission when a prober is configured; the index API
    composes onto the same app next. Oversize uploads refuse with
    aiohttp's own 413 via ``client_max_size`` - the body is never
    buffered past the cap."""
    app = web.Application(client_max_size=max_artifact_bytes)
    app[STORE_KEY] = store
    app[VAULT_KEY] = vault
    app[CLOCK_KEY] = clock
    app[PROBER_KEY] = prober
    app.router.add_get("/artifacts/{file}", handle_artifact_download)
    app.router.add_put("/artifacts/{file}", handle_artifact_upload)
    app.router.add_post("/publish", handle_publish)
    app.router.add_get("/tokens", handle_tokens)
    app.router.add_post("/tokens/{token_id}/revoke", handle_token_revoke)
    app.router.add_post("/releases/{pack}/versions/{version}/yank", handle_release_yank)
    app.router.add_post("/reviews/{pack}/versions/{version}/resolve", handle_review_resolve)
    app.router.add_get("/index/packs", handle_index_packs)
    app.router.add_get("/index/packs/{pack}", handle_index_pack)
    app.router.add_get("/index/packs/{pack}/versions/{version}", handle_index_release)
    app.router.add_get("/index/templates", handle_index_templates)
    app.router.add_get(
        "/index/packs/{pack}/versions/{version}/templates/{template_id}",
        handle_index_release_template,
    )
    return app


__all__ = [
    "DEFAULT_MAX_ARTIFACT_BYTES",
    "ArtifactVault",
    "Clock",
    "ProbeError",
    "ProbeResult",
    "Prober",
    "create_registry_app",
    "utc_now",
]
