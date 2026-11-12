from __future__ import annotations

import hashlib
import json
import re
from email.message import Message
from pathlib import Path
from typing import IO, NoReturn
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from packaging.utils import InvalidWheelFilename, parse_wheel_filename
from packaging.version import Version

MAX_ENGINE_METADATA = 4 * 1024 * 1024
MAX_API_WHEEL = 32 * 1024 * 1024
ENGINE_ORIGIN = "https://releases.dinkster.org"


class ScanEngineError(ValueError):
    """A scan engine binding does not identify exact trusted release bytes."""


def parse_scan_engine(data: bytes | None) -> dict[str, str] | None:
    if data is None:
        return None
    if not 1 <= len(data) <= 1024:
        raise ScanEngineError("engine binding must contain 1 through 1024 bytes")
    try:
        record = _metadata(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise ScanEngineError("engine binding must be valid JSON with unique fields") from exc
    if not isinstance(record, dict) or set(record) != {"commit", "manifestDigest"}:
        raise ScanEngineError("engine binding requires commit and manifestDigest")
    commit, digest = record["commit"], record["manifestDigest"]
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ScanEngineError("engine binding requires a full Git commit")
    if not isinstance(digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", digest) is None:
        raise ScanEngineError("engine binding requires an exact sha256 manifest digest")
    return {"commit": commit, "manifestDigest": digest}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: IO[bytes], code: int, msg: str, headers: Message, newurl: str
    ) -> NoReturn:
        raise ScanEngineError("engine downloads must remain at the trusted release origin")


def _read_release(path: str, limit: int) -> bytes:
    request = Request(
        f"{ENGINE_ORIGIN}/{path}", headers={"User-Agent": "dinkster-registry-service/1"}
    )
    with build_opener(_NoRedirect()).open(request, timeout=30) as response:
        data: bytes = response.read(limit + 1)
    if len(data) > limit:
        raise ScanEngineError("engine release input exceeds its size bound")
    return data


def _metadata(data: bytes) -> object:
    def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ScanEngineError("duplicate engine release metadata field")
            result[key] = value
        return result

    return json.loads(data, object_pairs_hook=unique)


def stage_scan_api(
    binding: dict[str, str], directory: Path, *, development_release: Path | None = None
) -> tuple[Path, str]:
    """Acquire exact trusted API bytes without importing or installing them on the host."""
    release_path = None
    index_version = None
    if development_release is None:
        index = _metadata(_read_release("engine/index.json", MAX_ENGINE_METADATA))
        if not isinstance(index, list) or any(not isinstance(row, dict) for row in index):
            raise ScanEngineError("engine index must contain release objects")
        matches = [row for row in index if row.get("commit") == binding["commit"]]
        if len(matches) != 1:
            raise ScanEngineError("engine index must identify exactly one matching commit")
        selected = matches[0]
        if "sha256:" + str(selected.get("sha256")) != binding["manifestDigest"]:
            raise ScanEngineError("engine index manifest identity mismatch")
        release_path = selected.get("path")
        if (
            not isinstance(release_path, str)
            or re.fullmatch(r"engine/[A-Za-z0-9][A-Za-z0-9._+-]*", release_path) is None
        ):
            raise ScanEngineError("invalid trusted engine release path")
        index_version = selected.get("version")

    def read(name: str, limit: int) -> bytes:
        if development_release is None:
            return _read_release(f"{release_path}/{quote(name, safe='')}", limit)
        source = development_release / name
        if source.resolve().parent != development_release.resolve():
            raise ScanEngineError("development engine input escapes its mounted directory")
        with source.open("rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ScanEngineError("development engine input exceeds its size bound")
        return data

    data = read("release-manifest.json", MAX_ENGINE_METADATA)
    if "sha256:" + hashlib.sha256(data).hexdigest() != binding["manifestDigest"]:
        raise ScanEngineError("engine manifest digest mismatch")
    manifest = _metadata(data)
    if (
        not isinstance(manifest, dict)
        or manifest.get("format") != "dinkster.engine/1"
        or manifest.get("repository") != "Kosinkadink/Dinkster"
        or manifest.get("commit") != binding["commit"]
        or not isinstance(manifest.get("version"), str)
    ):
        raise ScanEngineError("engine manifest identity mismatch")
    version = manifest["version"]
    Version(version)
    if development_release is None and index_version != version:
        raise ScanEngineError("engine index version mismatch")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list) or any(not isinstance(row, dict) for row in artifacts):
        raise ScanEngineError("engine manifest must contain artifact records")
    candidates = []
    for row in artifacts:
        name = row.get("name")
        if not isinstance(name, str) or not name.startswith("dinkster_api-"):
            continue
        try:
            distribution, wheel_version, _, tags = parse_wheel_filename(name)
        except InvalidWheelFilename as exc:
            raise ScanEngineError("invalid engine API wheel filename") from exc
        if (
            distribution != "dinkster-api"
            or wheel_version != Version(version)
            or any(tag.abi != "none" or tag.platform != "any" for tag in tags)
            or Path(name).name != name
            or "\\" in name
        ):
            raise ScanEngineError("engine API wheel identity mismatch")
        candidates.append(row)
    if len(candidates) != 1:
        raise ScanEngineError("engine release must identify one pure Python API wheel")
    artifact = candidates[0]
    size, sha = artifact.get("size"), artifact.get("sha256")
    if (
        type(size) is not int
        or not 1 <= size <= MAX_API_WHEEL
        or not isinstance(sha, str)
        or re.fullmatch(r"[0-9a-f]{64}", sha) is None
    ):
        raise ScanEngineError("engine API wheel size or digest is invalid")
    payload = read(artifact["name"], size)
    if len(payload) != size or hashlib.sha256(payload).hexdigest() != sha:
        raise ScanEngineError("engine API wheel bytes mismatch")
    target = directory / artifact["name"]
    target.write_bytes(payload)
    return target, version
