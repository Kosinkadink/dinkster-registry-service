from __future__ import annotations

import base64
import csv
import hashlib
import io
import re
import tomllib
import unicodedata
import zipfile
from pathlib import Path

from .digests import artifact_digest

ARCHIVE_LIMIT = 64 * 1024 * 1024
EXPANDED_LIMIT = 256 * 1024 * 1024
FILE_LIMIT = 64 * 1024 * 1024
ENTRY_LIMIT = 10_000
PATH_BYTE_LIMIT = 512
MANIFEST_LIMIT = 1024 * 1024
MANIFEST_NAME = "dinkster-pack.toml"
_SKIP_DIRECTORIES = frozenset(
    {".git", ".hg", ".svn", ".tox", ".venv", "__pycache__", "build", "dist", "node_modules"}
)
_ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
_FILE_MODE = 0o644 << 16


class ArtifactError(ValueError):
    """A fixture source cannot form a canonical Dinkster pack artifact."""


def _entries(source: Path) -> list[tuple[str, bytes]]:
    if not source.is_dir():
        raise ArtifactError(f"fixture source is not a directory: {source}")
    if not (source / MANIFEST_NAME).is_file():
        raise ArtifactError(f"fixture source has no root {MANIFEST_NAME}: {source}")

    entries: list[tuple[str, bytes]] = []
    casefolded_paths: set[str] = set()
    for path in source.rglob("*"):
        relative_parts = path.relative_to(source).parts
        if any(part in _SKIP_DIRECTORIES for part in relative_parts):
            continue
        if path.is_symlink():
            raise ArtifactError(f"symlinks are not allowed in artifacts: {path}")
        if not path.is_file():
            continue
        relative = unicodedata.normalize("NFC", path.relative_to(source).as_posix())
        if relative.startswith("/") or "\x00" in relative or ".." in Path(relative).parts:
            raise ArtifactError(f"artifact path is unsafe: {relative!r}")
        if len(relative.encode("utf-8")) > PATH_BYTE_LIMIT:
            raise ArtifactError(
                f"artifact path exceeds {PATH_BYTE_LIMIT} UTF-8 bytes: {relative!r}"
            )
        folded = relative.casefold()
        if folded in casefolded_paths:
            raise ArtifactError(f"artifact paths collide case-insensitively: {relative!r}")
        casefolded_paths.add(folded)
        payload = path.read_bytes()
        if len(payload) > FILE_LIMIT:
            raise ArtifactError(f"artifact file exceeds {FILE_LIMIT} bytes: {relative!r}")
        if relative == MANIFEST_NAME and len(payload) > MANIFEST_LIMIT:
            raise ArtifactError(f"artifact manifest exceeds {MANIFEST_LIMIT} bytes")
        entries.append((relative, payload))

    entries.sort(key=lambda item: item[0])
    if len(entries) > ENTRY_LIMIT:
        raise ArtifactError(f"artifact contains more than {ENTRY_LIMIT} entries")
    if sum(len(payload) for _, payload in entries) > EXPANDED_LIMIT:
        raise ArtifactError(f"artifact expands beyond {EXPANDED_LIMIT} bytes")
    return entries


def build_registry_fixture_archive(source: Path) -> bytes:
    manifest = (source / MANIFEST_NAME).read_text()
    pack = tomllib.loads(manifest)["pack"]
    name = pack["name"]
    version = pack.get("version", "1.2.3")
    package = name.replace("-", "_").replace(".", "_")
    dist = f"{package}-{version}.dist-info"
    entries = {f"{package}/{path}": data for path, data in _entries(source)}
    # The fixture sources keep short entry names for direct probe tests; a
    # published wheel binds those entries to its only installed package.
    manifest = re.sub(r'"nodes:', f'"{package}.nodes:', manifest)
    entries[f"{package}/{MANIFEST_NAME}"] = manifest.encode()
    entries.setdefault(f"{package}/__init__.py", b"")
    entries[f"{dist}/METADATA"] = (
        f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"
        + "".join(f"Requires-Dist: {value}\n" for value in pack.get("requires", []))
        + "\n"
    ).encode()
    entries[f"{dist}/WHEEL"] = (
        b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    )
    record = io.StringIO()
    writer = csv.writer(record, lineterminator="\n")
    for path, payload in sorted(entries.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        writer.writerow((path, f"sha256={digest}", len(payload)))
    writer.writerow((f"{dist}/RECORD", "", ""))
    entries[f"{dist}/RECORD"] = record.getvalue().encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for relative, payload in sorted(entries.items()):
            info = zipfile.ZipInfo(relative, date_time=_ZIP_EPOCH)
            info.create_system = 3
            info.external_attr = _FILE_MODE
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, payload)
    data = output.getvalue()
    if len(data) > ARCHIVE_LIMIT:
        raise ArtifactError(f"artifact exceeds {ARCHIVE_LIMIT} bytes")
    return data


def build_registry_fixture_archive_with_digests(source: Path) -> tuple[bytes, str, str]:
    data = build_registry_fixture_archive(source)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        path = next(name for name in archive.namelist() if name.endswith("/" + MANIFEST_NAME))
        manifest = archive.read(path)
    return data, artifact_digest(data), artifact_digest(manifest)
