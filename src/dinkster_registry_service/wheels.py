from __future__ import annotations

import base64
import csv
import hashlib
import io
import re
import stat
import tempfile
import unicodedata
import zipfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

from packaging.requirements import Requirement
from packaging.tags import Tag, parse_tag
from packaging.utils import canonicalize_name, parse_wheel_filename
from packaging.version import Version

from .artifacts import ARCHIVE_LIMIT, ENTRY_LIMIT, EXPANDED_LIMIT, FILE_LIMIT, PATH_BYTE_LIMIT


class WheelError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class Wheel:
    name: str
    version: str
    filename: str
    sha256: str
    imports: tuple[str, ...]
    requirements: tuple[str, ...]
    manifest_path: str | None
    tags: frozenset[Tag]

    @property
    def library(self) -> bool:
        return self.manifest_path is None


def _invalid(message: str) -> WheelError:
    return WheelError("wheel.invalid", message)


def _members(archive: zipfile.ZipFile) -> dict[str, bytes]:
    infos = archive.infolist()
    if len(infos) > ENTRY_LIMIT or sum(info.file_size for info in infos) > EXPANDED_LIMIT:
        raise _invalid("Wheel exceeds expanded size or entry count limits.")
    seen: set[str] = set()
    files: dict[str, bytes] = {}
    for info in infos:
        name = info.filename
        path = PurePosixPath(name)
        if (
            not name
            or name.startswith("/")
            or "\\" in name
            or ":" in name
            or any(ord(char) < 32 for char in name)
            or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
            or name != unicodedata.normalize("NFC", name)
            or len(name.encode("utf-8")) > PATH_BYTE_LIMIT
            or info.file_size > FILE_LIMIT
            or info.flag_bits & 1
            or stat.S_IFMT(info.external_attr >> 16) not in {0, stat.S_IFREG, stat.S_IFDIR}
        ):
            raise _invalid(f"Unsafe wheel member: {name!r}.")
        folded = name.rstrip("/").casefold()
        if folded in seen:
            raise _invalid(f"Duplicate wheel member: {name!r}.")
        seen.add(folded)
        if path.suffix.casefold() == ".pth":
            raise WheelError("wheel.pth-forbidden", f"Wheel contains a .pth file: {name!r}.")
        if path.name.casefold() == "entry_points.txt" or (
            path.parts[0].endswith(".data") and "scripts" in path.parts[1:]
        ):
            raise WheelError(
                "wheel.entry-point-forbidden", "Wheel entry points and scripts are forbidden."
            )
        if info.is_dir():
            continue
        if path.parts[0].endswith(".data"):
            raise _invalid("Wheel files must install directly, without .data relocation.")
        files[name] = archive.read(info)
    for name in files:
        if any(str(parent) in files for parent in PurePosixPath(name).parents):
            raise _invalid("Wheel contains a file that is also a directory.")
    return files


def _verify_record(files: dict[str, bytes], dist_info: str) -> None:
    record_path = f"{dist_info}/RECORD"
    if record_path not in files:
        raise _invalid("Wheel has no RECORD.")
    records: set[str] = set()
    for row in csv.reader(io.StringIO(files[record_path].decode("utf-8"))):
        if len(row) != 3:
            raise _invalid("Wheel RECORD rows must have three fields.")
        path, digest, size = row
        if path in records or path not in files:
            raise _invalid("Wheel RECORD contains duplicate or absent files.")
        records.add(path)
        if path == record_path:
            if digest or size:
                raise _invalid("Wheel RECORD must not hash itself.")
            continue
        algorithm, separator, encoded = digest.partition("=")
        if not separator or algorithm not in {"sha256", "sha384", "sha512"}:
            raise _invalid("Every wheel file requires a secure RECORD hash.")
        expected = base64.urlsafe_b64encode(
            hashlib.new(algorithm, files[path]).digest()
        ).rstrip(b"=").decode("ascii")
        if encoded != expected or size != str(len(files[path])):
            raise _invalid(f"Wheel RECORD does not match {path!r}.")
    unsigned = set(files) - {f"{dist_info}/RECORD.jws", f"{dist_info}/RECORD.p7s"}
    if records != unsigned:
        raise _invalid("Wheel RECORD does not cover exactly the installed files.")


def inspect_wheel(data: bytes, name: str, version: str) -> Wheel:
    """Validate installable bytes without importing code or extracting untrusted paths."""
    try:
        return _inspect_wheel(data, name, version)
    except WheelError:
        raise
    except (ValueError, KeyError, UnicodeError, csv.Error, zipfile.BadZipFile) as exc:
        raise _invalid(str(exc)) from exc


def _inspect_wheel(data: bytes, name: str, version: str) -> Wheel:
    if not 1 <= len(data) <= ARCHIVE_LIMIT:
        raise _invalid("Wheel exceeds the artifact size limit.")
    if not zipfile.is_zipfile(io.BytesIO(data)):
        raise WheelError("wheel.required", "Only wheel artifacts are accepted.")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files = _members(archive)
    roots = {path.split("/", 1)[0] for path in files}
    dist_infos = {root for root in roots if root.endswith(".dist-info")}
    if not dist_infos:
        raise WheelError("wheel.required", "The Dinkster ZIP format is not a wheel.")
    if len(dist_infos) != 1:
        raise _invalid("Wheel must contain exactly one .dist-info directory.")
    dist_info = dist_infos.pop()
    metadata = BytesParser(policy=policy.default).parsebytes(files[f"{dist_info}/METADATA"])
    wheel = BytesParser(policy=policy.default).parsebytes(files[f"{dist_info}/WHEEL"])
    for field in ("Name", "Version", "Metadata-Version"):
        if len(metadata.get_all(field, [])) != 1:
            raise _invalid(f"Wheel metadata requires exactly one {field}.")
    if str(metadata["Name"]) != name:
        raise WheelError("wheel.distribution-name", "Wheel Name must equal the submitted name.")
    if str(metadata["Version"]) != version or str(Version(version)) != version:
        raise _invalid("Wheel Version must equal the normalized submitted version.")
    distribution = re.sub(r"[-_.]+", "_", name)
    if dist_info != f"{distribution}-{version}.dist-info":
        raise _invalid("Wheel .dist-info directory differs from its metadata identity.")
    if wheel.get("Wheel-Version") != "1.0" or wheel.get("Root-Is-Purelib") not in {"true", "false"}:
        raise _invalid("Wheel requires supported WHEEL metadata.")
    tags = frozenset(tag for value in wheel.get_all("Tag", []) for tag in parse_tag(str(value)))
    if not tags:
        raise _invalid("Wheel must declare compatibility tags.")
    build = str(wheel.get("Build", ""))
    filename = f"{distribution}-{version}-" + (f"{build}-" if build else "")
    filename += "-".join(
        ".".join(sorted({getattr(tag, field) for tag in tags}))
        for field in ("interpreter", "abi", "platform")
    ) + ".whl"
    parsed_name, parsed_version, _, parsed_tags = parse_wheel_filename(filename)
    if parsed_name != canonicalize_name(name) or parsed_version != Version(version) or parsed_tags != tags:
        raise _invalid("Wheel tags cannot be represented by its filename.")
    _verify_record(files, dist_info)
    imports: set[str] = set()
    for root in roots - {dist_info}:
        if "/" in next(path for path in files if path.split("/", 1)[0] == root):
            import_name = root
        elif root.endswith((".py", ".so", ".pyd")):
            import_name = root.split(".", 1)[0]
        else:
            continue
        if not import_name.isidentifier() or not import_name.isascii():
            raise _invalid(f"Invalid top-level import name: {import_name!r}.")
        imports.add(import_name)
    manifests = [path for path in files if PurePosixPath(path).name == "dinkster-pack.toml"]
    if len(manifests) > 1:
        raise _invalid("Wheel contains multiple pack manifests.")
    manifest_path = manifests[0] if manifests else None
    if manifest_path is not None:
        expected_import = name.replace("-", "_").replace(".", "_")
        if manifest_path != f"{expected_import}/dinkster-pack.toml":
            raise _invalid("Pack manifest must be inside its top-level import package.")
        if imports != {expected_import} or not any(
            path.startswith(f"{expected_import}/") for path in files
        ):
            raise WheelError(
                "wheel.import-name", f"Pack must ship only the {expected_import!r} import package."
            )
    requirements = tuple(str(value) for value in metadata.get_all("Requires-Dist", []))
    for requirement in requirements:
        Requirement(requirement)
    return Wheel(
        name, version, filename, hashlib.sha256(data).hexdigest(), tuple(sorted(imports)),
        requirements, manifest_path, tags,
    )


@contextmanager
def extracted_wheel(data: bytes, wheel: Wheel) -> Iterator[Path]:
    """Expose installed imports and manifest-relative assets to the existing probe."""
    with tempfile.TemporaryDirectory(prefix="registry-wheel-probe-") as temporary:
        root = Path(temporary)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name, payload in _members(archive).items():
                destination = root / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)
            if wheel.manifest_path is not None:
                package = PurePosixPath(wheel.manifest_path).parent
                # The trusted probe takes a root manifest. Only its private view
                # relocates assets; the admitted and installed wheel stays intact.
                for name in archive.namelist():
                    path = PurePosixPath(name)
                    if not path.is_relative_to(package) or name.endswith("/"):
                        continue
                    relative = path.relative_to(package)
                    if relative.suffix in {".py", ".so", ".pyd", ".pyc"}:
                        continue
                    destination = root / relative
                    if destination.exists():
                        raise _invalid("Pack assets collide with installed wheel files.")
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(archive.read(name))
        yield root
