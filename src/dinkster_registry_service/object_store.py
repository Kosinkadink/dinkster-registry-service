from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO, Protocol

from blake3 import blake3

MAX_ARTIFACT_SIZE = 64 * 1024 * 1024
READ_CHUNK_SIZE = 64 * 1024


class ObjectStoreError(RuntimeError):
    """Object bytes do not match immutable local storage."""


class StoredObject:
    def __init__(self, source: BinaryIO, size: int) -> None:
        self.source = source
        self.size = size

    def __iter__(self) -> Iterator[bytes]:
        remaining = self.size
        try:
            while remaining:
                chunk = self.source.read(min(READ_CHUNK_SIZE, remaining))
                if not chunk:
                    raise ObjectStoreError("object changed after integrity verification")
                remaining -= len(chunk)
                yield chunk
            if self.source.read(1):
                raise ObjectStoreError("object changed after integrity verification")
        finally:
            self.close()

    def close(self) -> None:
        self.source.close()


class ObjectStore(Protocol):
    def put(self, key: str, data: bytes) -> None: ...

    def read(self, key: str, *, max_size: int = MAX_ARTIFACT_SIZE) -> bytes: ...

    def open(self, key: str, *, expected_size: int, expected_digest: str) -> StoredObject: ...

    def exists(self, key: str) -> bool: ...

    def remove(self, key: str) -> None: ...


class LocalFilesystemObjectStore:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    def _path(self, key: str) -> Path:
        path = (self.root / key).resolve()
        if not path.is_relative_to(self.root):
            raise ObjectStoreError("object key escapes the configured root")
        return path

    def put(self, key: str, data: bytes) -> None:
        if not 1 <= len(data) <= MAX_ARTIFACT_SIZE:
            raise ObjectStoreError(f"object size must be between 1 and {MAX_ARTIFACT_SIZE} bytes")
        destination = self._path(key)
        if destination.exists():
            if not self._matches(destination, data):
                raise ObjectStoreError(f"object {key!r} already exists with different bytes")
            return
        destination.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temporary:
            temporary.write(data)
            temporary.flush()
            os.fsync(temporary.fileno())
            temporary_path = Path(temporary.name)
        try:
            os.replace(temporary_path, destination)
        finally:
            temporary_path.unlink(missing_ok=True)

    def read(self, key: str, *, max_size: int = MAX_ARTIFACT_SIZE) -> bytes:
        if max_size < 1:
            raise ObjectStoreError("object read limit must be positive")
        with self._path(key).open("rb") as source:
            data = source.read(max_size + 1)
        if len(data) > max_size:
            raise ObjectStoreError(f"object exceeds the {max_size}-byte read limit")
        return data

    @staticmethod
    def _matches(path: Path, data: bytes) -> bool:
        offset = 0
        with path.open("rb") as source:
            while chunk := source.read(READ_CHUNK_SIZE):
                if chunk != data[offset : offset + len(chunk)]:
                    return False
                offset += len(chunk)
                if offset > len(data):
                    return False
        return offset == len(data)

    def open(self, key: str, *, expected_size: int, expected_digest: str) -> StoredObject:
        if not 1 <= expected_size <= MAX_ARTIFACT_SIZE:
            raise ObjectStoreError("artifact metadata exceeds the supported size range")
        source = self._path(key).open("rb")
        try:
            digest = blake3()
            remaining = expected_size
            while remaining:
                chunk = source.read(min(READ_CHUNK_SIZE, remaining))
                if not chunk:
                    raise ObjectStoreError("object is shorter than its declared size")
                digest.update(chunk)
                remaining -= len(chunk)
            if source.read(1):
                raise ObjectStoreError("object exceeds its declared size or the artifact size cap")
            if "blake3:" + digest.hexdigest() != expected_digest:
                raise ObjectStoreError("object digest differs from immutable artifact metadata")
            source.seek(0)
            return StoredObject(source, expected_size)
        except BaseException:
            source.close()
            raise

    def exists(self, key: str) -> bool:
        return self._path(key).is_file()

    def remove(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)
