from __future__ import annotations

import os
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any, BinaryIO, Protocol, cast

import boto3  # type: ignore[import-untyped]
from blake3 import blake3
from botocore.exceptions import BotoCoreError, ClientError  # type: ignore[import-untyped]

MAX_ARTIFACT_SIZE = 64 * 1024 * 1024
READ_CHUNK_SIZE = 64 * 1024
INDEX_KEYS = frozenset({"packs/index.json", "locales/index.json"})


class ObjectStoreError(RuntimeError):
    """Object bytes do not match immutable local storage."""


class StoredObject:
    def __init__(self, source: BinaryIO, size: int) -> None:
        self.source = source
        self.size = size
        self.closed = False

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
        self.closed = True


class ObjectStore(Protocol):
    def put(self, key: str, data: bytes) -> None: ...

    def replace_index(self, key: str, data: bytes) -> None: ...

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
        self._write(destination, data)

    def replace_index(self, key: str, data: bytes) -> None:
        _validate_index(key, data)
        self._write(self._path(key), data)

    @staticmethod
    def _write(destination: Path, data: bytes) -> None:
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


class S3ObjectStore:
    def __init__(
        self,
        *,
        endpoint_url: str,
        bucket: str,
        access_key_id: str,
        secret_access_key: str,
        region: str,
    ) -> None:
        self.bucket = bucket
        self._client: Any = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=region,
        )

    def put(self, key: str, data: bytes) -> None:
        if not 1 <= len(data) <= MAX_ARTIFACT_SIZE:
            raise ObjectStoreError(f"object size must be between 1 and {MAX_ARTIFACT_SIZE} bytes")
        try:
            self._client.put_object(Bucket=self.bucket, Key=key, Body=data, IfNoneMatch="*")
        except ClientError as error:
            if not self._is_precondition_failure(error):
                self._raise_storage_error(error)
        except BotoCoreError as error:
            self._raise_storage_error(error)
        else:
            return
        if not self._matches(key, data):
            raise ObjectStoreError(f"object {key!r} already exists with different bytes")

    def replace_index(self, key: str, data: bytes) -> None:
        _validate_index(key, data)
        try:
            self._client.put_object(
                Bucket=self.bucket,
                Key=key,
                Body=data,
                ContentType="application/json",
                CacheControl="public, max-age=60",
            )
        except (BotoCoreError, ClientError) as error:
            self._raise_storage_error(error)

    def read(self, key: str, *, max_size: int = MAX_ARTIFACT_SIZE) -> bytes:
        if max_size < 1:
            raise ObjectStoreError("object read limit must be positive")
        body = self._get_object(key)["Body"]
        try:
            data = cast(bytes, body.read(max_size + 1))
        finally:
            body.close()
        if len(data) > max_size:
            raise ObjectStoreError(f"object exceeds the {max_size}-byte read limit")
        return data

    def open(self, key: str, *, expected_size: int, expected_digest: str) -> StoredObject:
        if not 1 <= expected_size <= MAX_ARTIFACT_SIZE:
            raise ObjectStoreError("artifact metadata exceeds the supported size range")
        stored = self._get_object(key)
        body = stored["Body"]
        try:
            digest = blake3()
            remaining = expected_size
            while remaining:
                chunk = body.read(min(READ_CHUNK_SIZE, remaining))
                if not chunk:
                    raise ObjectStoreError("object is shorter than its declared size")
                digest.update(chunk)
                remaining -= len(chunk)
            if body.read(1):
                raise ObjectStoreError("object exceeds its declared size or the artifact size cap")
            if "blake3:" + digest.hexdigest() != expected_digest:
                raise ObjectStoreError("object digest differs from immutable artifact metadata")
        finally:
            body.close()
        return StoredObject(self._get_object(key, etag=stored["ETag"])["Body"], expected_size)

    def exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self.bucket, Key=key)
        except ClientError as error:
            if self._is_missing(error):
                return False
            self._raise_storage_error(error)
        except BotoCoreError as error:
            self._raise_storage_error(error)
        return True

    def remove(self, key: str) -> None:
        try:
            self._client.delete_object(Bucket=self.bucket, Key=key)
        except (BotoCoreError, ClientError) as error:
            self._raise_storage_error(error)

    def _matches(self, key: str, expected: bytes) -> bool:
        body = self._get_object(key)["Body"]
        try:
            offset = 0
            while chunk := body.read(READ_CHUNK_SIZE):
                if chunk != expected[offset : offset + len(chunk)]:
                    return False
                offset += len(chunk)
                if offset > len(expected):
                    return False
            return offset == len(expected)
        finally:
            body.close()

    def _get_object(self, key: str, *, etag: str | None = None) -> Any:
        try:
            conditions = {} if etag is None else {"IfMatch": etag}
            response = self._client.get_object(Bucket=self.bucket, Key=key, **conditions)
        except ClientError as error:
            if self._is_missing(error):
                raise FileNotFoundError(key) from None
            self._raise_storage_error(error)
        except BotoCoreError as error:
            self._raise_storage_error(error)
        return response

    @staticmethod
    def _is_missing(error: ClientError) -> bool:
        code = str(error.response.get("Error", {}).get("Code", ""))
        return code in {"404", "NoSuchKey", "NoSuchObject", "NotFound"}

    @staticmethod
    def _is_precondition_failure(error: ClientError) -> bool:
        code = str(error.response.get("Error", {}).get("Code", ""))
        return code in {"412", "PreconditionFailed", "ConditionalRequestConflict"}

    @staticmethod
    def _raise_storage_error(error: BotoCoreError | ClientError) -> None:
        del error
        raise ObjectStoreError("S3 object storage operation failed") from None


def _validate_index(key: str, data: bytes) -> None:
    if key not in INDEX_KEYS:
        raise ObjectStoreError("only public static indexes may be replaced")
    if not 1 <= len(data) <= MAX_ARTIFACT_SIZE:
        raise ObjectStoreError(f"index size must be between 1 and {MAX_ARTIFACT_SIZE} bytes")
