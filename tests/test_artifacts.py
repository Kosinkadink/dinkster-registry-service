from __future__ import annotations

import zipfile
from pathlib import Path

import pytest
from blake3 import blake3

from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.digests import DigestError, artifact_digest, require_blake3_digest
from dinkster_registry_service.object_store import (
    MAX_ARTIFACT_SIZE,
    LocalFilesystemObjectStore,
    ObjectStoreError,
)
from dinkster_registry_service.seed import FIXTURE_ROOT


def test_blake3_known_vector_and_algorithm_rejection() -> None:
    assert artifact_digest(b"") == "blake3:" + blake3(b"").hexdigest()
    with pytest.raises(DigestError, match="rebuild or reinstall"):
        require_blake3_digest("sha256:" + "0" * 64)
    with pytest.raises(DigestError, match="64 lowercase hex"):
        require_blake3_digest("blake3:" + "A" * 64)


def test_fixture_archive_is_deterministic_and_canonical(tmp_path: Path) -> None:
    first = build_registry_fixture_archive(FIXTURE_ROOT / "example-pack")
    second = build_registry_fixture_archive(FIXTURE_ROOT / "example-pack")
    assert first == second
    assert artifact_digest(first) == artifact_digest(second)

    path = tmp_path / "fixture.zip"
    path.write_bytes(first)
    with zipfile.ZipFile(path) as archive:
        assert archive.namelist() == sorted(archive.namelist())
        assert archive.comment == b""
        assert all(info.compress_type == zipfile.ZIP_STORED for info in archive.infolist())
        assert all(info.date_time == (1980, 1, 1, 0, 0, 0) for info in archive.infolist())
        assert all(info.external_attr == 0o644 << 16 for info in archive.infolist())


def test_object_store_reads_with_declared_size_digest_and_hard_cap(tmp_path: Path) -> None:
    store = LocalFilesystemObjectStore(tmp_path / "objects")
    key = "fixture/object"
    data = b"fixture bytes"
    digest = artifact_digest(data)
    store.put(key, data)

    assert b"".join(store.open(key, expected_size=len(data), expected_digest=digest)) == data

    path = store.root / key
    path.write_bytes(data + b"x")
    with pytest.raises(ObjectStoreError, match="exceeds its declared size"):
        store.open(key, expected_size=len(data), expected_digest=digest)

    with pytest.raises(ObjectStoreError, match="supported size range"):
        store.open(
            "not-opened",
            expected_size=MAX_ARTIFACT_SIZE + 1,
            expected_digest=digest,
        )
