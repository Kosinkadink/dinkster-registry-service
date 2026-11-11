import json
import runpy
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dinkster_registry_service.admission import AdmissionService
from dinkster_registry_service.database import Database
from dinkster_registry_service.object_store import LocalFilesystemObjectStore
from dinkster_registry_service.principals import PrincipalRepository
from dinkster_registry_service.wheels import WheelError


@pytest.mark.parametrize("damage", (None, "size", "sha256", "name", "version"))
def test_first_party_wheel_fixture_rejects_identity_or_hash_changes(damage: str | None) -> None:
    script = Path("scripts/check-release-packs.py")
    lock = json.loads(script.with_name("release-packs.lock").read_bytes())
    verify = runpy.run_path(str(script))["verify_fixture"]
    if damage is not None:
        lock[damage] = 1 if damage == "size" else "wrong"
        with pytest.raises((AssertionError, WheelError)):
            verify(Path("fixtures/wheels"), lock)
    else:
        assert verify(Path("fixtures/wheels"), lock).name == lock["filename"]


def test_real_wheel_accepts_reordered_dependency_specifiers(tmp_path: Path) -> None:
    lock = json.loads(Path("scripts/release-packs.lock").read_bytes())
    database = Database(f"sqlite:///{tmp_path / 'catalog.db'}")
    try:
        principals = PrincipalRepository(database)
        principals.register_user("operator")
        principals.register_publisher("dinkster", "operator", datetime.now(UTC).isoformat())
        store = LocalFilesystemObjectStore(tmp_path / "objects")
        service = AdmissionService(database, store, require_isolation=False)
        data = (Path("fixtures/wheels") / lock["filename"]).read_bytes()
        candidate = service.submit(
            data, pack_name=lock["name"], version=lock["version"], publisher="dinkster"
        )
        assert service.run_once()
        assert service.status(candidate).status == "accepted", service.status(candidate)
        assert service.run_once()
        (entry,) = json.loads(store.read("static/packs/index.json"))["items"]
        (entry,) = json.loads(store.read("static/" + entry["url"]))["items"]
        (wheel,) = entry["wheels"]
        assert wheel["sha256"] == lock["sha256"]
        assert store.read("static/" + wheel["url"]) == data
    finally:
        database.dispose()
