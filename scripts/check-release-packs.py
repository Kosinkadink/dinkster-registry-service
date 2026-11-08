"""Admit an unchanged first-party wheel through the isolated production probe."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

from dinkster_registry_service.wheels import inspect_wheel


def verify_fixture(directory: Path, lock: dict[str, object]) -> Path:
    wheel = directory / str(lock["filename"])
    data = wheel.read_bytes()
    assert len(data) == lock["size"], "fixture size mismatch"
    assert hashlib.sha256(data).hexdigest() == lock["sha256"], "fixture hash mismatch"
    inspected = inspect_wheel(data, str(lock["name"]), str(lock["version"]))
    assert inspected.filename == wheel.name
    assert not inspected.library
    return wheel


def cli(*arguments: str) -> str:
    return subprocess.check_output(
        [sys.executable, "-m", "dinkster_registry_service.cli", *arguments], text=True
    ).strip()


def main() -> None:
    assert os.environ.get("DINKSTER_DATABASE_URL"), "a disposable migrated database is required"
    lock = json.loads(Path(__file__).with_name("release-packs.lock").read_bytes())
    wheel = verify_fixture(Path("fixtures/wheels"), lock)
    cli("admin", "add-user", "release-check")
    cli("admin", "add-publisher", "dinkster", "--owner", "release-check")
    candidate = cli(
        "submit",
        str(wheel),
        "--pack",
        lock["name"],
        "--version",
        lock["version"],
        "--publisher",
        "dinkster",
        "--submitted-by",
        "release-check",
    )
    for _ in range(4):
        cli("scanner", "--once")
        status = json.loads(cli("status", candidate))
        if status["status"] in {"accepted", "rejected", "review"}:
            break
    print(json.dumps(status, sort_keys=True), flush=True)
    assert status["status"] == "accepted", status
    root = Path(os.environ["DINKSTER_OBJECT_STORE_ROOT"])
    (entry,) = json.loads((root / "static/packs/index.json").read_bytes())["items"]
    (published,) = entry["wheels"]
    assert (entry["name"], entry["version"]) == (lock["name"], lock["version"])
    assert published["sha256"] == lock["sha256"]
    assert (root / "static" / published["url"]).read_bytes() == wheel.read_bytes()
    schemas = json.loads(
        (root / f"static/packs/{lock['name']}/{lock['version']}/schemas.json").read_bytes()
    )["schemas"]
    assert sorted(item["nodeType"] for item in schemas) == lock["nodeTypes"]
    print(f"accepted real wheel with {len(schemas)} node schemas", flush=True)


if __name__ == "__main__":
    main()
