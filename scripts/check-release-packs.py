"""Admit an unchanged first-party wheel through the isolated production probe."""

from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from datetime import UTC, datetime, timedelta
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
    token = cli(
        "admin",
        "mint-token",
        "dinkster",
        "--user",
        "release-check",
        "--expires",
        (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
    )
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    origin = f"http://127.0.0.1:{port}"

    def request(path: str, data: bytes | None = None, *, authenticated: bool = False) -> bytes:
        headers = {"Authorization": f"Bearer {token}"} if authenticated else {}
        with urllib.request.urlopen(
            urllib.request.Request(origin + path, data=data, headers=headers), timeout=30
        ) as response:
            return response.read()

    server = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "dinkster_registry_service.cli",
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ]
    )
    try:
        deadline = time.monotonic() + 30
        while True:
            assert server.poll() is None, "HTTP server exited before readiness"
            try:
                request("/v1/health")
                break
            except urllib.error.URLError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)
        submitted = json.loads(
            request(
                f"/v1/publish/{lock['name']}/versions/{lock['version']}",
                wheel.read_bytes(),
                authenticated=True,
            )
        )
        candidate = submitted["candidateId"]
        assert submitted["status"] == "queued"
        for _ in range(4):
            cli("scanner", "--once")
            status = json.loads(request(f"/v1/publish/{candidate}", authenticated=True))
            if status["status"] in {"accepted", "rejected", "review"}:
                break
        assert status["status"] == "accepted", status
        cli("scanner", "--once")
        catalog = json.loads(request("/static/packs/index.json"))
        assert catalog["schemaVersion"] == 2
        (summary,) = catalog["items"]
        assert (summary["name"], summary["latestVersion"]) == (lock["name"], lock["version"])
        assert summary["url"] == f"packs/{lock['name']}/index.json"
        versions = json.loads(request("/static/" + summary["url"]))
        assert versions["schemaVersion"] == 2 and versions["name"] == lock["name"]
        (entry,) = versions["items"]
        (published,) = entry["wheels"]
        assert (entry["name"], entry["version"]) == (lock["name"], lock["version"])
        assert published["sha256"] == lock["sha256"]
        assert request("/static/" + published["url"]) == wheel.read_bytes()
        schemas = json.loads(
            request(f"/static/packs/{lock['name']}/{lock['version']}/schemas.json")
        )["schemas"]
        assert sorted(item["nodeType"] for item in schemas) == lock["nodeTypes"]
        print(
            f"publisher HTTP upload promoted: {lock['name']}, {len(schemas)} node schemas",
            flush=True,
        )

        old = io.BytesIO()
        with zipfile.ZipFile(old, "w") as archive:
            archive.writestr("dinkster-pack.toml", '[pack]\nname = "old-pack"\n')
        queued = json.loads(
            request("/v1/publish/old-pack/versions/0.0.1", old.getvalue(), authenticated=True)
        )
        cli("scanner", "--once")
        refused = json.loads(request(f"/v1/publish/{queued['candidateId']}", authenticated=True))
        assert refused["status"] == "rejected", refused
        assert refused["reason"] == "wheel.required", refused
        print("queued ZIP refused: wheel.required", flush=True)
    finally:
        server.terminate()
        server.wait(timeout=10)


if __name__ == "__main__":
    main()
