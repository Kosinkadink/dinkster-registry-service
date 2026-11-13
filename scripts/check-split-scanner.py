"""Exercise HTTPS scanner assignments in an assignment-only worker container."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import secrets
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path
from typing import Any
from unittest.mock import patch

import uvicorn

from dinkster_registry_service.admission import AdmissionService
from dinkster_registry_service.app import create_app
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.database import Database
from dinkster_registry_service.principals import PrincipalRepository
from dinkster_registry_service.seed import FIXTURE_ROOT
from dinkster_registry_service.settings import ServerSettings


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="registry-split-") as directory:
        root = Path(directory)
        certificate = root / "certificate.pem"
        key = root / "key.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(key),
                "-out",
                str(certificate),
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
            ],
            check=True,
            capture_output=True,
        )
        certificate.chmod(0o644)
        token = secrets.token_urlsafe(32)
        settings = ServerSettings(
            database_url=f"sqlite:///{root / 'catalog.db'}",
            object_store_root=root / "objects",
            scanner_token_sha256=hashlib.sha256(token.encode()).hexdigest(),
        )
        database = Database(settings.database_url)
        service = AdmissionService(database, settings.create_object_store(), settings=settings)
        principals = PrincipalRepository(database)
        principals.register_user("split-check")
        principals.register_publisher("dinkster", "split-check", "2026-11-12T00:00:00Z")
        archive = build_registry_fixture_archive(FIXTURE_ROOT / "example-pack")
        accepted = service.submit(
            archive, pack_name="example-pack", version="1.2.3", publisher="dinkster"
        )
        invalid = io.BytesIO()
        with zipfile.ZipFile(invalid, "w") as wheel:
            wheel.writestr("dinkster-pack.toml", '[pack]\nname = "old-pack"\n')
        rejected = service.submit(invalid.getvalue(), pack_name="old-pack", version="0.0.1")
        context = ssl.create_default_context(cafile=str(certificate))
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        origin = f"https://127.0.0.1:{listener.getsockname()[1]}"
        app = create_app(settings)
        server = uvicorn.Server(
            uvicorn.Config(
                app, log_level="warning", ssl_certfile=str(certificate), ssl_keyfile=str(key)
            )
        )
        worker_env = root / "worker.env"
        worker_env.write_text(
            f"DINKSTER_SCANNER_ORIGIN={origin}\nDINKSTER_SCANNER_TOKEN={token}\n"
            "SSL_CERT_FILE=/scanner-certificate.pem\n"
        )
        worker_env.chmod(0o600)
        name = "registry-split-check-" + uuid.uuid4().hex

        def read(path: str) -> Any:
            with urllib.request.urlopen(origin + path, context=context, timeout=5) as response:
                return json.loads(response.read())

        def no_web_probe(*args: object, **kwargs: object) -> None:
            raise AssertionError("Web admission executed a submitted pack")

        # This trap remains active for both result handling and public-index delivery.
        with patch.object(AdmissionService, "_probe_with_dependencies", no_web_probe):
            thread = threading.Thread(target=server.run, kwargs={"sockets": [listener]})
            thread.start()
            try:
                deadline = time.monotonic() + 30
                while True:
                    assert thread.is_alive(), "HTTPS web server exited before readiness"
                    try:
                        read("/v1/health")
                        break
                    except urllib.error.URLError:
                        assert time.monotonic() < deadline, "HTTPS web readiness failed"
                        time.sleep(0.1)
                assert not service.deliver_once()
                assert service.status(accepted).status == "queued"
                result = subprocess.run(
                    [
                        "docker",
                        "run",
                        "--rm",
                        "--name",
                        name,
                        "--network",
                        "host",
                        "--privileged",
                        "--env-file",
                        str(worker_env),
                        "--mount",
                        f"type=bind,src={certificate},dst=/scanner-certificate.pem,readonly",
                        args.image,
                        "dinkster-scanner",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=180,
                )
                # Do not echo process exceptions, request headers or capability-bearing config.
                assert token not in result.stdout + result.stderr, "worker exposed its capability"
                print(result.stdout, end="", flush=True)
                assert result.returncode == 0, "HTTPS scanner container failed"
                assert service.status(accepted).status == "accepted", service.status(accepted)
                refused = service.status(rejected)
                assert refused.status == "rejected" and refused.reason == "wheel.required", refused
                deadline = time.monotonic() + 30
                while service.deliver_once():
                    assert time.monotonic() < deadline, "outbox delivery did not drain"
                schemas = read("/v1/packs/example-pack/versions/1.2.3/schemas")["schemas"]
                assert sorted(item["nodeType"] for item in schemas) == [
                    "example.resize",
                    "example.save",
                ]
                index = read("/static/packs/index.json")
                assert [item["name"] for item in index["items"]] == ["example-pack"]
                print(
                    "split_scanner=passed transport=https jail=full "
                    "web_probe=forbidden accepted=1 rejected=1 schemas=2 idle_exit=0 "
                    "worker_mounts=certificate-only worker_authority=assignment-only",
                    flush=True,
                )
            finally:
                subprocess.run(["docker", "rm", "--force", name], capture_output=True, check=False)
                server.should_exit = True
                thread.join(timeout=10)
                listener.close()
                database.dispose()
                assert not thread.is_alive(), "HTTPS web server did not stop"


if __name__ == "__main__":
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    main()
