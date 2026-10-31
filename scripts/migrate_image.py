"""Migrate the registry database using an immutable service image."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from contextlib import suppress
from typing import Any, cast

APP_NAME = "dinkster-registry"
DATABASE_NAME = "dinkster-registry"
CLUSTER_NAME = "dinkster"
ORGANIZATION = "dinkster"
CLUSTER_ID = "vmkq609v6xvo35ln"
REGION = "sjc"
IMAGE_PATTERN = re.compile(rf"registry\.fly\.io/{re.escape(APP_NAME)}@sha256:[0-9a-f]{{64}}")


def get_json(path: str) -> dict[str, Any]:
    request = urllib.request.Request(
        "https://api.machines.dev/v1/postgres/" + path,
        headers={"Authorization": "Bearer " + os.environ["FLY_API_TOKEN"]},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return cast(dict[str, Any], json.load(response))


def redact(output: str, secrets: tuple[str, ...]) -> str:
    for secret in secrets:
        output = output.replace(secret, "[redacted]")
    return re.sub(r"postgres(?:ql)?(?:\+\w+)?://[^\s]+", "[redacted URL]", output)


def cleanup_proxy(proxy: subprocess.Popen[bytes] | None) -> None:
    if proxy is None:
        return
    with suppress(OSError):
        if proxy.poll() is None:
            proxy.terminate()
    try:
        proxy.wait(timeout=10)
    except subprocess.TimeoutExpired:
        with suppress(OSError):
            proxy.kill()
        with suppress(OSError):
            proxy.wait(timeout=10)
    except OSError:
        pass


def cleanup_container(container_name: str | None) -> None:
    if container_name is None:
        return
    with suppress(OSError, subprocess.TimeoutExpired):
        subprocess.run(
            ["docker", "rm", "--force", container_name],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
            check=False,
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    if IMAGE_PATTERN.fullmatch(args.image) is None:
        parser.error("image must be the immutable registry image digest")

    proxy: subprocess.Popen[bytes] | None = None
    container_name: str | None = None
    try:
        cluster = get_json(CLUSTER_ID)["data"]
        if (
            cluster["id"],
            cluster["name"],
            cluster["organization"]["slug"],
            cluster["region"],
            cluster["status"],
        ) != (CLUSTER_ID, CLUSTER_NAME, ORGANIZATION, REGION, "ready"):
            raise RuntimeError("Unexpected cluster inventory")

        credentials = get_json(CLUSTER_ID + "/users/fly-user/credentials")["data"]
        if credentials["username"] != "fly-user" or not credentials["password"]:
            raise RuntimeError("Unexpected migration credential identity")

        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]

        proxy = subprocess.Popen(
            [
                "flyctl",
                "mpg",
                "proxy",
                CLUSTER_ID,
                "--bind-addr",
                "127.0.0.1",
                "--local-port",
                str(port),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 60
        while True:
            if proxy.poll() is not None:
                raise RuntimeError("Migration proxy exited before readiness")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise TimeoutError("Migration proxy readiness deadline") from None
                time.sleep(0.2)

        quoted_password = urllib.parse.quote(credentials["password"], safe="")
        database_url = (
            f"postgresql+psycopg://fly-user:{quoted_password}@127.0.0.1:{port}/{DATABASE_NAME}"
        )
        container_name = f"{APP_NAME}-migration-{uuid.uuid4().hex}"
        environment = {
            **os.environ,
            "DINKSTER_DATABASE_URL": database_url,
        }
        environment.pop("DATABASE_URL", None)
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--name",
                container_name,
                "--network",
                "host",
                "--env",
                "DINKSTER_DATABASE_URL",
                args.image,
                "alembic",
                "upgrade",
                "head",
            ],
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=300,
            check=False,
        )
        secrets = (
            database_url,
            quoted_password,
            credentials["password"],
            os.environ["FLY_API_TOKEN"],
        )
        for output in (result.stdout, result.stderr):
            print(redact(output, secrets), end="", flush=True)
        print("Immutable-image migration exit code:", result.returncode, flush=True)
        return int(result.returncode != 0)
    except urllib.error.HTTPError as error:
        print("Migration credential/inventory GET failed with HTTP status:", error.code)
        return 1
    except Exception as error:
        print("Migration failed (" + type(error).__name__ + "); details withheld")
        return 1
    finally:
        cleanup_proxy(proxy)
        cleanup_container(container_name)


if __name__ == "__main__":
    raise SystemExit(main())
