"""Execute the public guide against an isolated disposable SQLite registry."""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

from dinkster_registry_service.database import Database
from dinkster_registry_service.principals import PrincipalRepository


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("guide", type=Path)
    args = parser.parse_args()
    guide = args.guide.read_text(encoding="utf-8")
    blocks = dict(
        re.findall(r"<!-- registry-command: (\w+) -->\n```sh\n(.*?)\n```", guide, re.DOTALL)
    )
    if set(blocks) != {"build", "submit", "yank"} or guide.count("```sh") != len(blocks):
        raise SystemExit("Every shell command must belong to a named, executed guide block")
    with tempfile.TemporaryDirectory(prefix="registry-guide-") as temporary:
        root = Path(temporary)
        database_url = f"sqlite:///{root / 'registry.db'}"
        database = Database(database_url)
        try:
            principals = PrincipalRepository(database)
            now = datetime.now(UTC)
            principals.register_user("guide-author")
            principals.register_publisher("guide-author", "guide-author", now.isoformat())
            token, _ = principals.mint_token(
                "guide-author",
                "guide-author",
                now.isoformat(),
                (now + timedelta(hours=1)).isoformat(),
                pack="maple-text",
            )
        finally:
            database.dispose()
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        base = f"http://127.0.0.1:{port}"
        env = {
            "PATH": os.pathsep.join((str(Path(sys.executable).parent), os.environ["PATH"])),
            "HOME": str(root),
            "LANG": "C.UTF-8",
            "TMPDIR": str(root),
            "UV_CACHE_DIR": str(root / "uv-cache"),
            "DINKSTER_DATABASE_URL": database_url,
            "DINKSTER_OBJECT_STORE_ROOT": str(root / "objects"),
            "DINKSTER_PUBLIC_BASE_URL": base,
        }
        with (root / "server.log").open("w+") as server_log:
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
                ],
                env=env,
                stdout=server_log,
                stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    if server.poll() is not None:
                        server_log.seek(0)
                        raise RuntimeError(server_log.read())
                    try:
                        with urllib.request.urlopen(base + "/v1/health", timeout=1):
                            break
                    except (urllib.error.URLError, TimeoutError):
                        time.sleep(0.1)
                else:
                    raise RuntimeError("Disposable registry did not become ready")
                subprocess.run(["bash", "-euc", blocks["build"]], cwd=root, env=env, check=True)
                with (root / "scanner.log").open("w+") as scanner_log:
                    scanner = subprocess.Popen(
                        [sys.executable, "-m", "dinkster_registry_service.cli", "scanner"],
                        env=env,
                        stdout=scanner_log,
                        stderr=subprocess.STDOUT,
                    )
                    try:
                        author_env = {
                            **env,
                            "DINKSTER_REGISTRY_URL": base,
                            "DINKSTER_REGISTRY_TOKEN": token,
                        }
                        subprocess.run(
                            ["bash", "-euc", blocks["submit"]],
                            cwd=root / "maple-text",
                            env=author_env,
                            check=True,
                            timeout=360,
                        )
                    except BaseException:
                        scanner_log.seek(0)
                        print(scanner_log.read(), file=sys.stderr)
                        raise
                    finally:
                        scanner.terminate()
                        scanner.wait(timeout=15)
                with urllib.request.urlopen(base + "/v1/packs/maple-text/versions/0.1.0") as r:
                    active = json.load(r)
                assert active["state"] == "active"
                assert active["trustSignals"]["doctor"]["status"] == "passed"
                assert active["trustSignals"]["scan"]["status"] == "passed"
                assert [node["nodeType"] for node in active["nodes"]] == ["maple-text.shout"]
                headers = {"Authorization": "Bearer " + token}
                invalid = urllib.request.Request(
                    base + "/v1/publish/maple-text/versions/0.2.0",
                    data=b"not a wheel",
                    headers={**headers, "Content-Type": "application/octet-stream"},
                )
                with urllib.request.urlopen(invalid, timeout=30) as response:
                    candidate = json.load(response)["candidateId"]
                subprocess.run(
                    [sys.executable, "-m", "dinkster_registry_service.cli", "scanner", "--once"],
                    env=env,
                    check=True,
                    timeout=60,
                )
                status_request = urllib.request.Request(
                    base + "/v1/publish/" + candidate, headers=headers
                )
                with urllib.request.urlopen(status_request, timeout=30) as response:
                    rejected = json.load(response)
                assert rejected["status"] == "rejected", rejected["status"]
                finding = rejected["findings"][0]
                assert finding["code"] == "wheel.required", finding
                assert finding["message"] == "Only wheel artifacts are accepted.", finding
                assert f"`{finding['code']}` | `{finding['message']}`" in guide
                subprocess.run(["bash", "-euc", blocks["yank"]], cwd=root, env=env, check=True)
                with urllib.request.urlopen(base + "/v1/packs/maple-text/versions/0.1.0") as r:
                    yanked = json.load(r)
                assert yanked["state"] == "yanked"
                assert yanked["stateReason"] == "Replaced by a corrected release."
                print(
                    "Guide commands: build, tests, doctor, HTTP admission, active schema, "
                    "refusal message, yank passed"
                )
            finally:
                server.terminate()
                server.wait(timeout=15)


if __name__ == "__main__":
    main()
