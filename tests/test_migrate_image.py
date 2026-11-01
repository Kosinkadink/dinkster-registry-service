"""Exercise migration orchestration against local process simulators only."""

import json
import runpy
import subprocess
import sys
from collections.abc import Callable
from contextlib import nullcontext
from io import StringIO
from pathlib import Path
from typing import Any, cast
from urllib.request import Request

import pytest

MIGRATION = Path(__file__).parents[1] / "scripts" / "migrate_image.py"
IMAGE = "registry.fly.io/dinkster-registry@sha256:" + "a" * 64
PASSWORD = "migration-test-secret:@/"
TOKEN = "test-fly-token"


class FakeProcess:
    def __init__(self) -> None:
        self.terminated = False
        self.killed = False
        self.waited = False

    def poll(self) -> None:
        return None

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:
        self.killed = True

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.waited = True
        return 0


def load_main() -> Callable[[], int]:
    return cast(Callable[[], int], runpy.run_path(str(MIGRATION))["main"])


def install_inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    def response(request: Request, **kwargs: object) -> StringIO:
        del kwargs
        data: dict[str, Any]
        if request.full_url.endswith("/credentials"):
            data = {"username": "fly-user", "password": PASSWORD}
        else:
            data = {
                "id": "vmkq609v6xvo35ln",
                "name": "dinkster",
                "organization": {"slug": "dinkster"},
                "region": "sjc",
                "status": "ready",
            }
        return StringIO(json.dumps({"data": data}))

    monkeypatch.setattr("urllib.request.urlopen", response)


def set_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FLY_API_TOKEN", TOKEN)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setattr(sys, "argv", [str(MIGRATION), "--image", IMAGE])


@pytest.mark.parametrize("migration_exit_code", [0, 1])
def test_migration_uses_only_its_temporary_url_and_redacts_credentials(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    migration_exit_code: int,
) -> None:
    set_arguments(monkeypatch)
    install_inventory(monkeypatch)
    proxy = FakeProcess()
    commands: list[tuple[tuple[object, ...], dict[str, object]]] = []

    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: proxy)
    monkeypatch.setattr("socket.create_connection", lambda *args, **kwargs: nullcontext())

    def run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        commands.append((args, kwargs))
        command = cast(list[str], args[0])
        if command[:2] == ["docker", "rm"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        environment = cast(dict[str, str], kwargs["env"])
        url = environment["DINKSTER_DATABASE_URL"]
        assert command[0:2] == ["docker", "run"]
        assert "DINKSTER_DATABASE_URL" in command
        assert "DATABASE_URL" not in command
        assert "FLY_API_TOKEN" not in command
        assert "DATABASE_URL" not in environment
        assert "+psycopg://" in url
        assert url.endswith("/dinkster-registry")
        return subprocess.CompletedProcess(
            command,
            migration_exit_code,
            f"Migration diagnostic: {PASSWORD} {TOKEN} {url}\n",
            "Schema update failed\n" if migration_exit_code else "",
        )

    monkeypatch.setattr("subprocess.run", run)
    result = load_main()()
    output = capsys.readouterr().out

    assert result == migration_exit_code
    assert PASSWORD not in output
    assert TOKEN not in output
    assert "postgresql+psycopg://" not in output
    assert "[redacted]" in output
    assert proxy.terminated
    assert proxy.waited
    assert any(cast(list[str], args[0])[:2] == ["docker", "rm"] for args, _ in commands)


def test_proxy_readiness_timeout_cleans_up_without_starting_docker(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_arguments(monkeypatch)
    install_inventory(monkeypatch)
    proxy = FakeProcess()
    monotonic_values = iter((0.0, 61.0))
    docker_commands: list[list[str]] = []

    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: proxy)
    monkeypatch.setattr(
        "socket.create_connection",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("not ready")),
    )
    monkeypatch.setattr("time.monotonic", lambda: next(monotonic_values))
    monkeypatch.setattr("time.sleep", lambda _seconds: None)

    def run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        docker_commands.append(cast(list[str], args[0]))
        return subprocess.CompletedProcess(cast(list[str], args[0]), 0, "", "")

    monkeypatch.setattr("subprocess.run", run)
    result = load_main()()
    output = capsys.readouterr().out

    assert result == 1
    assert "TimeoutError" in output
    assert proxy.terminated
    assert proxy.waited
    assert docker_commands == []


def test_migration_timeout_cleans_up_proxy_and_container(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    set_arguments(monkeypatch)
    install_inventory(monkeypatch)
    proxy = FakeProcess()
    commands: list[list[str]] = []

    monkeypatch.setattr("subprocess.Popen", lambda *args, **kwargs: proxy)
    monkeypatch.setattr("socket.create_connection", lambda *args, **kwargs: nullcontext())

    def run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        del kwargs
        command = cast(list[str], args[0])
        commands.append(command)
        if command[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(command, 300)
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr("subprocess.run", run)
    result = load_main()()
    output = capsys.readouterr().out

    assert result == 1
    assert "TimeoutExpired" in output
    assert proxy.terminated
    assert proxy.waited
    assert any(command[:2] == ["docker", "rm"] for command in commands)


def test_migration_rejects_mutable_images_before_contacting_fly() -> None:
    result = subprocess.run(
        [sys.executable, str(MIGRATION), "--image", "registry.fly.io/dinkster-registry:main"],
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 2
    assert "immutable registry image digest" in result.stderr
