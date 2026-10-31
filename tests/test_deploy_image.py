"""Exercise the deploy command against a local Fly CLI simulator, never Fly resources."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

DEPLOY = Path(__file__).parents[1] / "scripts" / "deploy_image.py"
OLD_IMAGE = "registry.fly.io/dinkster-registry@sha256:" + "a" * 64
NEW_IMAGE = "registry.fly.io/dinkster-registry@sha256:" + "b" * 64

FLY = """#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
state_path = pathlib.Path(os.environ["FLY_TEST_STATE"])
state = json.loads(state_path.read_text())
if args[:2] == ["machine", "list"]:
    if state.get("empty", False):
        print("[]")
        sys.exit(0)
    managed = {"image": state["image"], "metadata": {"fly_platform_version": "v2"}}
    unmanaged = {"image": "old-backup-image", "metadata": {}}
    machines = [{"id": "owned", "config": managed}]
    if not state.get("bootstrap", False):
        machines.append({"id": "unmanaged", "config": unmanaged})
    print(json.dumps(machines))
elif args[:2] == ["config", "save"]:
    pathlib.Path(args[args.index("--config") + 1]).write_text(state["config"])
elif args[:2] == ["machine", "destroy"]:
    if args[2] != "owned":
        sys.exit(99)
    state["empty"] = True
    state_path.write_text(json.dumps(state))
elif args[0] == "deploy":
    config = pathlib.Path(args[args.index("--config") + 1]).read_text()
    image = args[args.index("--image") + 1]
    state.update(image=image, config=config, empty=False)
    state_path.write_text(json.dumps(state))
    if "broken-health" in config or ("--skip-release-command" in args and state["fail_rollback"]):
        sys.exit(1)
else:
    sys.exit(99)
"""

CURL = """#!/usr/bin/env python3
import json, os, pathlib, sys
state_path = pathlib.Path(os.environ["FLY_TEST_STATE"])
state = json.loads(state_path.read_text())
state.setdefault("public_checks", []).append(state["image"])
state_path.write_text(json.dumps(state))
failure = state["failed_public"] if state["image"].endswith("b" * 64) else ""
print("302" if failure == "redirect" else "200", end="")
sys.exit(int(failure == "network"))
"""


@pytest.mark.parametrize(
    "failed_health,failed_rollback,failed_public",
    [
        (False, False, ""),
        (True, False, ""),
        (True, True, ""),
        (False, False, "network"),
        (False, False, "redirect"),
    ],
)
@pytest.mark.parametrize("bootstrap", (False, True))
def test_deployment_keeps_the_new_release_or_restores_the_last_healthy_config(
    tmp_path: Path,
    failed_health: bool,
    failed_rollback: bool,
    failed_public: str,
    bootstrap: bool,
) -> None:
    fly = tmp_path / "flyctl"
    fly.write_text(FLY)
    fly.chmod(0o700)
    curl = tmp_path / "curl"
    curl.write_text(CURL)
    curl.chmod(0o700)
    state = tmp_path / "state.json"
    state.write_text(
        json.dumps(
            {
                "image": OLD_IMAGE,
                "config": "healthy-config",
                "fail_rollback": failed_rollback,
                "failed_public": failed_public,
                "bootstrap": bootstrap,
                "empty": bootstrap,
            }
        )
    )
    config = tmp_path / "new.toml"
    config.write_text("broken-health" if failed_health else "new-healthy-config")
    result = subprocess.run(
        [
            sys.executable,
            str(DEPLOY),
            "--app",
            "dinkster-registry",
            "--region",
            "sjc",
            "--image",
            NEW_IMAGE,
            "--config",
            str(config),
        ],
        env={
            **os.environ,
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "FLY_TEST_STATE": str(state),
        },
        text=True,
        capture_output=True,
        check=False,
    )
    final = json.loads(state.read_text())
    failed = failed_health or bool(failed_public)
    assert result.returncode == int(failed)
    if failed_public:
        assert final["public_checks"] == ([NEW_IMAGE] if bootstrap else [NEW_IMAGE, OLD_IMAGE])
    if bootstrap:
        assert final["empty"] == failed
        if failed:
            assert "First deployment failed" in result.stdout
        else:
            assert final["image"] == NEW_IMAGE
            assert final["config"] == "new-healthy-config"
        return
    assert final["image"] == (OLD_IMAGE if failed else NEW_IMAGE)
    assert final["config"] == ("healthy-config" if failed else "new-healthy-config")
    if failed_rollback:
        assert "ROLLBACK FAILED" in result.stdout
    elif failed:
        assert "Rollback passed Fly and public health checks" in result.stdout


def test_deploy_refuses_a_mutable_image_before_contacting_fly() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(DEPLOY),
            "--app",
            "dinkster-registry",
            "--region",
            "sjc",
            "--image",
            "registry.fly.io/dinkster-registry:main",
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "immutable Fly registry digest" in result.stderr
