"""Deploy an immutable image, restoring the previous image and config on failure."""

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


def public_ready() -> bool:
    try:
        result = subprocess.run(
            [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--retry",
                "10",
                "--retry-all-errors",
                "--retry-delay",
                "2",
                "--max-time",
                "10",
                "--retry-max-time",
                "120",
                "--output",
                os.devnull,
                "--write-out",
                "%{http_code}",
                "https://registry.dinkster.org/healthz",
            ],
            check=False,
            timeout=150,
            text=True,
            capture_output=True,
        )
        return result.returncode == 0 and result.stdout == "200"
    except (OSError, subprocess.TimeoutExpired):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True)
    parser.add_argument("--region", choices=("sjc",), required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--config", default="fly.toml")
    args = parser.parse_args()
    if not re.fullmatch(
        rf"registry\.fly\.io/{re.escape(args.app)}@sha256:[0-9a-f]{{64}}", args.image
    ):
        parser.error("image must be this app's immutable Fly registry digest")

    # Store the prior config privately: it can contain environment configuration.
    with tempfile.TemporaryDirectory(prefix="fly-rollback-") as directory:
        previous_config = Path(directory) / "fly.toml"
        machines = json.loads(
            subprocess.check_output(
                ["flyctl", "machine", "list", "--app", args.app, "--json"], text=True
            )
        )
        images = {
            machine["config"]["image"]
            for machine in machines
            if machine["config"].get("metadata", {}).get("fly_platform_version") == "v2"
        }
        if machines and len(images) != 1:
            raise RuntimeError(
                "Need one previously deployed image; reconcile the app before deploying"
            )
        previous_image = images.pop() if images else None
        if machines and not previous_image:
            raise RuntimeError("Previous image is missing; refusing deployment without rollback")
        if previous_image is not None and not re.fullmatch(
            rf"registry\.fly\.io/{re.escape(args.app)}(?::[^@]+)?@sha256:[0-9a-f]{{64}}",
            previous_image,
        ):
            raise RuntimeError("Previous image must have an immutable registry digest")
        # flyctl resolves --config as an existing input before saving the remote config.
        previous_config.touch(mode=0o600)
        if previous_image is not None:
            subprocess.run(
                [
                    "flyctl",
                    "config",
                    "save",
                    "--app",
                    args.app,
                    "--config",
                    str(previous_config),
                    "--yes",
                ],
                check=True,
                stdout=subprocess.DEVNULL,
            )
        os.chmod(previous_config, 0o600)
        common = [
            "flyctl",
            "deploy",
            "--app",
            args.app,
            "--strategy",
            "rolling",
            "--ha=true",
            "--max-unavailable",
            "0.5",
            "--no-public-ips",
            "--wait-timeout",
            "5m",
            "--yes",
        ]
        result = subprocess.run(
            [
                *common,
                "--config",
                args.config,
                "--primary-region",
                args.region,
                "--image",
                args.image,
            ],
            check=False,
        )
        if result.returncode == 0 and public_ready():
            print("Deployment passed Fly and public health checks", flush=True)
            return 0

        if previous_image is None:
            print(
                "First deployment failed; removing only newly created service Machines", flush=True
            )
            created = json.loads(
                subprocess.check_output(
                    ["flyctl", "machine", "list", "--app", args.app, "--json"], text=True
                )
            )
            for machine in created:
                config = machine["config"]
                if (
                    config.get("image", "").rsplit("@", 1)[-1] != args.image.rsplit("@", 1)[-1]
                    or config.get("metadata", {}).get("fly_platform_version") != "v2"
                ):
                    raise RuntimeError(
                        "Unexpected Machine after failed first deploy; refusing cleanup"
                    )
            for machine in created:
                subprocess.run(
                    ["flyctl", "machine", "destroy", machine["id"], "--app", args.app, "--force"],
                    check=True,
                )
            return 1

        print("Deployment failed; restoring the previous image and configuration", flush=True)
        rollback = subprocess.run(
            [
                *common,
                "--config",
                str(previous_config),
                "--image",
                previous_image,
                "--skip-release-command",
            ],
            check=False,
        )
        if rollback.returncode != 0 or not public_ready():
            print("ROLLBACK FAILED: operator intervention is required", flush=True)
        else:
            print(
                "Rollback passed Fly and public health checks; deployment remains failed",
                flush=True,
            )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
