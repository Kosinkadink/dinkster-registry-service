"""Deploy an immutable image, restoring the previous image and config on failure."""

import argparse
import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True)
    parser.add_argument("--region", choices=("iad", "sjc"), required=True)
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
        if len(images) != 1:
            raise RuntimeError(
                "Need one previously deployed image; bootstrap or reconcile the app first"
            )
        previous_image = images.pop()
        if not previous_image:
            raise RuntimeError("Previous image is missing; refusing deployment without rollback")
        # flyctl resolves --config as an existing input before saving the remote config.
        previous_config.touch(mode=0o600)
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
            "--ha=false",
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
        if result.returncode == 0:
            print("Deployment passed Fly health checks", flush=True)
            return 0

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
        if rollback.returncode != 0:
            print("ROLLBACK FAILED: operator intervention is required", flush=True)
        else:
            print("Rollback passed Fly health checks; deployment remains failed", flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
