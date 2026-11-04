"""Admit the exact official ZIPs from a pinned Dinkster release."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tomllib
import urllib.request
import zipfile
from pathlib import Path

from dinkster_registry_service.digests import artifact_digest
from dinkster_registry_service.identifiers import require_canonical_pack_name
from dinkster_registry_service.versioning import require_public_version

PIN_URL = (
    "https://api.github.com/repos/Kosinkadink/Dinkster-Environments/"
    "contents/consumer-pins.json?ref=main"
)


def release_pin(document: dict) -> dict:
    if document["format"] != "dinkster.consumer-pins/1":
        raise ValueError("Unsupported consumer pin format")
    pin = document["consumers"]["dinkster-registry"]
    if (
        pin["repository"] != "Kosinkadink/Dinkster"
        or not re.fullmatch(r"(?:main-|v)[A-Za-z0-9._+-]+", pin["releaseTag"])
        or not re.fullmatch(r"[0-9a-f]{40}", pin["commit"])
    ):
        raise ValueError("Invalid official-packs release pin")
    return pin


def cli(*arguments: str) -> str:
    return subprocess.check_output(
        [sys.executable, "-m", "dinkster_registry_service.cli", *arguments], text=True
    ).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--download-only", action="store_true")
    args = parser.parse_args()
    directory = args.directory
    selection = directory / "consumer-pins.json"
    if args.download_only:
        request = urllib.request.Request(
            PIN_URL, headers={"Accept": "application/vnd.github.raw+json"}
        )
        with urllib.request.urlopen(request, timeout=60) as response:
            document = response.read()
        pin = release_pin(json.loads(document))
        directory.mkdir(parents=True, exist_ok=True)
        selection.write_bytes(document)
    else:
        pin = release_pin(json.loads(selection.read_bytes()))
    release_url = "https://github.com/Kosinkadink/Dinkster/releases/download/" + pin["releaseTag"]
    if args.download_only:
        with urllib.request.urlopen(f"{release_url}/official-packs.lock", timeout=60) as response:
            (directory / "official-packs.lock").write_bytes(response.read())
    lock = json.loads((directory / "official-packs.lock").read_bytes())
    assert lock["format"] == "dinkster.lock/1"
    packs = lock["packs"]
    assert len(packs) == 14
    assert len({pack["pack"] for pack in packs}) == 14
    pending = {}
    for pack in packs:
        name = require_canonical_pack_name(pack["pack"])
        version = require_public_version(pack["version"])
        assert pack["publisher"] == "dinkster"
        assert pack["source"] == f"git:Kosinkadink/Dinkster@{pin['commit']}"
        archive = directory / f"{name}-{version}.zip"
        if args.download_only:
            with urllib.request.urlopen(f"{release_url}/{archive.name}", timeout=60) as response:
                archive.write_bytes(response.read())
        assert artifact_digest(archive.read_bytes()) == pack["artifactDigest"], name
        with zipfile.ZipFile(archive) as source:
            manifest = tomllib.loads(source.read("dinkster-pack.toml").decode())
        dependencies = set(manifest["pack"].get("dependencies", {}))
        pending[name] = (pack, archive, dependencies)
        print(f"verified {name} {version} {pack['artifactDigest']}", flush=True)
    if args.download_only:
        return
    assert os.environ.get("DINKSTER_DATABASE_URL"), "a disposable migrated database is required"
    cli("admin", "add-user", "release-check")
    cli("admin", "add-publisher", "dinkster", "--owner", "release-check")
    completed: set[str] = set()
    failures = []
    while pending:
        available = sorted(name for name, (_, _, deps) in pending.items() if deps <= completed)
        assert available, f"unresolved release dependencies: {sorted(pending)}"
        for name in available:
            pack, archive, _ = pending.pop(name)
            candidate = cli(
                "submit",
                str(archive),
                "--pack",
                name,
                "--version",
                pack["version"],
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
            result = {
                "pack": name,
                "version": pack["version"],
                "status": status["status"],
                "reason": status["reason"],
                "digest": status["digest"],
                "lockDigestMatches": status["digest"] == pack["artifactDigest"],
                "blockingCodes": sorted(
                    {
                        finding["code"]
                        for finding in status["findings"]
                        if finding["effect"] == "block"
                    }
                ),
            }
            completed.add(name)
            print(json.dumps(result, sort_keys=True), flush=True)
            if status["status"] != "accepted" or not result["lockDigestMatches"]:
                failures.append(result)
    assert len(completed) == 14
    assert not failures, failures


if __name__ == "__main__":
    main()
