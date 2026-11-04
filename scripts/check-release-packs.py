"""Admit pinned official ZIPs from the independently published pack registry."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tomllib
import urllib.request
import zipfile
from pathlib import Path

from dinkster_registry_service.digests import artifact_digest
from dinkster_registry_service.identifiers import require_canonical_pack_name
from dinkster_registry_service.versioning import require_public_version

REGISTRY_URL = "https://registry.dinkster.org"


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
    if args.download_only:
        directory.mkdir(parents=True, exist_ok=True)
    lock = json.loads(Path(__file__).with_name("release-packs.lock").read_bytes())
    assert lock["format"] == "dinkster.lock/1"
    packs = lock["packs"]
    assert len(packs) == 14
    assert len({pack["pack"] for pack in packs}) == 14
    pending = {}
    for pack in packs:
        name = require_canonical_pack_name(pack["pack"])
        version = require_public_version(pack["version"])
        assert pack["publisher"] == "dinkster"
        assert pack["source"] == f"registry:{REGISTRY_URL}"
        archive = directory / f"{name}-{version}.zip"
        if args.download_only:
            with urllib.request.urlopen(f"{REGISTRY_URL}/v1/packs/{name}", timeout=60) as response:
                owner = json.load(response)
            assert owner["name"] == name and owner["owner"]["slug"] == pack["publisher"], name
            with urllib.request.urlopen(
                f"{REGISTRY_URL}/v1/packs/{name}/versions/{version}", timeout=60
            ) as response:
                release = json.load(response)
            assert release["packName"] == name and release["version"] == version, name
            assert release["state"] == "active", name
            assert release["artifact"]["digest"] == pack["artifactDigest"], name
            with urllib.request.urlopen(
                f"{REGISTRY_URL}/v1/artifacts/{pack['artifactDigest']}", timeout=60
            ) as response:
                data = response.read()
            assert len(data) == release["artifact"]["size"], name
            archive.write_bytes(data)
        assert artifact_digest(archive.read_bytes()) == pack["artifactDigest"], name
        with zipfile.ZipFile(archive) as source:
            manifest = tomllib.loads(source.read("dinkster-pack.toml").decode())
        assert manifest["pack"]["name"] == name, name
        if "version" in manifest["pack"]:
            assert manifest["pack"]["version"] == version, name
        assert manifest["pack"]["publisher"] == pack["publisher"], name
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
