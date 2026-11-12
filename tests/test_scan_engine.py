from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

import dinkster_registry_service.scan_engine as engine_module
from dinkster_registry_service.scan_engine import ScanEngineError, stage_scan_api
from dinkster_registry_service.settings import ServerSettings


def _write_manifest(release: Path, manifest: dict[str, Any]) -> dict[str, str]:
    data = json.dumps(manifest).encode()
    (release / "release-manifest.json").write_bytes(data)
    return {"commit": "a" * 40, "manifestDigest": "sha256:" + hashlib.sha256(data).hexdigest()}


def _release(tmp_path: Path) -> tuple[Path, dict[str, Any], dict[str, str]]:
    release = tmp_path / "release"
    release.mkdir()
    wheel = release / "dinkster_api-0.9.1-py3-none-any.whl"
    wheel.write_bytes(b"verified synthetic API artifact")
    manifest = {
        "format": "dinkster.engine/1",
        "repository": "Kosinkadink/Dinkster",
        "commit": "a" * 40,
        "version": "0.9.1",
        "artifacts": [
            {
                "name": wheel.name,
                "size": wheel.stat().st_size,
                "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
            }
        ],
    }
    return release, manifest, _write_manifest(release, manifest)


def test_exact_api_artifact_is_staged_from_trusted_index_or_development_mount(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release, _, binding = _release(tmp_path)
    index = [
        {
            **binding,
            "sha256": binding["manifestDigest"][7:],
            "path": "engine/exact",
            "version": "0.9.1",
        }
    ]

    def read(path: str, limit: int) -> bytes:
        if path == "engine/index.json":
            return json.dumps(index).encode()
        assert path.startswith("engine/exact/")
        data = (release / path.removeprefix("engine/exact/")).read_bytes()
        assert len(data) <= limit
        return data

    monkeypatch.setattr(engine_module, "_read_release", read)
    for local in (None, release):
        wheel, version = stage_scan_api(binding, tmp_path, development_release=local)
        assert version == "0.9.1"
        assert wheel.read_bytes() == b"verified synthetic API artifact"
    index[0]["sha256"] = "b" * 64
    with pytest.raises(ScanEngineError, match="index manifest identity"):
        stage_scan_api(binding, tmp_path)
    index.clear()
    with pytest.raises(ScanEngineError, match="exactly one matching commit"):
        stage_scan_api(binding, tmp_path)


@pytest.mark.parametrize(
    "fault", ("commit", "repository", "version", "missing", "duplicate", "size", "digest", "native")
)
def test_selected_api_refuses_mismatched_release_inputs(tmp_path: Path, fault: str) -> None:
    release, manifest, _ = _release(tmp_path)
    if fault == "commit":
        manifest["commit"] = "b" * 40
    elif fault == "repository":
        manifest["repository"] = "untrusted/repository"
    elif fault == "version":
        manifest["version"] = "0.9.2"
    elif fault == "missing":
        manifest["artifacts"] = []
    elif fault == "duplicate":
        manifest["artifacts"] *= 2
    elif fault == "size":
        manifest["artifacts"][0]["size"] += 1
    elif fault == "digest":
        manifest["artifacts"][0]["sha256"] = "b" * 64
    elif fault == "native":
        manifest["artifacts"][0]["name"] = "dinkster_api-0.9.1-cp312-cp312-linux_x86_64.whl"
    binding = _write_manifest(release, manifest)
    with pytest.raises(ScanEngineError):
        stage_scan_api(binding, tmp_path, development_release=release)


def test_selected_api_refuses_changed_manifest_or_escaping_local_wheel(tmp_path: Path) -> None:
    release, manifest, binding = _release(tmp_path)
    (release / "release-manifest.json").write_bytes(b"changed")
    with pytest.raises(ScanEngineError, match="manifest digest"):
        stage_scan_api(binding, tmp_path, development_release=release)
    binding = _write_manifest(release, manifest)
    wheel = release / manifest["artifacts"][0]["name"]
    wheel.unlink()
    wheel.symlink_to(tmp_path / "outside.whl")
    with pytest.raises(ScanEngineError, match="escapes"):
        stage_scan_api(binding, tmp_path, development_release=release)


def test_local_engine_override_is_forbidden_outside_development(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="only in development"):
        ServerSettings(environment="production", probe_engine_release=tmp_path)
