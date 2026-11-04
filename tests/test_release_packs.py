from __future__ import annotations

import io
import json
import runpy
import sys
import urllib.error
import urllib.request
import zipfile
from email.message import Message
from pathlib import Path
from typing import Any

import pytest

from dinkster_registry_service.digests import artifact_digest

SCRIPT = Path(__file__).parents[1] / "scripts" / "check-release-packs.py"


def test_release_download_uses_and_saves_the_producer_read_pin(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pin = {
        "repository": "Kosinkadink/Dinkster",
        "releaseTag": "main-a-different-release",
        "commit": "b" * 40,
    }
    document = {"format": "dinkster.consumer-pins/1", "consumers": {"dinkster-registry": pin}}
    archives = {}
    packs = []
    for number in range(14):
        name = f"test-pack-{number}"
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("dinkster-pack.toml", "[pack]\ndependencies = {}\n")
        archives[f"{name}-1.0.0.zip"] = buffer.getvalue()
        packs.append(
            {
                "pack": name,
                "version": "1.0.0",
                "publisher": "dinkster",
                "source": "git:Kosinkadink/Dinkster@" + pin["commit"],
                "artifactDigest": artifact_digest(buffer.getvalue()),
            }
        )
    archives["official-packs.lock"] = json.dumps(
        {"format": "dinkster.lock/1", "packs": packs}
    ).encode()

    def read(request: Any, **kwargs: Any) -> io.BytesIO:
        if isinstance(request, urllib.request.Request):
            assert request.full_url.endswith("/contents/consumer-pins.json?ref=main")
            return io.BytesIO(json.dumps(document).encode())
        prefix = "https://github.com/Kosinkadink/Dinkster/releases/download/"
        assert request.startswith(prefix + pin["releaseTag"] + "/")
        return io.BytesIO(archives[request.rsplit("/", 1)[1]])

    monkeypatch.setattr(urllib.request, "urlopen", read)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), str(tmp_path), "--download-only"])
    runpy.run_path(str(SCRIPT), run_name="__main__")
    assert json.loads((tmp_path / "consumer-pins.json").read_bytes()) == document
    assert all((tmp_path / name).read_bytes() == payload for name, payload in archives.items())


def test_unreadable_pin_refuses_release_download(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def read(request: Any, **kwargs: Any) -> io.BytesIO:
        raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", Message(), None)

    monkeypatch.setattr(urllib.request, "urlopen", read)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT), str(tmp_path), "--download-only"])
    with pytest.raises(urllib.error.HTTPError):
        runpy.run_path(str(SCRIPT), run_name="__main__")
    assert list(tmp_path.iterdir()) == []
