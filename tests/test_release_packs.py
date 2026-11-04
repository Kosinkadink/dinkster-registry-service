import io
import json
import runpy
import zipfile
from pathlib import Path
from typing import Any

import pytest

from dinkster_registry_service.digests import artifact_digest

SCRIPT = Path(__file__).parents[1] / "scripts" / "check-release-packs.py"


@pytest.mark.parametrize(
    "damage", [None, "publisher", "version", "digest", "bytes", "manifest-version", "source"]
)
def test_pinned_registry_downloads_reject_changed_identity_or_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, damage: str | None
) -> None:
    module = runpy.run_path(str(SCRIPT))
    main = module["main"]
    main.__globals__["__file__"] = str(tmp_path / SCRIPT.name)
    root = module["REGISTRY_URL"]
    responses: dict[str, bytes] = {}
    packs = []
    for index in range(14):
        name = f"example-pack-{index}"
        archive = io.BytesIO()
        version = "9.8.7" if damage == "manifest-version" and index == 0 else "1.2.3"
        with zipfile.ZipFile(archive, "w") as output:
            output.writestr(
                "dinkster-pack.toml",
                f'[pack]\nname = "{name}"\nversion = "{version}"\npublisher = "dinkster"\n',
            )
        data = archive.getvalue()
        digest = artifact_digest(data)
        pack = {
            "pack": name,
            "version": "1.2.3",
            "publisher": "dinkster",
            "source": f"registry:{root}",
            "artifactDigest": digest,
        }
        owner = {"name": name, "owner": {"slug": "dinkster"}}
        release: dict[str, Any] = {
            "packName": name,
            "version": "1.2.3",
            "state": "active",
            "artifact": {"digest": digest, "size": len(data)},
        }
        if index == 0:
            if damage == "publisher":
                owner["owner"] = {"slug": "someone-else"}
            elif damage == "version":
                release["version"] = "1.2.4"
            elif damage == "digest":
                release["artifact"]["digest"] = "blake3:" + "0" * 64
            elif damage == "bytes":
                data = b"X" * len(data)
            elif damage == "source":
                pack["source"] = "registry:https://different.invalid"
        packs.append(pack)
        responses[f"{root}/v1/packs/{name}"] = json.dumps(owner).encode()
        responses[f"{root}/v1/packs/{name}/versions/1.2.3"] = json.dumps(release).encode()
        responses[f"{root}/v1/artifacts/{digest}"] = data
    (tmp_path / "release-packs.lock").write_text(
        json.dumps({"format": "dinkster.lock/1", "packs": packs})
    )
    monkeypatch.setattr("urllib.request.urlopen", lambda url, timeout: io.BytesIO(responses[url]))
    directory = tmp_path / "downloaded"
    monkeypatch.setattr("sys.argv", [str(SCRIPT), str(directory), "--download-only"])
    if damage:
        with pytest.raises(AssertionError):
            main()
    else:
        main()
        assert len(list(directory.glob("*.zip"))) == 14
        assert (directory / "example-pack-0-1.2.3.zip").read_bytes() == responses[
            f"{root}/v1/artifacts/{packs[0]['artifactDigest']}"
        ]
