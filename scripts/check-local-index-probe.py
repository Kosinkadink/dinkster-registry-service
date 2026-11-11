from __future__ import annotations

import argparse
import json
import os
import shutil
import tempfile
from pathlib import Path

from sqlalchemy import select

from dinkster_registry_service.admission import AdmissionService
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.database import Database, ReleaseRecord, ReleaseScanRunRecord
from dinkster_registry_service.object_store import LocalFilesystemObjectStore
from dinkster_registry_service.seed import FIXTURE_ROOT
from dinkster_registry_service.settings import ServerSettings


def check_candidate(wheels: Path, case: str) -> None:
    with tempfile.TemporaryDirectory(prefix="registry-local-index-") as directory:
        root = Path(directory)
        index = root / "simple"
        index.mkdir()
        for wheel in sorted(wheels.glob("*.whl")):
            project = wheel.name.split("-", 1)[0].replace("_", "-").lower()
            if case == "missing" and project == "torchvision":
                continue
            page = index / project
            page.mkdir(exist_ok=True)
            with (page / "index.html").open("a") as stream:
                stream.write(f'<a href="{wheel.resolve().as_uri()}">{wheel.name}</a>\n')

        os.environ["DINKSTER_PROBE_DEPENDENCY_SOURCE"] = "index"
        os.environ["DINKSTER_PROBE_PACKAGE_INDEX_URL"] = index.as_uri()
        settings = ServerSettings.from_environment()
        source = root / "pack"
        shutil.copytree(FIXTURE_ROOT / "example-pack", source)
        manifest = source / "dinkster-pack.toml"
        torch_requirement = "torch>=99" if case == "incompatible" else "torch==2.7.1+cpu"
        manifest.write_text(
            manifest.read_text()
            .replace('publisher = "dinkster"\n', "")
            .replace('namespaces = ["example"]', 'namespaces = ["example-pack"]')
            .replace(
                "[pack]\n",
                '[pack]\nrequires = ["' + torch_requirement + '", "torchvision==0.22.1+cpu"]\n',
            )
        )
        nodes = source / "nodes.py"
        nodes.write_text(
            "import torch\nimport torchvision\n"
            "assert torch.version.cuda is None\n"
            "assert torch.arange(3).sum().item() == 3\n"
            "assert torchvision.ops.nms(torch.tensor([[0., 0., 2., 2.]]), "
            "torch.tensor([0.9]), 0.5).tolist() == [0]\n"
            + nodes.read_text().replace("example.", "example-pack.")
        )
        database = Database(f"sqlite:///{root / 'catalog.db'}")
        try:
            service = AdmissionService(
                database,
                LocalFilesystemObjectStore(root / "objects"),
                settings=settings,
                require_isolation=True,
            )
            candidate = service.submit(
                build_registry_fixture_archive(source), pack_name="example-pack", version="1.2.3"
            )
            for _ in range(5):
                assert service.run_once(), "scanner stopped before a terminal candidate state"
                status = service.status(candidate)
                if status.status in {"accepted", "rejected", "review"}:
                    break
            codes = [finding.code for finding in status.findings]
            with database.session() as session:
                releases = list(session.scalars(select(ReleaseRecord)))
                scans = list(session.scalars(select(ReleaseScanRunRecord)))
                print(
                    json.dumps(
                        {
                            "case": case,
                            "status": status.status,
                            "findings": codes,
                            "releaseStates": [release.state for release in releases],
                            "operatorDetails": [scan.operator_details for scan in scans],
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
                if case == "complete":
                    assert status.status == "accepted", status
                    assert len(releases) == 1 and releases[0].state == "active"
                else:
                    assert status.status == "rejected", status
                    assert "probe.dependencies-unresolved" in codes
                    assert not releases
        finally:
            database.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Check a disposable scanner with staged CPU wheels"
    )
    parser.add_argument("wheels", type=Path)
    args = parser.parse_args()
    for case in ("complete", "missing", "incompatible"):
        check_candidate(args.wheels, case)


if __name__ == "__main__":
    main()
