from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import shutil
import subprocess
import threading
import urllib.request
import zipfile
from datetime import UTC, datetime
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from runtime_fixture import RuntimeFixture
from sqlalchemy import select

from dinkster_registry_service.admission import AdmissionService
from dinkster_registry_service.app import create_app
from dinkster_registry_service.artifacts import build_registry_fixture_archive
from dinkster_registry_service.database import Database, NamespaceGrantRecord, ReleaseRecord
from dinkster_registry_service.digests import artifact_digest
from dinkster_registry_service.indexes import StaticIndexes
from dinkster_registry_service.object_store import LocalFilesystemObjectStore
from dinkster_registry_service.principals import PrincipalRepository
from dinkster_registry_service.seed import FIXTURE_ROOT
from dinkster_registry_service.settings import ServerSettings
from dinkster_registry_service.wheels import WheelError, extracted_wheel, inspect_wheel


def wheel_bytes(
    *,
    name: str = "demo-nodes",
    package: str = "demo_nodes",
    version: str = "1.2.3",
    library: bool = False,
    extra: dict[str, bytes] | None = None,
    requirements: tuple[str, ...] = ("demo-core>=2",),
) -> bytes:
    dist = f"{name.replace('-', '_')}-{version}.dist-info"
    files = {
        f"{dist}/METADATA": (
            f"Metadata-Version: 2.4\nName: {name}\nVersion: {version}\n"
            + "".join(f"Requires-Dist: {value}\n" for value in requirements)
            + "\n"
        ).encode(),
        f"{dist}/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        f"{package}/__init__.py": b"ANSWER = 42\n",
    }
    if not library:
        files[f"{package}/dinkster-pack.toml"] = (
            f'[pack]\nname = "{name}"\nversion = "{version}"\n'
        ).encode()
        files[f"{package}/locales/en.json"] = b'{"title":"Example"}'
    files.update(extra or {})
    record = io.StringIO()
    writer = csv.writer(record, lineterminator="\n")
    for path, payload in sorted(files.items()):
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=")
        writer.writerow((path, "sha256=" + digest.decode(), str(len(payload))))
    writer.writerow((f"{dist}/RECORD", "", ""))
    files[f"{dist}/RECORD"] = record.getvalue().encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, payload in files.items():
            archive.writestr(path, payload)
    return output.getvalue()


def test_wheel_identity_and_probe_assets() -> None:
    data = wheel_bytes()
    wheel = inspect_wheel(data, "demo-nodes", "1.2.3")
    assert wheel.filename == "demo_nodes-1.2.3-py3-none-any.whl"
    assert wheel.imports == ("demo_nodes",)
    assert wheel.requirements == ("demo-core>=2",)
    assert wheel.sha256 == hashlib.sha256(data).hexdigest()
    assert not wheel.library
    with extracted_wheel(data, wheel) as root:
        assert (root / "demo_nodes/__init__.py").read_bytes() == b"ANSWER = 42\n"
        assert (root / "locales/en.json").read_bytes() == b'{"title":"Example"}'
        assert (root / "dinkster-pack.toml").read_bytes() == (
            root / "demo_nodes/dinkster-pack.toml"
        ).read_bytes()
        assert not (root / "__init__.py").exists()


def test_library_is_identified_by_absence_of_manifest() -> None:
    wheel = inspect_wheel(wheel_bytes(library=True), "demo-nodes", "1.2.3")
    assert wheel.library
    assert wheel.manifest_path is None
    assert wheel.imports == ("demo_nodes",)


@pytest.mark.parametrize("library", (False, True))
@pytest.mark.parametrize("tag", ("cp312-cp312-manylinux_2_17_x86_64", "py3-none-win_amd64"))
def test_native_release_is_refused(library: bool, tag: str) -> None:
    data = wheel_bytes(
        library=library,
        extra={
            "demo_nodes-1.2.3.dist-info/WHEEL": (
                f"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: {tag}\n"
            ).encode()
        },
    )
    with pytest.raises(WheelError) as error:
        inspect_wheel(data, "demo-nodes", "1.2.3")
    assert error.value.code == "wheel.platform-unsupported"


@pytest.mark.parametrize(
    ("path", "code"),
    [
        ("demo_nodes/startup.pth", "wheel.pth-forbidden"),
        ("demo_nodes-1.2.3.dist-info/entry_points.txt", "wheel.entry-point-forbidden"),
        ("demo_nodes-1.2.3.data/scripts/demo", "wheel.entry-point-forbidden"),
        ("unrelated/__init__.py", "wheel.import-name"),
        ("../escaped.py", "wheel.invalid"),
        ("demo_nodes/../escaped.py", "wheel.invalid"),
        ("demo_nodes\\escaped.py", "wheel.invalid"),
    ],
)
def test_wheel_refuses_unsafe_members_with_named_error(path: str, code: str) -> None:
    with pytest.raises(WheelError) as error:
        inspect_wheel(wheel_bytes(extra={path: b"payload"}), "demo-nodes", "1.2.3")
    assert error.value.code == code


def test_wheel_refuses_mismatched_distribution_and_tampered_record() -> None:
    with pytest.raises(WheelError) as error:
        inspect_wheel(wheel_bytes(name="other-name"), "demo-nodes", "1.2.3")
    assert error.value.code == "wheel.distribution-name"
    data = wheel_bytes()
    rewritten = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as source, zipfile.ZipFile(rewritten, "w") as output:
        for info in source.infolist():
            payload = source.read(info)
            if info.filename == "demo_nodes/__init__.py":
                payload = b"ANSWER = 43\n"
            output.writestr(info, payload)
    with pytest.raises(WheelError, match="RECORD does not match") as error:
        inspect_wheel(rewritten.getvalue(), "demo-nodes", "1.2.3")
    assert error.value.code == "wheel.invalid"


def test_old_zip_is_not_a_wheel() -> None:
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w") as archive:
        archive.writestr("dinkster-pack.toml", '[pack]\nname = "demo-nodes"\n')
    with pytest.raises(WheelError) as error:
        inspect_wheel(data.getvalue(), "demo-nodes", "1.2.3")
    assert error.value.code == "wheel.required"


@pytest.mark.parametrize(
    ("path", "payload", "status", "code"),
    [
        (
            "config.txt",
            b"AK" + b"IA" + b"1234567890ABCDEF",
            "rejected",
            "security.confirmed-secret",
        ),
        ("extension.so", b"native inventory", "review", "security.native-binary"),
    ],
)
def test_library_payloads_receive_security_checks(
    tmp_path: Path, path: str, payload: bytes, status: str, code: str
) -> None:
    database = Database(f"sqlite:///{tmp_path / 'catalog.db'}")
    try:
        service = AdmissionService(
            database, LocalFilesystemObjectStore(tmp_path / "objects"), require_isolation=False
        )
        data = wheel_bytes(library=True, extra={f"demo_nodes/{path}": payload})
        candidate = service.submit(data, pack_name="demo-nodes", version="1.2.3")
        assert service.run_once()
        result = service.status(candidate)
        assert result.status == status, result
        assert any(finding.code == code for finding in result.findings), result
    finally:
        database.dispose()


def test_library_admission_static_download_collision_and_yank(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'catalog.db'}"
    database = Database(url)
    store = LocalFilesystemObjectStore(tmp_path / "objects")
    service = AdmissionService(database, store, require_isolation=False)
    data = wheel_bytes(library=True)
    candidate = service.submit(data, pack_name="demo-nodes", version="1.2.3")
    assert service.run_once()
    assert service.status(candidate).status == "accepted"
    assert service.run_once()
    with database.session() as session:
        assert list(session.scalars(select(NamespaceGrantRecord))) == []
    app = create_app(ServerSettings(database_url=url, object_store_root=store.root))
    with TestClient(app) as client:
        index = client.get("/static/cpu/simple/demo-nodes/")
        assert index.status_code == 200
        wheel = inspect_wheel(data, "demo-nodes", "1.2.3")
        assert f"#sha256={wheel.sha256}" in index.text
        assert index.text.count(f">{wheel.filename}</a>") == 1
        catalog_entry = client.get("/static/packs/index.json").json()["items"][0]
        entry = client.get("/static/" + catalog_entry["url"]).json()["items"][0]
        assert not {"filename", "sha256", "url", "size", "digest"}.intersection(entry)
        assert len(entry["wheels"]) == 1
        assert entry["wheels"][0]["sha256"] == wheel.sha256
        assert entry["wheels"][0]["tags"] == ["py3-none-any"]
        assert entry["engine"] is None
        assert client.get("/static/" + entry["wheels"][0]["url"]).content == data
        detail = client.get("/v1/packs/demo-nodes/versions/1.2.3")
        assert detail.status_code == 200
        assert detail.json()["manifest"] == {
            "kind": "library",
            "pythonRequirements": ["demo-core>=2"],
        }
        assert detail.json()["nodes"] == []
        versions = client.get("/v1/packs/demo-nodes/versions")
        assert versions.status_code == 200
        assert versions.json()["items"][0]["dinkster"] is None
        assert versions.json()["items"][0]["license"] is None
        denied = client.put("/static/cpu/simple/demo-nodes/", content=b"changed")
        assert denied.status_code == 400
        assert denied.json()["error"]["code"] == "invalid_request"
        assert client.get("/static/cpu/simple/demo-nodes/").content == index.content
        assert client.get("/static/quarantine/uploads/secret").status_code == 404
        assert not store.exists("static/translations/index.json")
        assert client.get("/static/translations/index.json").status_code == 404
        assert client.get("/static/locales/index.json").json()["items"] == []
        assert client.get("/static/schemas/index.json").json()["items"] == []
        assert client.get("/static/packs/demo-nodes/1.2.3/schemas.json").status_code == 404
        conflict = service.submit(
            wheel_bytes(name="other-library", library=True),
            pack_name="other-library",
            version="1.2.3",
        )
        assert service.run_once()
        assert service.status(conflict).reason == "wheel.import-conflict"
        with database.session() as session, session.begin():
            release = session.scalar(select(ReleaseRecord))
            assert release is not None
            release.state = "yanked"
        StaticIndexes(database, store, "http://testserver").rebuild()
        assert wheel.filename not in client.get("/static/cpu/simple/demo-nodes/").text
        assert client.get("/static/packs/index.json").json()["items"] == []
    database.dispose()


@pytest.mark.parametrize("publisher", (None, "dinkster"))
def test_library_reserved_name_requires_authenticated_publisher(
    tmp_path: Path, publisher: str | None
) -> None:
    database = Database(f"sqlite:///{tmp_path / 'catalog.db'}")
    store = LocalFilesystemObjectStore(tmp_path / "objects")
    service = AdmissionService(database, store, require_isolation=False)
    try:
        if publisher is not None:
            principals = PrincipalRepository(database)
            principals.register_user("operator")
            principals.register_publisher(publisher, "operator", datetime.now(UTC).isoformat())
        candidate = service.submit(
            wheel_bytes(name="dinkster-core", package="dinkster_core", library=True),
            pack_name="dinkster-core",
            version="1.2.3",
            publisher=publisher,
        )
        assert service.run_once()
        if publisher is None:
            assert service.status(candidate).reason == "wheel.reserved-name"
            with database.session() as session:
                assert list(session.scalars(select(ReleaseRecord))) == []
        else:
            assert service.status(candidate).status == "accepted"
    finally:
        database.dispose()


@pytest.mark.parametrize(
    "publisher,declared_publisher",
    [
        ("dinkster", "dinkster"),
        (None, "dinkster"),
        ("dinkster", "someone-else"),
    ],
)
def test_manifest_publisher_matches_authenticated_publisher(
    tmp_path: Path, publisher: str | None, declared_publisher: str
) -> None:
    database = Database(f"sqlite:///{tmp_path / 'catalog.db'}")
    store = LocalFilesystemObjectStore(tmp_path / "objects")
    service = AdmissionService(database, store, require_isolation=False)
    source = tmp_path / "pack"
    shutil.copytree(FIXTURE_ROOT / "example-pack", source)
    manifest_path = source / "dinkster-pack.toml"
    manifest_path.write_text(
        manifest_path.read_text().replace(
            'publisher = "dinkster"', f'publisher = "{declared_publisher}"'
        )
    )
    try:
        if publisher is not None:
            principals = PrincipalRepository(database)
            principals.register_user("operator")
            principals.register_publisher(publisher, "operator", datetime.now(UTC).isoformat())
        candidate = service.submit(
            build_registry_fixture_archive(source),
            pack_name="example-pack",
            version="1.2.3",
            publisher=publisher,
        )
        assert service.run_once()
        status = service.status(candidate)
        if declared_publisher and declared_publisher != publisher:
            assert status.reason == "manifest.publisher-mismatch"
        else:
            assert status.status == "accepted", status
    finally:
        database.dispose()


def test_static_only_pinned_install_imports_library_and_refuses_pack_requirement(
    tmp_path: Path,
    runtime: RuntimeFixture,
) -> None:
    database = Database(f"sqlite:///{tmp_path / 'catalog.db'}")
    store = LocalFilesystemObjectStore(tmp_path / "objects")
    requests: list[str] = []

    class StaticOnly(SimpleHTTPRequestHandler):
        def do_GET(self) -> None:
            requests.append(self.path)
            if not self.path.startswith("/static/"):
                self.send_error(404)
                return
            super().do_GET()

    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(StaticOnly, directory=str(store.root)))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f"http://127.0.0.1:{server.server_port}"
    service = AdmissionService(
        database,
        store,
        require_isolation=False,
        settings=runtime.settings(tmp_path, probe_package_index_url=f"{origin}/static/cpu/simple"),
    )
    try:
        principals = PrincipalRepository(database)
        principals.register_user("operator")
        principals.register_publisher("dinkster", "operator", datetime.now(UTC).isoformat())
        library = wheel_bytes(name="demo-core", package="demo_core", library=True, requirements=())
        candidate = service.submit(library, pack_name="demo-core", version="1.2.3")
        assert service.run_once()
        assert service.status(candidate).status == "accepted"
        source = tmp_path / "pack"
        shutil.copytree(FIXTURE_ROOT / "example-pack", source)
        manifest = source / "dinkster-pack.toml"
        manifest.write_text(
            manifest.read_text().replace("[pack]\n", '[pack]\nrequires = ["demo-core==1.2.3"]\n')
        )
        nodes = source / "nodes.py"
        nodes.write_text("from demo_core import ANSWER\nassert ANSWER == 42\n" + nodes.read_text())
        pack = build_registry_fixture_archive(source)
        library_wheel = inspect_wheel(library, "demo-core", "1.2.3")
        locks = {
            variant: {
                "baseId": runtime.base_ids[variant],
                "artifactDigest": artifact_digest(pack),
                "lock": {
                    "format": "dinkster.pack-lock/1",
                    "pack": "example-pack",
                    "variant": variant,
                    "requiresPython": ">=3.12",
                    "requirements": ["demo-core==1.2.3"],
                    "indexes": [f"{origin}/static/{variant}/simple"],
                    "packages": [
                        {
                            "name": "demo-core",
                            "version": "1.2.3",
                            "wheels": [
                                {
                                    "filename": library_wheel.filename,
                                    "sha256": library_wheel.sha256,
                                    "size": len(library),
                                    "url": (
                                        f"{origin}/static/wheels/{library_wheel.sha256}/"
                                        f"{library_wheel.filename}"
                                    ),
                                }
                            ],
                        }
                    ],
                },
            }
            for variant in ("cpu", "cuda")
        }
        candidate = service.submit(
            pack,
            pack_name="example-pack",
            version="1.2.3",
            publisher="dinkster",
            locks=json.dumps(locks).encode(),
        )
        assert service.run_once()
        assert service.status(candidate).status == "accepted", service.status(candidate)
        assert service.run_once()
        for name in ("demo-core", "example-pack"):
            assert store.read(f"static/cpu/simple/{name}/index.html") == store.read(
                f"static/cuda/simple/{name}/index.html"
            )
        with urllib.request.urlopen(f"{origin}/static/packs/index.json", timeout=10) as response:
            entries = json.load(response)["items"]
        entry = next(item for item in entries if item["name"] == "example-pack")
        with urllib.request.urlopen(f"{origin}/static/{entry['url']}", timeout=10) as response:
            entry = json.load(response)["items"][0]
        assert entry["engine"] == ">=0.9,<1"
        binding = entry["installLocks"]["cpu"]
        with urllib.request.urlopen(f"{origin}/static/{binding['url']}", timeout=10) as response:
            lock_bytes = response.read()
        assert artifact_digest(lock_bytes) == binding["digest"]
        assert len(lock_bytes) == binding["size"]
        dependency = json.loads(lock_bytes)["packages"][0]
        assert (dependency["name"], dependency["version"]) == ("demo-core", "1.2.3")
        pinned_wheel = dependency["wheels"][0]
        pack_wheel = next(w for w in entry["wheels"] if w["tags"] == ["py3-none-any"])
        pins = tmp_path / "requirements.txt"
        pins.write_text(
            f"{entry['name']} @ {origin}/static/{pack_wheel['url']} "
            f"--hash=sha256:{pack_wheel['sha256']}\n"
            f"{dependency['name']} @ {pinned_wheel['url']} --hash=sha256:{pinned_wheel['sha256']}\n"
        )
        environment = tmp_path / "environment"
        subprocess.run(["uv", "venv", str(environment)], check=True, capture_output=True)
        python = environment / "bin/python"
        subprocess.run(
            [
                "uv",
                "pip",
                "install",
                "--python",
                str(python),
                "--no-deps",
                "--no-index",
                "--require-hashes",
                "--only-binary=:all:",
                "-r",
                str(pins),
            ],
            check=True,
            capture_output=True,
        )
        installed = subprocess.run(
            [
                str(python),
                "-c",
                "from importlib.metadata import version; from demo_core import ANSWER; "
                "import example_pack; print(version('demo-core'), version('example-pack'), ANSWER)",
            ],
            check=True,
            text=True,
            capture_output=True,
        )
        assert installed.stdout.strip() == "1.2.3 1.2.3 42"
        assert requests and all(path.startswith("/static/") for path in requests)
        bad = wheel_bytes(
            name="bad-library",
            package="bad_library",
            library=True,
            requirements=("example-pack==1.2.3",),
        )
        rejected = service.submit(bad, pack_name="bad-library", version="1.2.3")
        assert service.run_once()
        assert service.status(rejected).reason == "wheel.requires-pack"
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
        database.dispose()


@pytest.mark.parametrize(
    "state",
    [
        "active",
        "extras",
        "inactive-marker",
        "cycle",
        "conflict",
        "yanked",
        "quarantined",
        "out-of-range",
        "url",
    ],
)
def test_probe_resolves_registry_libraries_with_operator_requirements(
    tmp_path: Path, state: str
) -> None:
    database = Database(f"sqlite:///{tmp_path / 'catalog.db'}")
    store = LocalFilesystemObjectStore(tmp_path / "objects")
    index = tmp_path / "simple"
    for name, package, version in (
        ("operator-only", "operator_only", "1.2.3"),
        ("demo-core", "demo_core", "9.0"),
    ):
        project = index / name
        project.mkdir(parents=True)
        data = wheel_bytes(
            name=name,
            package=package,
            version=version,
            library=True,
            requirements=(),
            extra={f"{package}/__init__.py": b"ANSWER = 7\n"},
        )
        wheel = inspect_wheel(data, name, version)
        path = project / wheel.filename
        path.write_bytes(data)
        (project / "index.html").write_text(f'<a href="{path.as_uri()}">{path.name}</a>')
    service = AdmissionService(
        database,
        store,
        require_isolation=False,
        settings=ServerSettings(probe_package_index_url=index.as_uri()),
    )
    principals = PrincipalRepository(database)
    principals.register_user("operator")
    principals.register_publisher("dinkster", "operator", datetime.now(UTC).isoformat())
    try:
        for name, package, requirements, code in (
            (
                "demo-leaf",
                "demo_leaf",
                ("demo-core>=1",) if state == "cycle" else (),
                b"ANSWER = 35\n",
            ),
            (
                "demo-core",
                "demo_core",
                (
                    'demo-leaf==1.2.3; extra == "leaf"'
                    if state == "extras"
                    else "demo-leaf==1.2.3",
                    "operator-only @ https://example.invalid/untrusted.whl"
                    if state == "url"
                    else "operator-only==1.2.3",
                ),
                b"from demo_leaf import ANSWER as LEAF\n"
                b"from operator_only import ANSWER as OPERATOR\nANSWER = LEAF + OPERATOR\n",
            ),
        ):
            data = wheel_bytes(
                name=name,
                package=package,
                library=True,
                requirements=requirements,
                extra={f"{package}/__init__.py": code},
            )
            candidate = service.submit(data, pack_name=name, version="1.2.3")
            assert service.run_once()
            assert service.status(candidate).status == "accepted"
        if state == "active":
            candidate = service.submit(
                wheel_bytes(
                    name="demo-core",
                    package="demo_core",
                    version="2.0",
                    library=True,
                    requirements=("demo-leaf>=2",),
                ),
                pack_name="demo-core",
                version="2.0",
            )
            assert service.run_once()
            assert service.status(candidate).status == "accepted"
        if state in {"yanked", "quarantined", "inactive-marker"}:
            with database.session() as session, session.begin():
                for release in session.scalars(select(ReleaseRecord)):
                    release.state = "yanked" if state == "inactive-marker" else state
        source = tmp_path / "pack"
        shutil.copytree(FIXTURE_ROOT / "example-pack", source)
        manifest = source / "dinkster-pack.toml"
        version_range = ">=2" if state == "out-of-range" else ">=1,<10"
        extras = "[leaf]" if state == "extras" else ""
        conflict = ', "demo-leaf>=2"' if state == "conflict" else ""
        marker = "; python_version < '0'" if state == "inactive-marker" else ""
        manifest.write_text(
            manifest.read_text().replace(
                "[pack]\n",
                f'[pack]\nrequires = ["demo-core{extras}{version_range}{marker}", '
                f'"operator-only==1.2.3"{conflict}]\n',
            )
        )
        nodes = source / "nodes.py"
        imported = "operator_only" if state == "inactive-marker" else "demo_core"
        expected = 7 if state == "inactive-marker" else 42
        nodes.write_text(
            f"from {imported} import ANSWER\nassert ANSWER == {expected}\n" + nodes.read_text()
        )
        candidate = service.submit(
            build_registry_fixture_archive(source),
            pack_name="example-pack",
            version="1.2.3",
            publisher="dinkster",
        )
        assert service.run_once()
        result = service.status(candidate)
        if state in {"active", "extras", "cycle", "inactive-marker"}:
            assert result.status == "accepted", result
        else:
            assert result.status == "rejected", result
            assert result.reason == "probe.pack-dependencies-unavailable"
            expected_name = "demo-leaf" if state == "conflict" else "demo-core"
            assert any(expected_name in finding.message for finding in result.findings)
            if state == "url":
                assert any("must use the package index" in item.message for item in result.findings)
            else:
                expected_range = ">=2" if state in {"out-of-range", "conflict"} else "<10,>=1"
                assert any(expected_range in finding.message for finding in result.findings)
    finally:
        database.dispose()
