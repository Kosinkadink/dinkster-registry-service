# Local development

Use Python 3.12 and uv. Dependencies are public; no repository token is needed.
The fixture Compose setup is in the [README](../README.md#run-locally).

## SQLite

```sh
uv sync --frozen
uv run dinkster-registry admin --database-url sqlite:///registry-data/registry.db add-user local --operator
uv run dinkster-registry admin --database-url sqlite:///registry-data/registry.db add-publisher local --owner local
DINKSTER_DATABASE_URL=sqlite:///registry-data/registry.db \
  DINKSTER_OBJECT_STORE_ROOT=registry-data/objects \
  uv run dinkster-registry serve --host 127.0.0.1 --port 8791
```

To seed a disposable catalog, run `dinkster-registry seed` with the same database
and object-store settings, then `dinkster-registry rebuild-indexes`. Seeding is
not an admission test. Run `conformance/run.py` against the seeded service.

## PostgreSQL without Compose

For a disposable PostgreSQL database, apply migrations and seed manually:

```sh
export DINKSTER_DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost/dinkster_registry
export DINKSTER_OBJECT_STORE_ROOT=.data/objects
uv run alembic upgrade head
uv run dinkster-registry seed
uv run dinkster-registry rebuild-indexes
uv run dinkster-registry serve --host 127.0.0.1 --port 8000
```

Run `uv run dinkster-registry scanner` in a second shell with the same settings.
Production deployments must provide a shared unpredictable `DINKSTER_CURSOR_SECRET`
and a `DINKSTER_PUBLIC_BASE_URL` clients can reach; do not use development defaults.

## Exercise admission

Start a disposable empty registry, build the deterministic fixture in the
container and submit it:

```sh
DOCKER_BUILDKIT=1 DINKSTER_SEED_FIXTURES=0 docker compose up --build --wait
docker compose exec -T registry dinkster-registry admin add-user operator
docker compose exec -T registry dinkster-registry admin add-publisher dinkster --owner operator
docker compose exec -T registry python -c 'from pathlib import Path; from dinkster_registry_service.artifacts import build_registry_fixture_archive; from dinkster_registry_service.seed import FIXTURE_ROOT; Path("/tmp/example_pack-1.2.3-py3-none-any.whl").write_bytes(build_registry_fixture_archive(FIXTURE_ROOT / "example-pack"))'
candidate_id="$(docker compose exec -T registry dinkster-registry submit /tmp/example_pack-1.2.3-py3-none-any.whl --pack example-pack --version 1.2.3 --publisher dinkster --submitted-by operator)"
docker compose exec -T registry dinkster-registry status "$candidate_id"
curl --fail http://127.0.0.1:18041/v1/packs/example-pack/versions/1.2.3
```

Repeat `status` until `accepted` before the final `curl` (which otherwise returns
404). Schedule a static/security rescan with:

```sh
docker compose exec -T registry dinkster-registry rescan --pack example-pack --version 1.2.3
```

Remove the disposable containers and volumes when finished:

```sh
docker compose down --volumes --remove-orphans --rmi local
```

## Checks

PostgreSQL tests need a disposable database; SQLite tests use temporary databases.
S3 tests start a loopback moto server or use `TEST_S3_ENDPOINT_URL`.

```sh
env -u GH_TOKEN -u GITHUB_TOKEN uv sync --frozen
env -u GH_TOKEN -u GITHUB_TOKEN uv lock --check
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
bash scripts/with-test-postgres.sh uv run pytest -q
uv build --all-packages
```

See [CI](../.github/workflows/ci.yml) for HTTP, container, public submission guide
and pinned first-party wheel checks. `scripts/check-split-scanner.py <image>`
requires OpenSSL and Docker; its disposable HTTPS/jail check is not deployed Fly
credential or Machine lifecycle evidence.

For an offline probe test, stage CPU torch 2.7.1+cpu, torchvision 0.22.1+cpu and
all transitive wheels for the image's Python/platform. Run
`scripts/check-local-index-probe.py /staged` in the service image with external
networking denied and that directory mounted read-only at `/staged`. Nested
bubblewrap requires `--privileged`. This uses a disposable database and store,
not the production registry.

Disposable development registries may set `DINKSTER_PROBE_ENGINE_RELEASE` to a
directory containing an exact `release-manifest.json` and API wheel. Set
`DINKSTER_ENV=development`; this is not a production override.
