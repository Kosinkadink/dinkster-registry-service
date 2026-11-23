# Dinkster Registry

FastAPI service for publishing, browsing and downloading Dinkster node packs
and library wheels. Hosted catalogs use PostgreSQL and object storage;
self-hosted catalogs can use SQLite and local files.

## Run locally

Install Python 3.12, uv and Docker with Compose, then run the fixture catalog:

```sh
env -u GH_TOKEN -u GITHUB_TOKEN uv sync --frozen
DOCKER_BUILDKIT=1 docker-compose up --build --wait
uv run python conformance/run.py http://127.0.0.1:18041
```

The API is at `http://127.0.0.1:18041`. When finished, remove the disposable
fixture database and containers:

```sh
docker-compose down --volumes --remove-orphans --rmi local
```

For a SQLite setup or a real admission exercise, see
[local development](docs/development.md).

## Reference and operating notes

- Generated API reference: `/docs`, `/redoc` and `/openapi.json` on the service.
- [Local development and checks](docs/development.md).
- [Publishing, index recovery and scanner operations](docs/operations.md).
- [Production deployment](docs/deployment.md).
- [Signed release notices and independent trust](SECURITY-NOTICES.md).
- [Validation record](TESTED.md).
