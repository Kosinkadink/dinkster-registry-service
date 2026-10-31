# HTTP Conformance Runner

`run.py` checks a running registry containing the two fixture packs. It
browses the catalog, resolves a node provider, verifies conditional GET, and
downloads an artifact whose BLAKE3 digest and size match its ticket. This same
runner is the acceptance gate for PostgreSQL and SQLite deployments.

```sh
uv run python conformance/run.py http://127.0.0.1:8000
```

For SQLite, set `DINKSTER_DATABASE_URL=sqlite:///.data/conformance.db` for both
`seed` and `serve`; no migration command is needed because the service creates
the SQLite schema on first open.

## Published release catalog

Production does not need fixture packs. Supply the exact `official-packs.lock`
from the release whose unchanged ZIPs were accepted by the deployed scanner:

```sh
uv run python conformance/run.py https://registry.dinkster.org \
  --release-lock /path/to/official-packs.lock
```

This mode verifies every locked name appears in the paginated public catalog,
both static indexes contain every name/version/digest, release details are
active with that digest, every advertised node resolves to that locked
provider (including prereleases), and downloaded bytes match the locked
BLAKE3 and ticket size. Catalog pages and both static indexes must return
empty HTTP304 with unchanged ETag/cache policy on conditional GET. Additional
published packs are allowed; missing or mismatched locked releases fail.
The command only reads public metadata and requests download tickets; it does
not seed, publish, rescan or modify the catalog. Default fixture mode retains
its exact two-pack checks.
