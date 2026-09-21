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
