# HTTP Conformance Runner

`run.py` checks a running registry containing the two fixture packs. It
browses the catalog, resolves a node provider, verifies conditional GET, and
downloads an artifact whose BLAKE3 digest and size match its ticket.

```sh
uv run python conformance/run.py http://127.0.0.1:8000
```
