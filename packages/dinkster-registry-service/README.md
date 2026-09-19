# dinkster-registry-service

`dinkster-registry-service` adds durable state and an aiohttp surface above the
pure `dinkster-registry` model. `RegistryStore` keeps principals, grants,
releases, review evidence, and audit records in one SQLite file, while
`ArtifactVault` stores immutable archive bytes by digest.

## Setup

This package is a uv workspace member and is not published separately yet.
From the repository root:

```sh
uv sync --all-packages
uv run dinkster-registry --data ./registry-data serve
```

The `dinkster-registry` console script is supplied by the umbrella package. Its
`admin` subcommands bootstrap users, publishers, operators, and publish
tokens directly against the same data directory.

## Use

The HTTP surface is:

- `GET /artifacts/{file}` for unauthenticated, content-addressed downloads
- `PUT /artifacts/{file}` for bearer-token-authenticated upload
- `POST /publish` for bearer-token-authenticated admission
- `GET /index/packs` and `GET /index/packs/{pack}`
- `GET /index/packs/{pack}/versions/{version}`
- `GET /index/templates`
- `GET /index/packs/{pack}/versions/{version}/templates/{template_id}`

Downloads intentionally use public-registry semantics; uploads and publish
requests require `Authorization: Bearer dinkster_pat_...`. On publish, the
umbrella entry point injects `artifact_prober()`, which unpacks the stored
artifact and runs Dinkster's doctor on those exact bytes. Pack identity,
namespace claims, node types, and doctor findings therefore come from the
registry's own probe, never from publisher assertions.

`serve` takes `--probe-sandbox {required,off}` to control publish-probe
isolation. `required` jails the doctor's import probe - the one admission
stage that executes publisher code - in a network-less, CPU- and
file-size-limited bubblewrap sandbox (Linux only), and refuses to START if
the jail cannot be built; a required server never probes unjailed, and a
jail that breaks mid-flight surfaces as a probe-failed finding, never an
unjailed retry. `off` is the explicit lab posture: it warns loudly at
startup and runs the probe as a plain subprocess with only a timeout. The
default is currently `off` and flips to `required` before any non-lab
deployment.

Python composition starts with `RegistryStore`, `ArtifactVault`, and
`create_registry_app`. A service created without a prober can mirror
artifacts but refuses publishing.

## Design contract

The registry indexes by execution, never by scraping: the node inventory is
what the doctor probe actually loads (`define_schema()` in a disposable
subprocess), and the schema wire is the index - a pack the probe cannot
load is not indexed, so there is no parallel view to drift. The registry's
admission predicate is the same `diagnose()` a pack author runs locally via
the doctor's versioned, additive-only `--json` report, so "doctor-clean
locally" and "accepted by the registry" cannot drift apart. Namespaces are
owned, not inferred. Focused coverage is in
`tests/test_registry_service.py` and `tests/test_registry_store.py`.
