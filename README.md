# Dinkster Registry

The Dinkster Registry is a FastAPI service for publishing, browsing, and
downloading Dinkster node packs. The same `dinkster-registry-service`
distribution and `dinkster_registry_service` import run with PostgreSQL for a
hosted catalog or SQLite for a self-hosted registry. Immutable pack wheels
live behind an object-store interface; development uses the local filesystem
implementation.

Operators can submit pack wheels to quarantine through the in-process CLI.
Lease-based scanner workers validate every candidate and promote accepted bytes
to immutable artifact storage. Bearer-authenticated HTTP routes accept publisher
submissions and operator review decisions. Pending, rejected, and
operator-review candidates are never visible through public catalog routes.

## Wheel identity and admission

Only wheels are publishable; the old Dinkster ZIP and source distributions are
refused with `wheel.required`. Wheel `METADATA` Name equals the submitted pack
name exactly. A pack ships exactly one top-level import package, named by
replacing every `-` and `.` in its pack name with `_`. The original manifest
is `<import_package>/dinkster-pack.toml`; relative assets live beside it.
`Requires-Dist` matches the manifest's `requires`. Standard WHEEL tags and
RECORD hashes describe every installed file. The registry checks them before
extracting or executing any publisher code. Admitted versions are immutable.
Releases must be `py3-none-any`; other tags or non-pure wheels fail with
`wheel.platform-unsupported`. Native release sets are tracked separately in
[native wheel sets](https://github.com/Kosinkadink/comfy-vibe-station/issues/670).

Named refusals include `wheel.distribution-name`, `wheel.import-name`,
`wheel.pth-forbidden`, `wheel.entry-point-forbidden` (including console scripts),
`wheel.import-conflict`, and `wheel.requires-pack`. Malformed or unsafe wheels
fail with `wheel.invalid`. Import ownership is checked again while catalog
promotion is serialized; concurrent submissions cannot claim the same import.
These rules apply equally to first-party and third-party publishers.

A library wheel has no manifest, node schemas or namespace claims. It uses the
same admission and simple index as packs. Shared code belongs in such a library,
not a Python dependency on another pack. A distribution cannot switch between
library and pack identity (`wheel.library-claims`). A types pack still has a
manifest and is a pack, even when it has zero nodes.
Reserved library names require the authenticated `dinkster` publisher
(`wheel.reserved-name`). A declared manifest publisher must match the authenticated
publisher (`manifest.publisher-mismatch`); declaring a name never grants authority.
Alias and group records require the `dinkster` publisher, and their carriers and
replacement references are checked against the probed schemas
(`translations.invalid`). Libraries appear in the install index but not the schema,
locale or translation catalogs.

## Static public indexes

All installer reads use `/static/`. The registry writes PEP 503 pages at
`/static/<variant>/simple/<normalized-name>/` and the corresponding simple root.
The `cpu` view always exists; admitted installation locks declare additional
variant views. Project links contain the wheel filename and a relative URL to
`../../../wheels/<sha256>/<filename>.whl#sha256=<sha256>`. This SHA-256 hashes the
complete wheel bytes. The registry's BLAKE3 artifact identity remains separate.
Yanked releases are absent from the simple index. Universal wheel pages have
identical bytes across variants. There is no publisher route for editing an
index: the static prefix supports only GET, HEAD and OPTIONS.

`/static/packs/index.json` carries exact wheel filenames, hashes and prefix-relative
URLs, plus admitted installation locks. `/static/locks/` holds those immutable
lock bytes. Schemas, locale catalogs and translation records are indexed at
`/static/schemas/index.json`, `/static/locales/index.json` and
`/static/translations/index.json`. Relative JSON URLs resolve against `/static/`,
not against the directory containing the JSON index. An installer uses the
recorded pins, never unrestricted dependency resolution against the simple index.

Every accepted publish queues a durable rebuild of `packs/index.json` and
`locales/index.json` in the configured object store and immediately
attempts delivery. Both contain deterministic JSON with `schemaVersion: 1` and
an `items` array of active public releases, ordered by pack name and version
text. Each entry includes `name`, `version` and a `wheels` array. Each wheel has
`filename`, whole-file `sha256`, BLAKE3 `digest`, byte `size`, prefix-relative
download `url` and `tags` (currently `["py3-none-any"]`). These artifact fields
exist only in `wheels`, never on the release item. `publisher` is the authenticated publisher id
(null for operator submissions without a publisher); `engine` is the manifest's
engine compatibility range (null for libraries). Locale entries also contain `catalogs`, an
array of locale, SHA-256 digest, and path within the same wheel. An empty array
means the release carries no locale catalog. Quarantine queues a rebuild to
remove the release from both lists.

`/static/replacements/index.json` contains `schemaVersion: 1` and `items`, with
one item per migrated `from` type: `{"from":"old.type","candidates":[...]}`.
Each candidate has `pack`, `version`, `target` (carrier node id), and `rule`
(the unchanged canonical replacement rule, including its conditions and cases).
Only the latest active public release of each first-party pack contributes.
Native schema replacements, alias records and group records contribute; aliases
are searchable by their source node type and ComfyUI class name. Multiple packs
may migrate the same source, so candidates are retained rather than silently
choosing a winner. Targets and their interfaces come from the corresponding
per-pack schema file. Yank and quarantine rebuild the index without those releases.

The same rebuild writes `packs/<name>/<version>/schemas.json` for every public
active or yanked release. These are the admission probe's stored wire schemas,
byte-identical to `GET /v1/packs/<name>/versions/<version>/schemas`; no schema
file is required inside the archive. Files retain the `packName`, `version`,
and `schemas` envelope, including each node's wire version, signature and role.
Schemas of releases no longer publicly readable are removed on rebuild.

`schemas/index.json` contains `schemaVersion: 1` and one `items` entry per
first-party pack with an active public release. First-party means authenticated
publisher `dinkster`, not a matching pack-name prefix. Each entry has `name`,
`publisher`, `version`, `displayName`, `platforms`, `url`, and `digest`. The
highest active PEP 440 version wins. The digest is SHA-256 of the exact schema
file bytes, prefixed with `sha256:`. The URL is relative to the static prefix,
for example `packs/dinkster-upscale/1.0.0/schemas.json`, so a client resolves it
against its configured prefix, not against `schemas/`. Schema files are written
before their index. A mirror copies these directories unchanged and needs no
dynamic registry routes for schema discovery or preview.

The service serves the stored bytes at `/static/packs/index.json` and
`/static/locales/index.json`, plus the schema index and files, with GET/HEAD,
content-derived ETags and `If-None-Match` support (304). Read-only public CORS
exposes ETag and permits conditional browser requests; mirror operators must
provide equivalent CORS headers when serving a different browser origin.
The object-store indexes have a 60-second public cache lifetime. Artifact and
per-version schema bytes remain immutable; only the JSON and simple index keys can be
replaced. Production stores these objects in R2 through the S3 API, not on
local disk.

Index delivery is eventually consistent with SQL acceptance. A storage outage
does not undo an accepted artifact: the scanner retries the durable event after
five seconds. Each object replacement is atomic, but the set is not a single
transaction; a failure between writes can temporarily expose different
snapshots. A retry rebuilds all indexes from current catalog state. PostgreSQL advisory
transaction locks serialize snapshot reads and writes across replicas; SQLite
uses an immediate transaction. A slower writer cannot overwrite a newer
snapshot after another writer completes. Before any publish or rebuild, index
requests return 404 rather than synthesizing a different database view.

Operators can rebuild the indexes from current catalog state with the same
database and object-store environment settings used by the service:

```sh
uv run dinkster-registry rebuild-indexes
```

Seeding development fixtures does not simulate publish acceptance. Run the
rebuild command after `seed` to expose fixtures through the static indexes.

## Production deployment

Two replicas share PostgreSQL metadata, fenced scanner leases and durable
outbox events, plus R2 quarantine/artifacts/indexes. This makes local artifact
volumes unnecessary; the image declares none. The Fly configuration keeps two
512 MB shared-cpu-1x Machines in sjc, each with supervised nonroot API/scanner
processes and full probe-isolation preflight. See [deploy.md](deploy.md) for
secret prerequisites, migration/runtime credential separation, first deploy,
health-checked rollback and the required live evidence.

The [immutable-image deploy workflow](.github/workflows/deploy.yml) runs on hosted Ubuntu
after main's CI gates and only when production is enabled. The
[landed deployment run](https://github.com/Kosinkadink/dinkster-registry-service/actions/runs/41271898612)
for commit `6c08e1a347bc7b1a1150ba8d1ed4d4d49006d879` deployed both Machines
and verified automatic restoration after a deliberate failed health check.
[Issue586](https://github.com/Kosinkadink/comfy-vibe-station/issues/586) tracks
the remaining live publish and public conformance acceptance separately.
Do not enable a health-only deployment while admission is blocked.

Pull requests and main pushes run checks, HTTP conformance, and container
validation in GitHub Actions. Each validation job has a 10-minute bound;
the enabled main-only deployment has a separate 30-minute bound. The required
`CI_RUNNERS` repository variable routes all three CPU-only jobs and deployment
to hosted Ubuntu runners:

```json
{"linux":["ubuntu-latest"],"windows":["windows-latest"],"macos":["macos-latest"],"forkLinux":["ubuntu-latest"]}
```

The workflows do not require a self-hosted runner or run GPU validation.
CI PostgreSQL uses host networking with an ephemeral loopback-only port; image
probes use no network. Each hosted job has its own Docker daemon and temporary
workspace; dependency setup does not require a persistent local cache.
Container validation bounds the gzip-compressed saved image to 200 MB and
inspects the exported filesystem for forbidden caches, Git data and test data.

## Self-host with SQLite

One data directory can hold both SQLite metadata and artifact objects. The
service creates the SQLite schema on first open and adds missing installation
lock columns to existing catalogs without changing their releases. PostgreSQL
uses the Alembic migration. Use the same command and wire contract on both:

```sh
uv sync --frozen
uv run dinkster-registry admin --database-url sqlite:///registry-data/registry.db add-user local --operator
uv run dinkster-registry admin --database-url sqlite:///registry-data/registry.db add-publisher local --owner local
DINKSTER_DATABASE_URL=sqlite:///registry-data/registry.db \
  DINKSTER_OBJECT_STORE_ROOT=registry-data/objects \
  uv run dinkster-registry serve --host 127.0.0.1 --port 8791
```

Run `conformance/run.py` against this deployment after seeding to verify the
same catalog contract used by PostgreSQL. Publishing tokens, publisher and
operator principals, namespace grants, quarantine scanning, and review
resolution all use the shared schema and FastAPI routes on both backends.

## Run the fixture catalog

Requirements are Docker with Compose, Python 3.12, uv, and Git. The pinned
Dinkster source is public and needs no repository token. The second command
starts PostgreSQL 16, migrates and seeds the database, starts the service on
port 18041, and starts one isolated scanner worker.

```sh
env -u GH_TOKEN -u GITHUB_TOKEN uv sync --frozen
DOCKER_BUILDKIT=1 docker-compose up --build --wait
uv run python conformance/run.py http://127.0.0.1:18041
docker-compose down --volumes --remove-orphans --rmi local
```

The conformance runner browses both fixtures, queries the provider for
`example.resize`, repeats a browse request with `If-None-Match`, and downloads
the `example-pack` archive. It recomputes BLAKE3 over the response bytes and
compares the result and byte count with the download ticket.

The fixture seed is idempotent. Re-running the service keeps the same pack,
release, digest, and object identities. The included fixture wheels contain
package-relative manifests and assets with standard METADATA, WHEEL and hashed
RECORD files, sorted paths, fixed timestamps and no links.

## Release admission

Submission, status, and re-scan commands connect directly to the database and
object store. HTTP publishing and review routes require bearer authentication;
there is no unauthenticated publishing path.

Archive checks come from the pinned public `dinkster_registry.archive_admission`
library, also used by engine CI. The service retains catalog ownership, grants,
version collisions, active dependency checks, quarantine, leases, promotion and
index publication. Its validated probe settings use the public `ProbeSettings`
contract; no private source checkout or repository token is needed by engine CI.

The scanner runs these mandatory checks in order:

1. `ingest_integrity`: verifies size, BLAKE3, ZIP structure and CRCs, safe
   paths, regular files, limits, stored compression, and deterministic bytes.
2. `manifest`: invokes the pinned Dinkster manifest parser, validates release and
   catalog fields, checks namespace ownership, and rejects version collisions.
3. `doctor_static`: invokes the pinned Dinkster doctor's static checks against the
   exact extracted object.
4. `executable_probe`: imports the pack in a fresh process under bubblewrap
   with no network, read-only binds, and CPU, memory, process, file-size, and
   wall-time limits. The scanner requires full user and PID namespaces and
   refuses the degraded bubblewrap rung or any host without isolation. Declared
   Python requirements use Dinkster's `requires_for("cpu")`: base `requires` plus
   `[pack.extra-requires].cpu`, with normal platform markers. This CPU-only
   schema probe does not validate other accelerator environments. Wheels are
   installed into a disposable per-submission directory before probing, without
   processing dependency `.pth` startup files. The trusted interpreter and doctor
   load before dependency paths are exposed, and the jail applies limits before
   importing dependencies. Resolution failures are named findings; source builds
   and direct URL requirements are refused. The API image does not carry
   pack-specific dependencies, and the directory is removed after probing.
5. `fast_security`: scans for confirmed secrets and known-bad file hashes and
   inventories native, executable, bytecode-only, and obfuscated content.

The submission URL or CLI version is the release version; `[pack.release]` is
not required or read. Optional paired `[pack] version` and `engine` declarations
use the public compatibility schema; a declared version must match submission,
and the engine range is retained in catalog metadata, not matched against the
registry server's engine. Legacy packs without the pair remain accepted without
inventing a compatible engine range. Optional `dinkster`, `license`, and `repository`
metadata comes from `[pack]`. Missing version ranges and licenses are reported as
empty strings, not invented compatibility or license claims. Dinkster's host/API
contracts remain mandatory. Reserved namespaces require the registry-local
`dinkster` publisher, not merely a publisher string in the submitted manifest.
Exact node-ID claims retain their spelling using Dinkster's shared grammar.
Namespace grants are publisher-exclusive: packs from the same registered
publisher may share exact or overlapping claims. Anonymous operator submissions
remain pack-exclusive, and another publisher cannot take an overlapping claim.
Dependency admission considers active development and pre-release versions
within the declared bounds; it does not select a client installation version.

The development Compose scanner runs as root in a privileged container so
bubblewrap can create full user, PID, mount, and network namespaces on Docker
hosts that restrict unprivileged namespaces. The API container remains
non-root and unprivileged. Production hosts should grant bubblewrap's
documented AppArmor profile and run the scanner as the image's `dinkster` user
instead.

The registry replaces the parent environment with a controlled PATH and locale
while Dinkster constructs the probe jail. Dinkster currently passes its six-name
probe allowlist to bubblewrap through `--setenv` arguments, so these controlled
values remain visible in the host process table until the upstream probe
builder delivers them through a private file descriptor. Do not put secrets in
these variables.

All evidence uses policy `registry-scan/1` and is append-only. By default,
probe stdout and stderr are each capped at 2 MiB; exceeding either cap blocks
the candidate. The complete schema catalog is part of stdout; the official
Comfy pack's 592-schema report occupies 888,063 bytes. Bounded output tails are
stored only in operator details and never copied into public finding messages.
A `block` finding rejects an upload; a blocking active-release re-scan
quarantines that release. A `review` finding
leaves an upload visible only to operators and does not change active bytes
during re-scan. A `signal` finding is non-blocking and is included in accepted
trust evidence. By default, a candidate can be claimed at most three times
before it is rejected with append-only evidence.

The admission transaction rechecks version and namespace conflicts, inserts
the immutable release, schemas, dependencies, trust evidence, audit event, and
promotion outbox event, but leaves the release in `pending_scan`. The outbox
worker verifies and copies the quarantine object to its digest-derived artifact
key. It marks the release active only after that copy succeeds, then removes the
quarantine object. This activation is the public catalog visibility barrier.

To exercise admission instead of loading the fixture catalog, start an empty
registry, build the registry's deterministic test fixture inside the container,
and submit it:

```sh
DOCKER_BUILDKIT=1 DINKSTER_SEED_FIXTURES=0 docker-compose up --build --wait
docker-compose exec -T registry python -c 'from pathlib import Path; from dinkster_registry_service.artifacts import build_registry_fixture_archive; from dinkster_registry_service.seed import FIXTURE_ROOT; Path("/tmp/example-pack.zip").write_bytes(build_registry_fixture_archive(FIXTURE_ROOT / "example-pack"))'
candidate_id="$(docker-compose exec -T registry dinkster-registry submit /tmp/example-pack.zip --pack example-pack --version 1.2.3)"
docker-compose exec -T registry dinkster-registry status "$candidate_id"
curl --fail http://127.0.0.1:18041/v1/packs/example-pack/versions/1.2.3
```

Repeat `status` until it reports `accepted`; before that point the final `curl`
returns 404. The operator can schedule a 30-day static and security re-scan
immediately with:

```sh
docker-compose exec -T registry dinkster-registry rescan --pack example-pack --version 1.2.3
```

Dependency and SBOM scanning is tracked in
[issue 1](https://github.com/Kosinkadink/dinkster-registry/issues/1). Dynamic
behavior analysis is tracked in
[issue 2](https://github.com/Kosinkadink/dinkster-registry/issues/2).

## Public API

All catalog routes are under `/v1` and use camelCase JSON fields:

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/v1/health` | Check database access and fixture counts. |
| POST | `/v1/publish/{name}/versions/{version}` | Submit archive bytes with a publisher token. |
| GET | `/v1/publish/{candidateId}` | Read publisher-scoped admission status. |
| POST | `/v1/reviews/{candidateId}` | Accept or reject a candidate as a registry operator. |
| GET | `/v1/tokens` | List publisher token metadata as an owner. |
| POST | `/v1/tokens/{tokenId}/revoke` | Revoke a publisher token. |
| GET | `/v1/packs` | Search, filter, sort, and browse public packs. |
| GET | `/v1/packs/{name}` | Read pack metadata. |
| GET | `/v1/packs/{name}/versions` | List active releases, optionally including yanks. |
| GET | `/v1/packs/{name}/versions/{version}` | Read immutable release facts and trust signals. |
| GET | `/v1/packs/{name}/versions/{version}/schemas` | Read complete indexed node schemas. |
| GET | `/v1/packs/{name}/versions/{version}/locks/{variant}?baseId={id}` | Read an immutable dependency lock bound to an exact base. |
| GET | `/v1/nodes/{nodeType}/providers` | Find active compatible providers for a node type. |
| POST | `/v1/packs/{name}/versions/{version}/download-tickets` | Get an immutable public artifact URL. |
| GET | `/v1/artifacts/{digest}` | Download and verify an active or yanked public release archive. |
| GET | `/v1/security/blocks` | Read the public digest block feed, currently empty. |

Browse accepts `q`, `ownerType`, `owner`, `nodeType`, `visibility`, `sort`,
`limit`, and opaque `cursor` parameters. Only `visibility=public` is available
without authenticated private-pack support. Version lists accept
`includeYanked`, `limit`, and `cursor`. Node-provider queries accept
`dinksterVersion` and `includePrerelease`.

### Publishing dependency locks

The authenticated publish route also accepts `multipart/form-data` with one
file part named `archive` and one text part named `locks`. The latter is a
JSON map from every supported variant to its exact base identity, source
archive BLAKE3 and existing `dinkster.pack-lock/1` document:

```json
{
  "linux-cpu": {
    "baseId": "sha256:<64 lowercase hex>",
    "artifactDigest": "blake3:<archive hex>",
    "lock": {
      "format": "dinkster.pack-lock/1",
      "pack": "example-pack",
      "variant": "linux-cpu",
      "requiresPython": ">=3.12",
      "requirements": [],
      "indexes": [],
      "packages": []
    }
  }
}
```

Empty package lists are suitable only when the pack has no dependency closure.
The ordinary archive-only request remains unchanged. A lock-bearing request
requires a nonempty map of at most 32 variants, at most 8 MiB of lock input,
and at most 1 MiB per lock. Duplicate JSON keys, mismatched archive/pack/variant
identities, malformed base identities, incorrect JSON field types, unhashed
wheel records, local-file wheel origins and URLs with credentials or no host
refuse before candidate storage. Base identities are publisher bindings, not a
registry assertion that a base is approved or installed. The publisher must
provide the complete supported set; the service never resolves a missing lock
at installation time.

Locks are serialized as canonical JSON and stored through ObjectStore, with
immutable size/BLAKE3 metadata on the candidate and release. Identical retries
return the original candidate; a changed binding for that publication refuses.
The release remains private until every lock and the archive are verified in
immutable storage. A promotion outage retries through the existing outbox.

Release detail exposes `installLocks`, keyed by variant, containing `baseId`,
`artifactDigest`, lock `digest`, `size`, and a relative `url`. Resolve that URL
against the registry origin and pass the exact `baseId` query parameter; a
rolling variant label is insufficient and a different base returns 409. Lock
downloads follow archive visibility (active or yanked, never quarantine), verify
stored bytes, and use the digest ETag and immutable cache policy. Raw archive
releases without attached locks expose an empty map.

Every mutable public GET returns a strong opaque ETag and:

```text
Cache-Control: public, max-age=60, stale-while-revalidate=300
```

A matching `If-None-Match` returns 304 with an empty body, the same ETag, and
the same cache policy. Public 404 responses may be cached for 30 seconds.
Download-ticket responses use `no-store`. Artifact bytes use:

```text
ETag: "blake3:<64 lowercase hex>"
Cache-Control: public, max-age=31536000, immutable
X-Dinkster-Artifact-Digest: blake3:<64 lowercase hex>
```

Errors use one envelope:

```json
{
  "error": {
    "code": "not_found",
    "message": "The requested pack was not found.",
    "retryable": false,
    "requestId": "01990000-0000-7000-8000-000000000006",
    "detail": {"packName": "missing-pack"}
  }
}
```

## Identity and version rules

Pack names use Dinkster's shared closed grammar: 1 through 64 lowercase ASCII
characters, starting with a letter, with alphanumeric segments separated by
one `-`, `_`, or `.`. Separators are equivalent for identity, and hosted
coordinates use canonical hyphen spelling. Namespace validation and conflict
checks call the same pinned `dinkster-schema` functions used by Dinkster.

Pack, owner, and release identities use UUIDv7 values. Release versions are
normalized public PEP 440 versions. Pre-releases, post-releases, and
development releases are accepted; local versions such as `1.2.3+vendor.1`
are rejected. Each release also stores a semantic collision key, so equivalent
spellings such as `1.0` and `1.0.0` cannot both be published for one pack.

Artifact and manifest identifiers use only:

```text
blake3:<64 lowercase hex>
```

Other algorithm tags are invalid. There is no compatibility path for an
artifact, cache entry, or release record using another digest algorithm.

## Storage

Alembic revisions `20260902_0001`, `20260903_0002`, and `20260904_0003` create:

- `packs`: public metadata, globally canonical names, UUIDv7 owners, and the
  current active version.
- `namespace_grants`: canonical pack-name and node-namespace claims.
- `artifacts`: immutable digest, size, media type, manifest digest, and object
  key metadata.
- `releases`: immutable publication facts plus separately mutable lifecycle state.
- `release_nodes`: version-specific node type, schema version, wire version,
  signature, role, and complete schema JSON.
- `release_scan_runs`: append-only accepted and superseded doctor, scan,
  provenance, vulnerability, and candidate-only operator evidence.
- `release_findings`: append-only findings attached to one scan run.
- `release_attestations`: append-only attestation evaluations.
- `release_cloud_evaluations`: append-only cloud eligibility evaluations.
- `release_candidates`: quarantined uploads and active-release re-scan leases.
- `release_dependencies`: immutable declared pack dependencies.
- `audit_events`: append-only operator and activation records.
- `outbox`: idempotent artifact promotion work.

Reads project the latest accepted scan run, latest attestation, and latest
cloud evaluation into the public release DTO. PostgreSQL triggers reject
updates and deletes of artifacts, node evidence, and append-only evidence,
reject release deletion, and prevent deletion of packs that have releases.
Statement-level triggers reject plain and cascading truncation of every durable
catalog table. Candidate identity and upload facts are immutable while scanner
lease and status fields can advance. Audit records and declared dependencies
are append-only.

Artifact size must be between 1 byte and 64 MiB. The local object store writes
accepted bytes atomically, reads them in bounded chunks, and verifies the
declared size and BLAKE3 digest before returning them. Objects live at:

```text
artifacts/blake3/<first-two-hex>/<64-hex>.dinksterpack.zip
```

Quarantined uploads live at `quarantine/uploads/<candidate-uuid>` and are not
addressable by a public route. Admission accepts at most 10,000 entries, 256
MiB expanded content, 64 MiB per file, 1 MiB manifests, and 512-byte UTF-8
paths. Executable probes have a default 30-second wall limit, a 512 MiB
address-space limit, and a 64-process limit in addition to the Dinkster bubblewrap
limits.

Apply and seed manually with:

```sh
export DINKSTER_DATABASE_URL=postgresql+psycopg://postgres:postgres@localhost/dinkster_registry
export DINKSTER_OBJECT_STORE_ROOT=.data/objects
uv run alembic upgrade head
uv run dinkster-registry seed
uv run dinkster-registry serve --host 127.0.0.1 --port 8000
uv run dinkster-registry scanner
```

Configuration uses `DINKSTER_DATABASE_URL`, `DINKSTER_OBJECT_STORE_ROOT`,
`DINKSTER_PUBLIC_BASE_URL`, and `DINKSTER_CURSOR_SECRET`. Development startup also
accepts `DINKSTER_SEED_FIXTURES=0` to keep the catalog empty. PostgreSQL and SQLite
URLs are accepted. Production deployments must provide a shared unpredictable
cursor secret and a public base URL that clients can reach.

`DATABASE_URL` and `PUBLIC_BASE_URL` are aliases; the corresponding `DINKSTER_*`
variables take precedence. Setting all five `S3_ENDPOINT_URL`, `S3_BUCKET`,
`S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, and `S3_REGION` selects S3-compatible
artifact storage for the API and CLI, including quarantine and scanner
promotion. R2 uses region `auto`. Partial configuration is rejected in every
mode. `DINKSTER_ENV=production` requires all five settings and never falls back
to local artifact storage. Local files remain a development/self-hosting choice.

Probe and scanner limits use integer environment variables validated at
startup. Invalid values stop the process with an error naming the variable.

| Variable | Default | Valid range |
| --- | ---: | ---: |
| `DINKSTER_PROBE_TIMEOUT_SECONDS` | 30 | 1-600 seconds |
| `DINKSTER_PROBE_DEPENDENCY_TIMEOUT_SECONDS` | 300 | 1-1800 seconds |
| `DINKSTER_PROBE_OUTPUT_LIMIT_BYTES` | 2097152 | 4096-4194304 bytes per stream |
| `DINKSTER_PROBE_OPERATOR_TAIL_BYTES` | 8192 | 512 bytes through the configured output limit |
| `DINKSTER_SCANNER_MAX_ATTEMPTS` | 3 | 1-10 claims |

`DINKSTER_PROBE_PACKAGE_INDEX_URL` selects the operator-controlled package index
(default `https://pypi.org/simple`). Installer subprocesses do not inherit host
credentials or configuration. The scanner image includes uv; host-process
scanners must also have uv on PATH.

Packs declaring `[pack] node-source = "remote-gateway-catalog"` may publish an
empty offline node catalog. The validated declaration is retained as
`manifest.nodeSource`; undeclared empty packs and entry/schema errors still
reject, and the declaration does not bypass network, ownership or security checks.

## Development

The package targets Python 3.12 and commits `uv.lock`. The hosted service's
tests require a disposable PostgreSQL database; the separate SQLite tests
use temporary databases. S3 contract tests start a native moto HTTP server on
loopback, or use `TEST_S3_ENDPOINT_URL` when provided; they are not skipped in CI.

```sh
env -u GITHUB_TOKEN uv sync --frozen
env -u GITHUB_TOKEN uv lock --check
uv run ruff check .
uv run ruff format --check .
uv run mypy src tests
TEST_POSTGRES_URL=postgresql+psycopg://postgres:postgres@localhost/dinkster_registry_test uv run pytest -q
uv build --all-packages
```

CI runs these checks against PostgreSQL 16, starts the HTTP conformance runner,
builds the container without dependency credentials, inspects image contents,
runs the isolated probe under bubblewrap, and runs conformance against the image.

The container also admits the unchanged first-party wheel in `fixtures/wheels`,
pinned by source commit, size and SHA-256 in `scripts/release-packs.lock`.
It checks wheel identity before isolated admission, then verifies static artifact
bytes and schema ids. The remote pack has an empty node catalog without a gateway;
the separate isolated-probe fixture covers populated schemas. This replaces the
withdrawn ZIP-release download check; CI does not depend on the live registry.
