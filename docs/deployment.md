# Deploy the registry

The production app is `dinkster-registry` in the `dinkster` organization, primary
region `sjc`, at `https://registry.dinkster.org`. `fly.toml` declares two
always-running performance 1 CPU, 2 GB web Machines and no mounts. Each runs
the nonroot API and outbox delivery, never an installer or submitted pack code.
The separate `dinkster-registry-scanner` app contains one performance 1 CPU,
2 GB Machine, stopped when idle, with at most one scanner running. These are
[the approved production settings](https://github.com/Kosinkadink/comfy-vibe-station/issues/866#issuecomment-6842089411);
changing scanner capacity or web size requires a separate operator decision.
PostgreSQL holds metadata and durable outbox/leases; R2 holds quarantine,
immutable artifacts and static JSON indexes. Only the web control plane holds
credentials for those stores and promotes releases.
No user data depends on a Machine filesystem. Temporary extracted submissions
and dependency directories are disposable and removed after each scan.
The executable probe resolves the manifest's CPU requirements using uv's CPU
PyTorch backend; it does not provision CUDA wheels for this CPU-only scan.
Provisioning failures retain bounded installer output and timeout status in
operator-only scan details, never in public findings.

`fly.toml` sets `DINKSTER_PROBE_PACKAGE_INDEX_URL=https://pypi.org/simple`.
This operator index supplies ordinary Python dependencies; uv's CPU Torch
backend also uses `download.pytorch.org`. Registry library requirements use
active public releases selected from SQL and digest-checked wheels staged from
the object store, including nested registry library requirements. Their wheels
are explicit installer inputs, not an additional index. The installer receives
neither object-store credentials nor host configuration. No secret override of
the probe index is required.

## Prerequisites and deployment gate

Do not create a placeholder or health-only registry Machine. Before the first
real deployment, all 14 unchanged official ZIPs from the release named in the
pull request must pass local admission and the release-lock digest gate in CI.
The official packaging correction and this whole-issue acceptance are tracked
on [issue586](https://github.com/Kosinkadink/comfy-vibe-station/issues/586).
Do not enable production while that release gate is absent or red.

The foundations owner supplies the existing app, scoped deploy-token
availability, database URL, R2 bucket/token, and routing. Do not recreate them.
Expected routing is DNS-only CNAME `registry.dinkster.org` to
`dinkster-registry.fly.dev`, shared IPv4, public IPv6 and an existing certificate
request. The certificate must be issued and valid during public acceptance.

Required Fly secrets, never committed or placed in command arguments:

| Name | Purpose |
| --- | --- |
| `DINKSTER_DATABASE_URL` | Named service Writer on MPG database `dinkster-registry` |
| `S3_ENDPOINT_URL` | Cloudflare account R2 S3 endpoint |
| `S3_BUCKET` | `dinkster-registry` |
| `S3_ACCESS_KEY_ID` | Scoped R2 credential |
| `S3_SECRET_ACCESS_KEY` | Scoped R2 credential |
| `S3_REGION` | `auto` |
| `DINKSTER_CURSOR_SECRET` | Shared unpredictable pagination signing secret |

The database and R2 secrets are staged under the foundations handoff. Preserve
them. If the cursor secret is absent, the user or foundations owner runs this
in their own authenticated Bash shell, without tracing or terminal recording:

```bash
set -euo pipefail
set +x
printf 'DINKSTER_CURSOR_SECRET=%s\n' "$(openssl rand -hex 32)" |
  flyctl secrets import --app dinkster-registry --stage
flyctl secrets list --app dinkster-registry
```

Expected output is staging confirmation and secret names/digests only. Stop if
the app/organization is wrong, an existing cursor secret would be replaced, or
any command fails. Do not paste values into issues or threads. Do not run
`secrets deploy` to start a Machine early.

The repository already has `FLY_API_TOKEN` availability handed over by
foundations. Never create or change Actions secrets or deploy keys. All jobs
use `fromJSON(vars.CI_RUNNERS).linux`, configured as `["ubuntu-latest"]` for
hosted Ubuntu. `FLY_DEPLOY_ENABLED` is the explicit production enable switch. Keep
it disabled until the service and release gate are ready. Do not dispatch,
rerun or cancel workflows to obtain deployment evidence.

## Exact-commit CI deployment

Natural pushes to `main` run checks, conformance and container validation. Only
after all three succeed, and production is enabled, the reusable
[deploy workflow](.github/workflows/deploy.yml) runs. It checks out `github.sha`,
builds with that revision label on hosted Ubuntu, pushes the image to the existing Fly
registry, and resolves an immutable `registry.fly.io/dinkster-registry@sha256:...`
linux/amd64 image digest. When the push produces an OCI index, the workflow
retains its digest for provenance and deploys the unique linux/amd64 child so
Fly's runtime identity and first-deployment cleanup compare the same image.
Missing or ambiguous platform children stop deployment.
No repository credential is supplied to the build. Registry Docker
credentials use a private per-run directory that is removed afterward.

Before image push, migration or deployment, the workflow reads only
`flyctl secrets list --json` metadata for the existing app. It prints required
names and known deployment-status labels, not values, digests or raw JSON.
Missing database, cursor or any S3 secret name stops the job. Staged secrets
are allowed for the first real deployment; absent or unrecognized status is
reported as `Unknown`. Presence alone does not prove credential validity or
cursor entropy: normal production startup and live acceptance still apply.

`scripts/migrate_image.py --image <digest>` reads the approved cluster inventory
and short-lived `fly-user` credentials through the authenticated MPG API. It
opens a bounded loopback-only MPG proxy and runs Alembic from that exact image
in a host-networked container. The URL is supplied by environment name, not as
an argument; output redacts URLs, passwords and Fly tokens. Cleanup stops the
owned proxy/container on failure and timeout. No administrator app secret is
installed. The runtime keeps its separate Writer credential. Database schema
changes must remain compatible with the previous image: image rollback does
not reverse migrations or delete published data.

`scripts/deploy_image.py` snapshots the last deployed immutable image and
private remote configuration, then runs `flyctl deploy --image <digest>` with
rolling health checks and half the replicas unavailable at most. `--ha=true`
requests the two service Machines on first deployment; `--no-public-ips`
reuses the existing public allocations. Before discarding rollback state, the
helper checks public HTTPS readiness with bounded retries, including DNS and
TLS verification. A failed public check follows the same rollback path as a
failed Fly health check. Later failure restores the previous
image and configuration, keeps the deploy exit code nonzero, and reports
rollback failure prominently. On a first deployment there is no prior image;
failure removes only newly created Launch-managed Machines carrying the exact
attempted digest, or refuses cleanup on unexpected inventory. It never creates
a fake prior release. Check inventory before retrying any failed operation.

## Scanner isolation and process lifetime

The image runs uid10001, not root. On web Machines Fly starts
`bash scripts/start-service.sh`, which supervises `dinkster-registry serve`
and `dinkster-registry deliver`. Either child exiting terminates its sibling
and fails the web Machine. Neither child runs submitted code or requires a
probe jail. Fly sets `HTTP_HOST=0.0.0.0` for IPv4 proxy and health-check
reachability on port8000; `/healthz` performs an uncached database `SELECT 1`.
There is no fixture seeding or migration in runtime startup. A healthy web API
alone does not prove that scanners are configured or can execute work.

Before deploying this split, provision the separate scanner app and one
registered Machine from the reviewed immutable image. Set its `init.exec` to
`["dinkster-scanner"]`, `restart.policy` to `no`, no services, no auto-destroy
and no mounts. Create it stopped; do not start a second Machine as a spare.
The main-push web deployment workflow does not provision or update this pool.
Record the worker image digest and source revision independently of the web
image. Subsequent worker image changes require their own reviewed deployment;
a web deploy does not silently update the scanner.

The scanner receives only secret `DINKSTER_SCANNER_TOKEN`, nonsecret HTTPS
`DINKSTER_SCANNER_ORIGIN=https://registry.dinkster.org` and optional
`DINKSTER_SCANNER_RUNTIME_STORE`. It authenticates only to bounded leased
claim/input/dependencies/locks/heartbeat/result endpoints. It has no database,
object-store, cursor, signing, publisher or Fly management credential, and
cannot write public indexes. It requires the full bubblewrap user/PID namespace
jail before claiming work; unavailable isolation or ambient control-plane
credentials fail worker startup. Never bypass that check to drain a queue.

Stage these additional web settings without manually deploying the web app:

| Name | Purpose and lifetime |
| --- | --- |
| `DINKSTER_SCANNER_TOKEN_SHA256` | Worker capability's SHA256 verifier; rotate with the worker capability, no automatic protocol expiry |
| `DINKSTER_SCANNER_FLY_TOKEN` | Management credential scoped only to the scanner app, with a 90 day lifetime |
| `DINKSTER_SCANNER_FLY_APP` | `dinkster-registry-scanner` |
| `DINKSTER_SCANNER_MACHINE_IDS` | Exact ID of the single registered stopped Machine |
| `DINKSTER_SCANNER_MACHINE_LIMIT` | `1` |

Keep the plaintext worker capability off web and the Fly credential off the
scanner. The provisioned credential named `registry-scanner-lifecycle-821`
expires February 11, 2027 UTC (February 10 Pacific); renew before expiry and
record the new expiry without printing values. Resource/secret names and
initial state are recorded in the
[provisioning receipt](https://github.com/Kosinkadink/comfy-vibe-station/issues/821#issuecomment-6842395452).
The worker capability has no automatic expiry and must be revoked or rotated
by the operator. Preserve all existing DB/S3/cursor secrets. Verify names,
state, exact image, resource size and limit before landing; do not print raw
configuration, credential values, process arguments or environment dumps.

Outbox delivery reconciles pending or expired assignments against the fixed
pool and records durable start reservations before asking Fly to start the
registered Machine. It cannot provision, update, stop or execute commands on
Machines. Worker PID1 drains eligible work, then exits on an empty queue;
restart=no leaves the Machine stopped. A later arrival restarts it through
reconciliation. Concurrent web replicas share reservations; running
unregistered Machines occupy capacity rather than allowing another start.

A crash, interrupted transport or failed start leaves the candidate eligible
after its lease or start reservation expires. A lost assignment gets a new
fence and stale results cannot promote a release. Infrastructure loss does
not spend the completed probe-timeout retry budget. Actual install/probe
timeouts retain their existing finite retry policy. The web control plane
alone applies verdicts, promotes and delivers public indexes. If the scanner
fails, preserve bounded diagnostics and restore its approved configuration;
do not move execution back onto web or resubmit publication to evade recovery.

Local Docker's seccomp/AppArmor can deny namespaces even when Fly's guest
kernel supports them. The CI isolation probe uses a disposable privileged test
container, still uid10001, with no network. This is test permission, not a
production privilege exception. No production root/privileged fallback is
configured. Any necessary Fly exception requires a measured reason and
explicit authorization. Web-image rollback does not roll back staged secrets,
the scanner image or its configuration. Before removing scanner credentials
or destroying the pool, restore a reviewed compatible web topology through
the ordinary main deployment gate; do not strand the split web service with
no executor. Check actual state before retrying any failed operator action.

## Scanner split acceptance

For the scanner split, record the landed commit, automatic CI/deploy run,
immutable web and worker images, and name/state-only readbacks of the two web
Machines and the single scanner on
[issue821](https://github.com/Kosinkadink/comfy-vibe-station/issues/821).
Web remains performance 1 CPU, 2 GB with two replicas; the scanner starts for
queued work and stops when idle. A staged credential name is not proof that a
worker consumed it: confirm activation and the natural scan after deployment.

Wait for a later natural official publication. Link its original run and
public pack/version/digest, plus scanner Machine start/stop records that
identify the executor. A prior accepted publication, a health200 or local
simulation is not criterion8 evidence. Do not create a fixture submission,
resubmit an official publication, read private database/object-store data or
manually deploy web to manufacture that receipt. Preserve the explicit
operator authorization boundary when collecting evidence.

## Initial service acceptance evidence

The following checks describe the initial service acceptance on issue586,
not permission to repeat its publication or rollback exercise for the scanner
split. Record the exact landed commit, CI/deploy run URL and immutable image
digest on issue586, and link the successful landed-commit deploy run from README. Local
simulator tests are not live deployment/rollback evidence. After the actual
two-replica deployment, run these read-only checks from an authenticated shell:

```bash
dig +short CNAME registry.dinkster.org
curl --fail --silent --show-error -D - https://registry.dinkster.org/healthz
flyctl status --app dinkster-registry
flyctl machines list --app dinkster-registry --json
flyctl volumes list --app dinkster-registry --json
flyctl certs show registry.dinkster.org --app dinkster-registry
```

Require a Fly CNAME, valid TLS, health200, exactly two started web Machines in
sjc at the currently approved performance 1 CPU, 2 GB size and no volumes. Publish through the normal authenticated
API and wait for scanner acceptance; verify the same pack/version/BLAKE3 in
both static indexes and conditional304 on both, without exposing the token.
Run `uv run python conformance/run.py https://registry.dinkster.org --release-lock
/path/to/official-packs.lock` with the exact accepted release lock. This checks
the published catalog without seeding fixture packs into production. Keep the
unchanged default fixture checks for disposable CI stacks.
Public conformance and the deliberate failed-health deploy
are mandatory remaining acceptance evidence, not implied by a health200.

## Deliberate failed-health rollback run

The main-push deployment workflow includes an opt-in rollback exercise after
the normal immutable deployment passes both Fly and public health checks.
`FLY_VERIFY_ROLLBACK` is off unless explicitly set to `true`; it does not bypass
`FLY_DEPLOY_ENABLED`, the main-only condition or any prerequisite. Enable it
only for an eligible real deployment, never to start a placeholder Machine.
The operator sets the nonsecret repository variable before the natural main
push that should supply the receipt:

```bash
gh variable set FLY_VERIFY_ROLLBACK --repo Kosinkadink/dinkster-registry-service --body true
```

The workflow copies `fly.toml` into a temporary directory and changes only the
`/healthz` path to `/__registry-broken-health-check__`. It attempts that config
with the same immutable image through `scripts/deploy_image.py`. Success
requires the attempt to fail and automatic rollback to report
`Rollback passed Fly and public health checks; deployment remains failed`.
Failed restoration fails the workflow. Unexpected acceptance of the bad config
also fails the workflow, after attempting recovery with the healthy checked-in
config; it never counts as a successful drill. Temporary configs and logs are
removed on exit. No normal health check is weakened or disabled.

Preserve the workflow run link, landed commit and digest on issue586, then
confirm public health, both Machine images and restored health configuration.
After the receipt, disable repeat drills before another main push:

```bash
gh variable set FLY_VERIFY_ROLLBACK --repo Kosinkadink/dinkster-registry-service --body false
```

Both commands should exit zero without printing credentials. Stop on a wrong
repository, failed command or unready deployment prerequisite. Never dispatch,
rerun or cancel a workflow for this exercise. Local simulator results prove
the control flow only, not the required live Fly rollback receipt.
