# Deploy the registry

The production app is `dinkster-registry` in the `dinkster` organization, primary
region `sjc`, at `https://registry.dinkster.org`. `fly.toml` declares two
always-running shared-cpu-1x, 512 MB Machines and no mounts. Each runs the
nonroot API and lease-based scanner. PostgreSQL holds metadata and durable
outbox/leases; R2 holds quarantine, immutable artifacts and static JSON indexes.
No user data depends on a Machine filesystem. Temporary extracted submissions
and dependency directories are disposable and removed after each scan.

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
use `fromJSON(vars.CI_RUNNERS).linux` on X570; private hosted Actions are not a
fallback. `FLY_DEPLOY_ENABLED` is the explicit production enable switch. Keep
it disabled until the service and release gate are ready. Do not dispatch,
rerun or cancel workflows to obtain deployment evidence.

## Exact-commit CI deployment

Natural pushes to `main` run checks, conformance and container validation. Only
after all three succeed, and production is enabled, the reusable
[deploy workflow](.github/workflows/deploy.yml) runs. It checks out `github.sha`,
builds with that revision label on X570, pushes the image to the existing Fly
registry, and resolves an immutable `registry.fly.io/dinkster-registry@sha256:...`
digest. No repository credential is supplied to the build. Registry Docker
credentials use a private per-run directory that is removed afterward.

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

The image runs uid10001, not root. Fly starts `bash scripts/start-service.sh`.
It detects the upstream full bubblewrap user/PID namespace jail before starting
the API and scanner; a degraded or unavailable jail fails startup. Both children
are supervised: either exiting terminates its sibling and fails the Machine.
The API binds IPv6 port8000; `/healthz` performs an uncached database `SELECT 1`.
There is no fixture seeding or migration in runtime startup.

Local Docker's seccomp/AppArmor can deny namespaces even when Fly's guest
kernel supports them. The CI isolation probe uses a disposable privileged test
container, still uid10001, with no network. This is test permission, not a
production privilege exception. No production root/privileged fallback is
configured. If nonroot Fly isolation fails, preserve the diagnostic and stop;
do not expose a healthy API with a nonfunctional scanner or bypass the jail.
Any necessary Fly exception requires a measured reason recorded on issue586.

## Acceptance evidence

Record the exact landed commit, CI/deploy run URL and immutable image digest on
issue586, and link the successful landed-commit deploy run from README. Local
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

Require a Fly CNAME, valid TLS, health200, exactly two started Machines in sjc,
512 MB shared CPUs and no volumes. Publish through the normal authenticated
API and wait for scanner acceptance; verify the same pack/version/BLAKE3 in
both static indexes and conditional304 on both, without exposing the token.
Run `conformance/run.py` against the public hostname with its documented
fixture catalog; do not claim the fixture-specific runner passes against a
different catalog. Public conformance and the deliberate failed-health deploy
are mandatory remaining acceptance evidence, not implied by a health200.

For the rollback exercise, first confirm a healthy exact-image deployment.
Use a temporary copy of `fly.toml` with only the health path changed to a
nonexistent endpoint, and pass that copy to `scripts/deploy_image.py --config`
with the same immutable image. Require a nonzero deployment result followed by
`Rollback passed Fly and public health checks; deployment remains failed`, then confirm
public health and the restored image/configuration. Preserve the run link on
issue586 and remove the temporary config. Never weaken or disable the health
check to make this exercise pass, and never dispatch a workflow for the drill.
