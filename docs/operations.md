# Registry operations

## Publishing and ownership

Authors use `https://id.dinkster.org/registry`, sign in, choose their account or
organization and claim the attested publisher. Create an expiring token with an
optional pack restriction, save its one-time value in a secret manager or
publishing workflow secret, and use it on the publish endpoint. Refresh shows
metadata only; revoke on the same page. Ordinary authors need no server access.

For self-hosted identity, configure `DINKSTER_IDENTITY_ISSUER` and, if needed,
`DINKSTER_IDENTITY_AUDIENCE` to match that deployment. API fields and permission
checks are defined by the generated `/docs` reference and the account routes.

For a dispute, use the audited operator command:

```sh
uv run dinkster-registry admin freeze-publisher <publisher> --user <operator> --reason <reason>
```

For a binding or correction:

```sh
uv run dinkster-registry admin bind-publisher <publisher> --user <operator> --identity-subject <subject> --expected-owner <current-subject-or-unbound> --reason <reason>
```

Independently confirm the immutable `u_<UUID>` or `org:<UUID>` identity. Never
infer ownership from a matching email or name. This is not a bulk migration
tool. Initial binding of a reserved name keeps existing tokens until the
confirmed first-party cutover; coordinate that cutover separately.

## Index recovery and withdrawal

Use the service's database and object-store environment settings:

```sh
uv run dinkster-registry rebuild-indexes
uv run dinkster-registry admin yank example-pack 1.2.3 --reason "Replaced by separate packs."
```

If a yank reports an object-store error, retry delivery with `rebuild-indexes`,
not another yank: the withdrawal has already committed. Public caches can retain
old indexes for their 60-second lifetime. Mirror operators must provide the
same read-only CORS headers for cross-origin browser reads, including ETag and
If-None-Match support. Copy static directories unchanged; schema discovery needs
no dynamic routes. Clients with stale catalogs must refuse missing versions,
not substitute another release.

## Scanner provisioning

Follow [production deployment](deployment.md) for secret separation, migration,
rollback and live evidence. Provision the registered worker pool and stage its
separate credentials before deploying the web/scanner startup split; the deploy
workflow does not provision scanners. Do not enable a health-only deployment
while admission is blocked. Remaining live publish and public conformance
acceptance is tracked on [registry acceptance](https://github.com/Kosinkadink/comfy-vibe-station/issues/586).

The Compose scanner is privileged root to allow full nested bubblewrap
namespaces. Production hosts should grant bubblewrap's documented AppArmor
profile and run the scanner as the image's `dinkster` user instead.

Do not put secrets in probe environment variables. The controlled PATH and
locale values passed by Dinkster's six-name allowlist to bubblewrap `--setenv`
arguments remain visible in the host process table until the probe builder
uses a private file descriptor.

Use `dinkster-scanner` for remote workers, not the database-backed
`dinkster-registry scanner`. Configure only `DINKSTER_SCANNER_ORIGIN`,
`DINKSTER_SCANNER_TOKEN` and optional `DINKSTER_SCANNER_RUNTIME_STORE` on the
worker. Keep Fly management credentials on the web side, scoped to the scanner
app. See `ServerSettings` in `src/dinkster_registry_service/settings.py` for
configuration and limits; the software default is not production sizing approval.

Pool Machines must run exactly `dinkster-scanner`, use restart policy `no`,
have no services and no auto-destroy setting. Only the first configured limit
of registered IDs is eligible; extra IDs are not automatic spares. Stop old
controllers before changing that subset. Provisioning, restart policy and
production size/concurrency approval remain operator responsibilities. A
120-second start reservation is retry grace, not a measured provider startup
guarantee.

For offline disposable registries, stage all required wheels in the
operator-controlled index, set `DINKSTER_PROBE_PACKAGE_INDEX_URL` and choose
`DINKSTER_PROBE_DEPENDENCY_SOURCE=index`, then deny external networking. See the
[offline probe check](development.md#checks). Host-process scanners need uv on
PATH; the scanner image includes it.

## Operational observations

The [deployment run](https://github.com/Kosinkadink/dinkster-registry-service/actions/runs/41271898612)
for [the immutable-image deployment](https://github.com/Kosinkadink/dinkster-registry-service/commit/6c08e1a347bc7b1a1150ba8d1ed4d4d49006d879)
deployed both web Machines and verified automatic restoration after a deliberate
failed health check. This does not replace the remaining live admission acceptance.

The complete schema catalog is part of probe stdout. The official Comfy pack's
592-schema report was 888,063 bytes; account for this when choosing a bounded
output limit.

## Outstanding admission work

- [Native wheel sets](https://github.com/Kosinkadink/comfy-vibe-station/issues/670).
- [Dependency and SBOM scanning](https://github.com/Kosinkadink/dinkster-registry/issues/1).
- [Dynamic behavior analysis](https://github.com/Kosinkadink/dinkster-registry/issues/2).
