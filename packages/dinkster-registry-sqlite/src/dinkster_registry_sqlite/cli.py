"""Run and bootstrap a SQLite registry instance.

The prober unpacks the artifact, reads manifest claims, and runs the
doctor over those exact bytes. It is injected through the storage and
HTTP implementation's ``Prober`` seam.

Self-hostable by construction (the private-registry constraint): one
data directory holds the SQLite state and the artifact vault; `serve`
runs the same service a public registry would run. The `admin`
subcommands are the BOOTSTRAP surface for a fresh instance - they
operate directly on the store file (offline, never over HTTP), because
the HTTP auth layer that will mint user identities is still open work;
first-operator bootstrap and role gating are the store's own rules,
not reimplemented here. Every admin mutation lands on the same audit
trail as everything else.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

from aiohttp import web as web
from dinkster_registry import RegistryError, ReleaseTemplate, artifact_digest
from dinkster_registry.artifact import MANIFEST_FILENAME, ArtifactError, unpack_artifact
from dinkster_workers import (
    ManifestError,
    ProbeJail,
    SandboxError,
    detect_probe_jail,
    diagnose,
    load_manifest,
)

from dinkster_registry_sqlite import (
    ArtifactVault,
    ProbeError,
    Prober,
    ProbeResult,
    RegistryStore,
    StoreError,
    create_registry_app,
    utc_now,
)


def artifact_prober(probe_jail: ProbeJail | None = None) -> Prober:
    """The real registry probe: unpack the vault archive into a fresh
    temp directory, read the manifest for the pack's claims (name and
    namespaces - claims the admission gate checks against grants), and
    run the doctor over those exact bytes for the evidence.

    ``probe_jail`` (validated at serve startup via ``detect_probe_jail``)
    runs the doctor's import probe - the one admission stage that executes
    publisher code - in a network-less, rlimit-bounded bwrap jail. A jail
    that breaks mid-flight surfaces as a doctor.probe-failed finding with
    the bwrap stderr in the evidence, never as an unjailed retry."""

    def probe(archive: Path) -> ProbeResult:
        with tempfile.TemporaryDirectory(prefix="dinkster-registry-probe-") as tmp:
            root = Path(tmp)
            try:
                unpack_artifact(archive, root, artifact_digest(archive.read_bytes()))
            except (ArtifactError, OSError) as exc:
                raise ProbeError(str(exc)) from exc
            manifest_path = root / MANIFEST_FILENAME
            try:
                manifest = load_manifest(manifest_path)
            except ManifestError as exc:
                raise ProbeError(str(exc)) from exc
            report = diagnose(manifest_path, probe_jail=probe_jail)
            # Template descriptors ride the release record so browse
            # never re-opens artifacts; paths are recorded relative to
            # the pack root - exactly the artifact's member names.
            pack_root = root.resolve()
            templates = tuple(
                ReleaseTemplate(
                    id=template.id,
                    name=template.name,
                    digest=template.digest,
                    path=template.path.resolve().relative_to(pack_root).as_posix(),
                    description=template.description,
                    tags=template.tags,
                    assets=template.assets,
                )
                for template in manifest.templates
            )
            return ProbeResult(
                pack_name=manifest.name,
                namespaces=manifest.namespaces,
                report_json=report.to_json(),
                templates=templates,
                executes=manifest.executes,
            )

    return probe


def _open(args: argparse.Namespace) -> tuple[RegistryStore, ArtifactVault]:
    data = Path(args.data)
    data.mkdir(parents=True, exist_ok=True)
    return RegistryStore(data / "registry.db"), ArtifactVault(data / "artifacts")


def _cmd_serve(args: argparse.Namespace) -> None:
    probe_jail: ProbeJail | None = None
    if args.probe_sandbox == "required":
        try:
            probe_jail = detect_probe_jail()
        except SandboxError as exc:
            # Fail at startup, not per publish - and never probe unjailed
            # when the operator required a jail.
            print(
                f"dinkster-registry-sqlite: --probe-sandbox required refused: {exc}\n"
                "pass --probe-sandbox off to probe unjailed (lab only)",
                file=sys.stderr,
            )
            raise SystemExit(1) from None
    else:
        print(
            "dinkster-registry-sqlite: probe sandbox OFF - publishes run the import "
            "probe unjailed (lab posture; use --probe-sandbox required for "
            "anything publisher-facing)",
            file=sys.stderr,
        )
    store, vault = _open(args)
    app = create_registry_app(store, vault, prober=artifact_prober(probe_jail))
    print(f"dinkster-registry-sqlite: serving {args.data} on http://{args.host}:{args.port}")
    web.run_app(app, host=args.host, port=args.port, print=None)


def _cmd_add_user(args: argparse.Namespace) -> None:
    store, _ = _open(args)
    store.register_user(args.user)
    if args.operator:
        store.add_operator(args.user, actor=args.user, at=utc_now())
    print(f"registered user {args.user}" + (" (operator)" if args.operator else ""))


def _cmd_add_publisher(args: argparse.Namespace) -> None:
    store, _ = _open(args)
    store.register_publisher(args.publisher, owner=args.owner, at=utc_now())
    print(f"registered publisher {args.publisher} owned by {args.owner}")


def _cmd_mint_token(args: argparse.Namespace) -> None:
    store, _ = _open(args)
    plaintext, record = store.mint_token(
        args.publisher,
        minted_by=args.user,
        at=utc_now(),
        expires_at=args.expires,
        pack=args.pack or None,
    )
    # The one moment plaintext exists: print it, never store it.
    print(plaintext)
    print(
        f"token {record.token_id} for {record.publisher}"
        + (f" (pack {record.pack})" if record.pack else "")
        + f", expires {record.expires_at}",
        file=sys.stderr,
    )


def _cmd_list_tokens(args: argparse.Namespace) -> None:
    store, _ = _open(args)
    for token in store.administered_tokens(args.publisher, args.user):
        scope = token.pack or "*"
        state = f"revoked ({token.revoked_reason})" if token.revoked else "active"
        print(f"{token.token_id}\t{token.minted_by}\t{scope}\t{token.expires_at}\t{state}")


def _cmd_revoke_token(args: argparse.Namespace) -> None:
    store, _ = _open(args)
    store.revoke_token(args.token, actor=args.user, at=utc_now(), reason=args.reason)
    print(f"revoked token {args.token}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="dinkster-registry-sqlite",
        description="Run and bootstrap a Dinkster registry service instance",
    )
    parser.add_argument(
        "--data",
        required=True,
        metavar="DIR",
        help="registry data directory (SQLite state + artifact vault)",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    serve = commands.add_parser("serve", help="run the registry HTTP service")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8791)
    serve.add_argument(
        "--probe-sandbox",
        choices=("required", "off"),
        default="required",
        help="jail the publish probe in a network-less, rlimit-bounded "
        "bwrap sandbox; 'required' refuses to start when the jail cannot "
        "be built (default: required); 'off' is a loud lab-only opt-out",
    )
    serve.set_defaults(func=_cmd_serve)

    admin = commands.add_parser("admin", help="offline bootstrap operations on the store file")
    admin_commands = admin.add_subparsers(dest="admin_command", required=True)

    add_user = admin_commands.add_parser("add-user", help="register a user id")
    add_user.add_argument("user")
    add_user.add_argument(
        "--operator",
        action="store_true",
        help="also grant registry-operator authority (review resolution)",
    )
    add_user.set_defaults(func=_cmd_add_user)

    add_publisher = admin_commands.add_parser(
        "add-publisher", help="register a publisher owned by a user"
    )
    add_publisher.add_argument("publisher")
    add_publisher.add_argument("--owner", required=True, metavar="USER")
    add_publisher.set_defaults(func=_cmd_add_publisher)

    mint = admin_commands.add_parser(
        "mint-token", help="mint a publish token (plaintext printed ONCE)"
    )
    mint.add_argument("publisher")
    mint.add_argument("--user", required=True, help="the member the token acts as")
    mint.add_argument("--expires", required=True, metavar="ISO8601")
    mint.add_argument("--pack", default="", help="optionally scope the token to one pack")
    mint.set_defaults(func=_cmd_mint_token)

    list_tokens = admin_commands.add_parser(
        "list-tokens", help="list a publisher's token metadata (owner only)"
    )
    list_tokens.add_argument("publisher")
    list_tokens.add_argument("--user", required=True, help="publisher owner performing the listing")
    list_tokens.set_defaults(func=_cmd_list_tokens)

    revoke = admin_commands.add_parser("revoke-token", help="revoke a publish token")
    revoke.add_argument("token")
    revoke.add_argument("--user", required=True, help="token minter or publisher owner")
    revoke.add_argument("--reason", required=True)
    revoke.set_defaults(func=_cmd_revoke_token)

    args = parser.parse_args()
    try:
        args.func(args)
    except (RegistryError, StoreError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
