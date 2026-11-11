from __future__ import annotations

import argparse
import json
import os
import socket
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

import uvicorn
from dinkster_registry import RegistryError

from .admission import AdmissionService
from .app import create_app
from .database import Database
from .indexes import StaticIndexes
from .object_store import MAX_ARTIFACT_SIZE
from .ownership import transfer_ownership
from .principals import PrincipalRepository
from .seed import seed_fixtures
from .settings import ServerSettings


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dinkster-registry")
    subparsers = parser.add_subparsers(dest="command", required=True)
    seed_parser = subparsers.add_parser("seed", help="load the two public fixture packs")
    seed_parser.add_argument("--database-url")
    seed_parser.add_argument("--object-store-root")

    indexes_parser = subparsers.add_parser(
        "rebuild-indexes", help="publish both public static indexes"
    )
    indexes_parser.add_argument("--database-url")
    indexes_parser.add_argument("--object-store-root")

    serve_parser = subparsers.add_parser("serve", help="run the registry HTTP service")
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--database-url")
    serve_parser.add_argument("--object-store-root")

    submit_parser = subparsers.add_parser(
        "submit", help="submit one pack archive to operator quarantine"
    )
    submit_parser.add_argument("archive", type=Path)
    submit_parser.add_argument("--pack", required=True)
    submit_parser.add_argument("--version", required=True)
    submit_parser.add_argument("--submitted-by", default="operator")
    submit_parser.add_argument("--publisher", help="existing registry-local publisher id")
    submit_parser.add_argument("--database-url")
    submit_parser.add_argument("--object-store-root")

    status_parser = subparsers.add_parser(
        "status", help="show operator-only release candidate status"
    )
    status_parser.add_argument("candidate_id", type=UUID)
    status_parser.add_argument("--database-url")
    status_parser.add_argument("--object-store-root")

    scanner_parser = subparsers.add_parser("scanner", help="run the lease-based quarantine scanner")
    scanner_parser.add_argument("--once", action="store_true")
    scanner_parser.add_argument("--worker-id", default=f"{socket.gethostname()}:{os.getpid()}")
    scanner_parser.add_argument("--lease-seconds", type=int, default=60)
    scanner_parser.add_argument("--poll-seconds", type=float, default=1.0)
    scanner_parser.add_argument("--database-url")
    scanner_parser.add_argument("--object-store-root")

    rescan_parser = subparsers.add_parser(
        "rescan", help="queue static and security checks for an active release"
    )
    rescan_parser.add_argument("--pack", required=True)
    rescan_parser.add_argument("--version", required=True)
    rescan_parser.add_argument("--submitted-by", default="operator")
    rescan_parser.add_argument("--database-url")
    rescan_parser.add_argument("--object-store-root")

    admin_parser = subparsers.add_parser(
        "admin", help="manage users, publishers, tokens, and release withdrawals"
    )
    admin_parser.add_argument("--database-url")
    admin_parser.add_argument("--object-store-root")
    admin_commands = admin_parser.add_subparsers(dest="admin_command", required=True)

    yank = admin_commands.add_parser("yank", help="withdraw one active release from indexes")
    yank.add_argument("pack")
    yank.add_argument("version")
    yank.add_argument("--reason", required=True)

    add_user = admin_commands.add_parser("add-user", help="register a user id")
    add_user.add_argument("user")
    add_user.add_argument("--operator", action="store_true")

    add_publisher = admin_commands.add_parser("add-publisher", help="register a publisher")
    add_publisher.add_argument("publisher")
    add_publisher.add_argument("--owner", required=True)

    mint_token = admin_commands.add_parser("mint-token", help="mint a scoped publish token")
    mint_token.add_argument("publisher")
    mint_token.add_argument("--user", required=True)
    mint_token.add_argument("--expires", required=True)
    mint_token.add_argument("--pack")

    list_tokens = admin_commands.add_parser("list-tokens", help="list publish token metadata")
    list_tokens.add_argument("publisher")
    list_tokens.add_argument("--user", required=True)

    revoke_token = admin_commands.add_parser("revoke-token", help="revoke a publish token")
    revoke_token.add_argument("token")
    revoke_token.add_argument("--user", required=True)
    revoke_token.add_argument("--reason", required=True)

    freeze_publisher = admin_commands.add_parser(
        "freeze-publisher", help="freeze a disputed publisher and revoke its publishing tokens"
    )
    freeze_publisher.add_argument("publisher")
    freeze_publisher.add_argument("--user", required=True)
    freeze_publisher.add_argument("--reason", required=True)
    bind_publisher = admin_commands.add_parser(
        "bind-publisher", help="bind or transfer a publisher to a confirmed Dinkster identity"
    )
    bind_publisher.add_argument("publisher")
    bind_publisher.add_argument("--user", required=True)
    bind_publisher.add_argument("--identity-subject", required=True)
    bind_publisher.add_argument(
        "--expected-owner", required=True, help="current subject or unbound"
    )
    bind_publisher.add_argument("--reason", required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    settings = ServerSettings.from_environment()
    if getattr(args, "database_url", None) is not None:
        settings = replace(settings, database_url=args.database_url)
    if getattr(args, "object_store_root", None) is not None:
        settings = replace(settings, object_store_root=Path(args.object_store_root))
    if args.command == "rebuild-indexes":
        database = Database(settings.database_url)
        try:
            count = StaticIndexes(
                database, settings.create_object_store(), settings.public_base_url
            ).rebuild()
            print(f"Published pack and locale indexes for {count} releases.")
        finally:
            database.dispose()
        return
    if args.command == "seed":
        database = Database(settings.database_url)
        try:
            result = seed_fixtures(database, settings.create_object_store())
        finally:
            database.dispose()
        print(
            f"Fixture catalog ready: 2 packs; created {result.packs_created} packs, "
            f"{result.releases_created} releases, and {result.artifacts_created} artifacts."
        )
        return
    if args.command == "serve":
        app = create_app(settings)
        uvicorn.run(app, host=args.host, port=args.port, proxy_headers=False)
        return
    if args.command == "admin":
        database = Database(settings.database_url)
        principals = PrincipalRepository(database)
        now = datetime.now(UTC).isoformat()
        try:
            if args.admin_command == "yank":
                AdmissionService(database, settings.create_object_store(), settings=settings).yank(
                    args.pack, args.version, reason=args.reason
                )
                print(f"yanked {args.pack} {args.version}; public indexes rebuilt")
            elif args.admin_command == "add-user":
                principals.register_user(args.user)
                if args.operator:
                    principals.add_operator(args.user, args.user, now)
                print(f"registered user {args.user}" + (" (operator)" if args.operator else ""))
            elif args.admin_command == "add-publisher":
                publisher = principals.register_publisher(args.publisher, args.owner, now)
                print(f"registered publisher {publisher} owned by {args.owner}")
            elif args.admin_command == "mint-token":
                plaintext, token = principals.mint_token(
                    args.publisher,
                    args.user,
                    now,
                    args.expires,
                    pack=args.pack,
                )
                print(plaintext)
                print(
                    f"token {token.token_id} for {token.publisher}, expires {token.expires_at}",
                    file=sys.stderr,
                )
            elif args.admin_command == "list-tokens":
                for token in principals.administered_tokens(args.publisher, args.user):
                    scope = token.pack or "*"
                    state = f"revoked ({token.revoked_reason})" if token.revoked else "active"
                    print(
                        f"{token.token_id}\t{token.minted_by}\t{scope}\t{token.expires_at}\t{state}"
                    )
            elif args.admin_command == "freeze-publisher":
                principals.freeze_publisher(args.publisher, args.user, now, args.reason)
                print(f"froze publisher {args.publisher}; publishing tokens revoked")
            elif args.admin_command == "bind-publisher":
                with database.session() as session, session.begin():
                    if not database.is_postgresql:
                        session.connection().exec_driver_sql("BEGIN IMMEDIATE")
                    event_id = transfer_ownership(
                        session,
                        actor=args.user,
                        subject_kind="publisher",
                        subject_id=args.publisher,
                        expected_owner=(
                            None if args.expected_owner == "unbound" else args.expected_owner
                        ),
                        target_owner=args.identity_subject,
                        reason=args.reason,
                        at=datetime.now(UTC),
                    )
                print(f"bound publisher {args.publisher}; audit event {event_id}")
            else:
                principals.revoke_token(args.token, args.user, now, args.reason)
                print(f"revoked token {args.token}")
        except RegistryError as exc:
            raise SystemExit(f"error: {exc}") from None
        finally:
            database.dispose()
        return

    database = Database(settings.database_url)
    service = AdmissionService(
        database,
        settings.create_object_store(),
        settings=settings,
        worker_id=getattr(args, "worker_id", "registry-operator"),
        lease_seconds=getattr(args, "lease_seconds", 60),
    )
    try:
        if args.command == "submit":
            archive_size = args.archive.stat().st_size
            if not 1 <= archive_size <= MAX_ARTIFACT_SIZE:
                raise SystemExit(f"archive must be between 1 and {MAX_ARTIFACT_SIZE} bytes")
            candidate_id = service.submit(
                args.archive.read_bytes(),
                pack_name=args.pack,
                version=args.version,
                submitted_by=args.submitted_by,
                publisher=args.publisher,
            )
            print(candidate_id)
        elif args.command == "status":
            status = service.status(args.candidate_id)
            print(
                json.dumps(
                    {
                        "id": str(status.id),
                        "kind": status.kind,
                        "pack": status.pack_name,
                        "version": status.version,
                        "digest": status.digest,
                        "size": status.size,
                        "status": status.status,
                        "reason": status.reason,
                        "attempts": status.attempts,
                        "findings": [
                            {
                                "code": finding.code,
                                "severity": finding.severity,
                                "effect": finding.effect,
                                "message": finding.message,
                            }
                            for finding in status.findings
                        ],
                    },
                    indent=2,
                )
            )
        elif args.command == "rescan":
            print(service.schedule_rescan(args.pack, args.version, submitted_by=args.submitted_by))
        elif args.once:
            service.run_once()
        else:
            service.run(poll_seconds=args.poll_seconds)
    finally:
        database.dispose()


if __name__ == "__main__":
    main()
