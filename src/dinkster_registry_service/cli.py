from __future__ import annotations

import argparse
import json
import os
import socket
from dataclasses import replace
from pathlib import Path
from uuid import UUID

import uvicorn

from .admission import AdmissionService
from .app import create_app
from .database import Database
from .object_store import MAX_ARTIFACT_SIZE, LocalFilesystemObjectStore
from .seed import seed_fixtures
from .settings import ServerSettings


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dinkster-registry")
    subparsers = parser.add_subparsers(dest="command", required=True)
    seed_parser = subparsers.add_parser("seed", help="load the two public fixture packs")
    seed_parser.add_argument("--database-url")
    seed_parser.add_argument("--object-store-root")

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
    return parser


def main() -> None:
    args = _parser().parse_args()
    settings = ServerSettings.from_environment()
    if args.database_url is not None:
        settings = replace(settings, database_url=args.database_url)
    if args.object_store_root is not None:
        settings = replace(settings, object_store_root=args.object_store_root)
    if args.command == "seed":
        database = Database(settings.database_url)
        try:
            result = seed_fixtures(database, LocalFilesystemObjectStore(settings.object_store_root))
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

    database = Database(settings.database_url)
    service = AdmissionService(
        database,
        LocalFilesystemObjectStore(settings.object_store_root),
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
