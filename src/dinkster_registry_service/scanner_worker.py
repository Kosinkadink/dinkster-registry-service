from __future__ import annotations

import argparse
import base64
import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import asdict, replace
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from dinkster_registry.archive_admission import (
    AdmissionFinding,
    ProbeSettings,
    StageResult,
    run_doctor_static,
)
from dinkster_workers.sandbox import detect_probe_jail

from .artifacts import ARCHIVE_LIMIT, EXPANDED_LIMIT
from .scan_execution import ProbeDependencies, run_prepared_probe
from .wheels import extracted_wheel, inspect_wheel, run_wheel_integrity


class ScannerUnavailable(RuntimeError):
    """Leave an interrupted assignment for lease recovery, without a verdict."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class ScannerWorker:
    def __init__(
        self,
        origin: str,
        token: str,
        runtime_store: Path,
        *,
        development: bool = False,
        development_release: Path | None = None,
        development_runtime: Path | None = None,
    ) -> None:
        url = urlsplit(origin)
        if (
            url.scheme not in ({"http", "https"} if development else {"https"})
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.path not in {"", "/"}
            or url.query
            or url.fragment
        ):
            raise ValueError("Scanner origin must be an HTTPS origin without credentials or a path")
        if not token or len(token) > 4096 or "\n" in token or "\r" in token:
            raise ValueError("Scanner bearer capability is missing or invalid")
        if not development and (development_release is not None or development_runtime is not None):
            raise ValueError("Local runtime inputs require development mode")
        self.origin = origin.rstrip("/")
        self._token = token
        self.runtime_store = runtime_store
        self.development_release = development_release
        self.development_runtime = development_runtime
        # Neither ambient proxy credentials nor redirects may receive the capability.
        self._opener = build_opener(ProxyHandler({}), NoRedirect())

    def _request(
        self,
        method: str,
        path: str,
        *,
        lease: str | None = None,
        payload: dict[str, Any] | None = None,
        limit: int = 1024 * 1024,
    ) -> bytes | None:
        headers = {"Authorization": f"Bearer {self._token}"}
        if lease is not None:
            headers["X-Scanner-Lease"] = lease
        data = None if payload is None else json.dumps(payload, allow_nan=False).encode()
        if data is not None:
            if len(data) > 16 * 1024 * 1024:
                raise ScannerUnavailable("Scanner result exceeds its transfer bound")
            headers["Content-Type"] = "application/json"
        request = Request(self.origin + "/internal/scanner" + path, data, headers, method=method)
        try:
            with self._opener.open(request, timeout=30) as response:
                if response.status == 204:
                    return None
                body: bytes = response.read(limit + 1)
        except HTTPError as exc:
            status = exc.code
            exc.close()
            raise ScannerUnavailable(
                f"Scanner control request refused with HTTP {status}"
            ) from None
        except OSError:
            raise ScannerUnavailable("Scanner control request unavailable") from None
        if len(body) > limit:
            raise ScannerUnavailable("Scanner control response exceeds its transfer bound")
        return body

    def _execute(self, claim: dict[str, Any]) -> StageResult | None:
        path = f"/{claim['candidateId']}"
        lease = claim["leaseToken"]
        data = self._request("GET", path + "/input", lease=lease, limit=ARCHIVE_LIMIT)
        if data is None:
            raise ScannerUnavailable("Assigned archive is missing")
        integrity = run_wheel_integrity(
            data,
            claim["artifactSize"],
            claim["artifactDigest"],
            claim["packName"],
            claim["version"],
        )
        if integrity.blocked:
            return None
        wheel = inspect_wheel(data, claim["packName"], claim["version"])
        if claim["kind"] == "rescan" or wheel.library:
            return None
        with extracted_wheel(data, wheel) as root:
            doctor = run_doctor_static(root)
            if doctor.blocked:
                return replace(doctor, data=None)
            resolved = json.loads(
                self._request("GET", path + "/dependencies", lease=lease, limit=2 * EXPANDED_LIMIT)
                or b"null"
            )
            if "failure" in resolved:
                failure = resolved["failure"]
                return StageResult(
                    tuple(AdmissionFinding(**item) for item in failure["findings"]),
                    failure["data"],
                    failure["operator_details"],
                )
            dependencies = ProbeDependencies(
                tuple(base64.b64decode(item, validate=True) for item in resolved["helperWheels"]),
                tuple(
                    (item["filename"], base64.b64decode(item["data"], validate=True))
                    for item in resolved["libraryWheels"]
                ),
                tuple(resolved["requirements"]),
            )
            locks = json.loads(
                self._request("GET", path + "/locks", lease=lease, limit=48 * 1024 * 1024)
                or b"null"
            )
            return run_prepared_probe(
                root,
                dependencies,
                settings=ProbeSettings(**claim["probeSettings"]),
                scan_engine=claim["scanEngine"],
                install_locks=claim["installLocks"],
                lock_bytes={
                    key: base64.b64decode(value, validate=True) for key, value in locks.items()
                },
                artifact_digest=claim["artifactDigest"],
                runtime_store=self.runtime_store,
                development_release=self.development_release,
                development_runtime=self.development_runtime,
            )

    def run_once(self) -> bool:
        data = self._request("POST", "/claim")
        if data is None:
            print(json.dumps({"scannerEvent": "queue-empty"}), flush=True)
            return False
        claim = json.loads(data)
        print(
            json.dumps(
                {
                    "scannerEvent": "claimed",
                    "candidateId": claim["candidateId"],
                    "attempt": claim["attempt"],
                }
            ),
            flush=True,
        )
        path = f"/{claim['candidateId']}"
        lease = claim["leaseToken"]
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self._execute, claim)
            while not wait((future,), timeout=claim["leaseSeconds"] / 3).done:
                self._request("POST", path + "/heartbeat", lease=lease)
            probe = future.result()
        if probe is not None:
            probe = replace(
                probe,
                operator_details={
                    **(probe.operator_details or {}),
                    "scannerHost": socket.gethostname(),
                    "scannerWorker": f"{socket.gethostname()}:{os.getpid()}",
                },
            )
        self._request(
            "POST",
            path + "/result",
            lease=lease,
            payload={
                "artifactDigest": claim["artifactDigest"],
                "probe": asdict(probe) if probe else None,
            },
        )
        print(
            json.dumps(
                {
                    "scannerEvent": "submitted",
                    "candidateId": claim["candidateId"],
                    "attempt": claim["attempt"],
                }
            ),
            flush=True,
        )
        return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run isolated leased probes until the queue is empty"
    )
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    try:
        if any(
            name.startswith(("S3_", "AWS_"))
            or name
            in {
                "DATABASE_URL",
                "DINKSTER_DATABASE_URL",
                "DINKSTER_CURSOR_SECRET",
                "DINKSTER_SECURITY_SIGNING_KEY_PATH",
                "DINKSTER_SCANNER_TOKEN_SHA256",
                "DINKSTER_SCANNER_FLY_TOKEN",
                "FLY_API_TOKEN",
                "GITHUB_TOKEN",
                "GH_TOKEN",
            }
            for name in os.environ
        ):
            raise ScannerUnavailable("Scanner environment contains control-plane authority")
        if not detect_probe_jail().user_namespaces:
            raise ScannerUnavailable("Scanner requires full user/PID namespace isolation")
        worker = ScannerWorker(
            os.environ.get("DINKSTER_SCANNER_ORIGIN", ""),
            os.environ.get("DINKSTER_SCANNER_TOKEN", ""),
            Path(os.environ.get("DINKSTER_SCANNER_RUNTIME_STORE", "/tmp/dinkster-scan-runtime")),
        )
        while worker.run_once():
            if args.once:
                break
    except Exception:
        # Transport exceptions and chained tracebacks may contain request credentials.
        raise SystemExit(
            "Scanner interrupted; its assignment will recover after lease expiry"
        ) from None


if __name__ == "__main__":
    main()
