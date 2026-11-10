from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from blake3 import blake3

from dinkster_registry_service.wire import (
    DownloadTicket,
    NodeProvidersResponse,
    PackPage,
    ReleaseDetail,
)


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: dict[str, str]
    body: bytes


class ConformanceFailure(AssertionError):
    """A running registry does not satisfy the public read contract."""


def _request(url: str, *, method: str = "GET", headers: dict[str, str] | None = None) -> HttpResult:
    request = urllib.request.Request(url, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return HttpResult(
                response.status,
                {name.lower(): value for name, value in response.headers.items()},
                response.read(),
            )
    except urllib.error.HTTPError as exc:
        return HttpResult(
            exc.code,
            {name.lower(): value for name, value in exc.headers.items()},
            exc.read(),
        )


def _json(result: HttpResult) -> Any:
    if result.status != 200:
        raise ConformanceFailure(
            f"expected HTTP 200, got {result.status}: {result.body.decode(errors='replace')}"
        )
    return json.loads(result.body)


def run(base_url: str) -> None:
    origin = base_url.rstrip("/")

    browse = _request(origin + "/v1/packs")
    packs = PackPage.model_validate(_json(browse))
    names = [pack.name for pack in packs.items]
    if names != ["example-pack", "color-tools"]:
        raise ConformanceFailure(f"fixture browse returned {names!r}")
    print("PASS browse catalog: example-pack, color-tools")

    providers_result = _request(origin + "/v1/nodes/example.resize/providers?dinksterVersion=0.9.5")
    providers = NodeProvidersResponse.model_validate(_json(providers_result))
    if len(providers.providers) != 1 or providers.providers[0].pack_name != "example-pack":
        raise ConformanceFailure("example.resize did not resolve to example-pack")
    print("PASS node provider: example.resize -> example-pack 1.2.3")

    etag = browse.headers.get("etag")
    if etag is None:
        raise ConformanceFailure("browse response has no ETag")
    conditional = _request(origin + "/v1/packs", headers={"If-None-Match": etag})
    if conditional.status != 304 or conditional.body:
        raise ConformanceFailure("conditional browse did not return an empty HTTP 304")
    if conditional.headers.get("cache-control") != browse.headers.get("cache-control"):
        raise ConformanceFailure("HTTP 304 changed the browse cache policy")
    print("PASS conditional GET: 304 with unchanged cache policy")

    ticket_result = _request(
        origin + "/v1/packs/example-pack/versions/1.2.3/download-tickets",
        method="POST",
    )
    ticket = DownloadTicket.model_validate(_json(ticket_result))
    artifact = _request(ticket.url)
    if artifact.status != 200:
        raise ConformanceFailure(f"artifact download returned HTTP {artifact.status}")
    actual_digest = "blake3:" + blake3(artifact.body).hexdigest()
    if actual_digest != ticket.artifact_digest:
        raise ConformanceFailure(
            f"artifact digest is {actual_digest}, expected {ticket.artifact_digest}"
        )
    if len(artifact.body) != ticket.artifact_size:
        raise ConformanceFailure("artifact size does not match the download ticket")
    print(f"PASS fixture artifact: {actual_digest} ({len(artifact.body)} bytes)")


def check_conditional(origin: str, path: str, result: HttpResult) -> None:
    etag = result.headers.get("etag")
    if not etag:
        raise ConformanceFailure(f"{path} has no ETag")
    conditional = _request(origin + path, headers={"If-None-Match": etag})
    if conditional.status != 304 or conditional.body:
        raise ConformanceFailure(f"{path} did not return an empty HTTP 304")
    for header in ("etag", "cache-control"):
        if conditional.headers.get(header) != result.headers.get(header):
            raise ConformanceFailure(f"{path} changed {header} on HTTP 304")


def run_release(base_url: str, lock: dict[str, Any]) -> None:
    origin = base_url.rstrip("/")
    if lock.get("format") != "dinkster.lock/1" or not lock.get("packs"):
        raise ConformanceFailure("expected a nonempty dinkster.lock/1 release lock")
    expected = {(pack["pack"], pack["version"], pack["artifactDigest"]) for pack in lock["packs"]}
    if len(expected) != len(lock["packs"]):
        raise ConformanceFailure("release lock contains duplicate entries")

    names: set[str] = set()
    cursors: set[str] = set()
    path = "/v1/packs?limit=100"
    while True:
        browse = _request(origin + path)
        page = PackPage.model_validate(_json(browse))
        names.update(pack.name for pack in page.items)
        check_conditional(origin, path, browse)
        if page.next_cursor is None:
            break
        if page.next_cursor in cursors:
            raise ConformanceFailure("browse repeated a pagination cursor")
        cursors.add(page.next_cursor)
        path = "/v1/packs?" + urllib.parse.urlencode({"limit": 100, "cursor": page.next_cursor})
    if missing := {name for name, _, _ in expected} - names:
        raise ConformanceFailure(f"release packs missing from browse: {sorted(missing)}")
    print(f"PASS release browse and conditional GET: {len(expected)} locked packs")

    for path in ("/static/packs/index.json", "/static/locales/index.json"):
        response = _request(origin + path)
        index = _json(response)
        if index.get("schemaVersion") != 2:
            raise ConformanceFailure(f"{path} has an unsupported schema")
        if path == "/static/packs/index.json":
            entries = set()
            for item in index["items"]:
                pack_path = "/static/" + item["url"]
                pack_response = _request(origin + pack_path)
                document = _json(pack_response)
                if document.get("schemaVersion") != 2 or document.get("name") != item["name"]:
                    raise ConformanceFailure(f"{pack_path} has an invalid pack identity")
                if item["latestVersion"] not in {row["version"] for row in document["items"]}:
                    raise ConformanceFailure(f"{pack_path} lacks the advertised latest version")
                entries.update(
                    (row["name"], row["version"], wheel["digest"])
                    for row in document["items"]
                    for wheel in row["wheels"]
                )
                check_conditional(origin, pack_path, pack_response)
            if not expected <= entries:
                raise ConformanceFailure("per-pack indexes lack a locked release and digest")
        elif not {(name, version) for name, version, _ in expected} <= {
            (item["name"], item["version"]) for item in index["items"]
        }:
            raise ConformanceFailure("locale index lacks a locked release")
        check_conditional(origin, path, response)
        print(f"PASS release static index and conditional GET: {path}")

    for name, version, digest in sorted(expected):
        path = f"/v1/packs/{urllib.parse.quote(name, safe='')}/versions/"
        path += urllib.parse.quote(version, safe="")
        detail = ReleaseDetail.model_validate(_json(_request(origin + path)))
        if (detail.pack_name, detail.version, detail.artifact.digest, detail.state) != (
            name,
            version,
            digest,
            "active",
        ):
            raise ConformanceFailure(f"release detail differs from lock: {name} {version}")
        for node in detail.nodes:
            provider_path = "/v1/nodes/" + urllib.parse.quote(node.node_type, safe="")
            providers = NodeProvidersResponse.model_validate(
                _json(_request(origin + provider_path + "/providers?includePrerelease=true"))
            )
            if not any(
                (provider.pack_name, provider.version, provider.artifact_digest)
                == (name, version, digest)
                for provider in providers.providers
            ):
                raise ConformanceFailure(
                    f"node provider differs from lock: {name} {node.node_type}"
                )
        ticket = DownloadTicket.model_validate(
            _json(_request(origin + path + "/download-tickets", method="POST"))
        )
        if (ticket.pack_name, ticket.version, ticket.artifact_digest, ticket.artifact_size) != (
            name,
            version,
            digest,
            detail.artifact.size,
        ):
            raise ConformanceFailure(f"download ticket differs from locked release: {name}")
        artifact = _request(ticket.url, headers=ticket.required_headers)
        if (
            artifact.status != 200
            or "blake3:" + blake3(artifact.body).hexdigest() != digest
            or len(artifact.body) != ticket.artifact_size
        ):
            raise ConformanceFailure(f"downloaded bytes differ from locked release: {name}")
        print(f"PASS locked release, providers and artifact: {name} {version} {digest}")


def main() -> None:
    parser = argparse.ArgumentParser(prog="registry-conformance")
    parser.add_argument("base_url")
    parser.add_argument("--release-lock", type=Path)
    args = parser.parse_args()
    if args.release_lock is None:
        run(cast("str", args.base_url))
    else:
        run_release(args.base_url, json.loads(args.release_lock.read_bytes()))


if __name__ == "__main__":
    main()
