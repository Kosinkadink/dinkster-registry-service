from __future__ import annotations

import argparse
import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, cast

from blake3 import blake3

from dinkster_registry_service.wire import DownloadTicket, NodeProvidersResponse, PackPage


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


def main() -> None:
    parser = argparse.ArgumentParser(prog="registry-conformance")
    parser.add_argument("base_url")
    args = parser.parse_args()
    run(cast("str", args.base_url))


if __name__ == "__main__":
    main()
