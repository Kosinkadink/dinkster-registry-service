from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dinkster_supervisor.environment_artifacts import (
    EnvironmentCatalog,
    discover_manifest,
    parse_metadata,
)
from dinkster_supervisor.environment_state import ArtifactLocation, Channel

from .scan_engine import ENGINE_ORIGIN, MAX_ENGINE_METADATA, ScanEngineError, _read_release


def scan_catalog(
    engine: dict[str, str] | None,
    bindings: dict[str, dict[str, Any]],
    *,
    mirror: Path | None = None,
) -> tuple[EnvironmentCatalog, str]:
    """Locate submitted identities only in trusted runtime publication metadata."""
    origin = str(mirror.resolve()) if mirror is not None else ENGINE_ORIGIN

    def read(path: str) -> bytes:
        if mirror is None:
            return _read_release(path, MAX_ENGINE_METADATA)
        source = mirror / path
        if not source.resolve().is_relative_to(mirror.resolve()):
            raise ScanEngineError("runtime metadata escapes its development mirror")
        with source.open("rb") as stream:
            data = stream.read(MAX_ENGINE_METADATA + 1)
        if len(data) > MAX_ENGINE_METADATA:
            raise ScanEngineError("runtime metadata exceeds its size bound")
        return data

    channels = []
    for name in ("main", "stable"):
        try:
            channels.append(Channel.parse(parse_metadata(read(f"channels/{name}.json"))))
        except (OSError, ValueError):
            continue
    bases: dict[str, dict[str, object]] = {}
    sources: dict[str, tuple[str, ...]] = {}
    locations: dict[str, tuple[ArtifactLocation, ...]] = {}
    for variant, binding in sorted(bindings.items()):
        base_id = binding["baseId"]
        candidates: list[tuple[ArtifactLocation, ...]] = []
        try:
            index = json.loads(read(f"base/{variant}/index.json"))
            if not isinstance(index, list):
                raise ScanEngineError("base index must contain release objects")
            for row in index:
                if not isinstance(row, dict) or row.get("id") != base_id:
                    continue
                path = row.get("path")
                if not isinstance(path, str):
                    continue
                candidates.append(
                    (
                        ArtifactLocation.read(
                            {"type": "mirror", "path": f"{path}/manifest.json"},
                            f"base/{variant}/{base_id[7:]}/manifest.json",
                        ),
                    )
                )
        except (OSError, ValueError):
            pass
        for channel in channels:
            if dict(channel.bases).get(variant) != base_id:
                continue
            candidates.append(dict(channel.base_locations)[variant])
        for selected_locations in candidates:
            try:
                base, roots, _ = discover_manifest(selected_locations, (origin,), base_id, variant)
            except (OSError, ValueError):
                continue
            bases[variant], sources[variant], locations[variant] = base, roots, selected_locations
            break
        else:
            raise ScanEngineError(f"missing matching base {base_id} for {variant}")
    cpu_variant = next((name for name in ("linux-cpu", "cpu") if name in bases), None)
    if cpu_variant is None:
        raise ScanEngineError("missing CPU base binding for the admission probe")
    variant = cpu_variant
    index = json.loads(read("engine/index.json"))
    if not isinstance(index, list):
        raise ScanEngineError("engine index must contain release objects")
    if engine is None:
        if not channels:
            raise ScanEngineError("missing published engine for the submitted dependency locks")
        defaults = [
            row
            for row in index
            if isinstance(row, dict)
            and "sha256:" + str(row.get("sha256")) == channels[0].engine_release
        ]
        if len(defaults) != 1 or not isinstance(defaults[0].get("commit"), str):
            raise ScanEngineError("missing engine index entry for the published channel")
        engine = {"commit": defaults[0]["commit"], "manifestDigest": channels[0].engine_release}
    matches = [
        row for row in index if isinstance(row, dict) and row.get("commit") == engine["commit"]
    ]
    if len(matches) != 1:
        raise ScanEngineError("engine index must identify exactly one matching commit")
    selected = matches[0]
    if "sha256:" + str(selected.get("sha256")) != engine["manifestDigest"]:
        raise ScanEngineError("engine index manifest identity mismatch")
    path = selected.get("path")
    if not isinstance(path, str):
        raise ScanEngineError("missing trusted engine release path")
    # Channel parsing validates the content-addressed publication path before any fetch.
    document: dict[str, object] = {
        "format": "dinkster.channel/1",
        "minimumDesktopVersion": "0.0.0",
        "engine": {
            "version": selected.get("version"),
            "release": engine["manifestDigest"],
            "locations": [{"type": "mirror", "path": f"{path}/release-manifest.json"}],
        },
        "base": {
            variant: {
                "id": bindings[variant]["baseId"],
                "locations": [
                    {"type": "mirror", "path": location.path}
                    if location.kind == "mirror"
                    else {
                        "type": "github",
                        "repository": location.repository,
                        "tag": location.tag,
                        "asset": location.asset,
                    }
                    for location in locations[variant]
                ],
            }
        },
    }
    channel = Channel.parse(document)
    manifest, engine_sources, engine_bytes = discover_manifest(
        channel.engine_locations, (origin,), engine["manifestDigest"]
    )
    if (
        manifest.get("repository") != "Kosinkadink/Dinkster"
        or manifest.get("commit") != engine["commit"]
        or manifest.get("version") != channel.engine_version
        or manifest["workerProtocol"] != bases[variant]["workerProtocol"]
    ):
        raise ScanEngineError("engine and base identity or worker protocol mismatch")
    return (
        EnvironmentCatalog(
            "main",
            document,
            channel,
            manifest,
            engine_sources,
            {variant: bases[variant]},
            {variant: sources[variant]},
            engine_bytes,
        ),
        variant,
    )
