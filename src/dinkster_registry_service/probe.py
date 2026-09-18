from __future__ import annotations

import json
import resource
import sys
from pathlib import Path
from typing import Any, cast


def _apply_limits() -> None:
    limits = (
        (resource.RLIMIT_AS, 512 * 1024 * 1024),
        (resource.RLIMIT_NPROC, 64),
    )
    for resource_id, requested in limits:
        if resource_id == resource.RLIMIT_AS and sys.platform != "linux":
            continue
        soft, hard = resource.getrlimit(resource_id)
        limit = requested
        if soft != resource.RLIM_INFINITY:
            limit = min(limit, soft)
        if hard != resource.RLIM_INFINITY:
            limit = min(limit, hard)
        resource.setrlimit(resource_id, (limit, hard))


def inspect_pack(manifest_path: Path) -> dict[str, object]:
    _apply_limits()
    from dinkster_schema import SCHEMA_WIRE_VERSION, Node, schema_signature, schema_to_wire
    from dinkster_workers._doctor_probe import probe
    from dinkster_workers.manifest import load_manifest, resolve_entry

    doctor_report = probe(str(manifest_path))
    schemas: list[dict[str, Any]] = []
    if doctor_report["entry_error"] is None and doctor_report["nodes_entry_problem"] is None:
        manifest = load_manifest(manifest_path)
        nodes = cast("list[object] | tuple[object, ...]", resolve_entry(manifest.nodes_entry))
        for node in nodes:
            if not isinstance(node, type) or not issubclass(node, Node):
                continue
            schema = node.schema()
            schemas.append(
                {
                    "nodeType": schema.node_type,
                    "schemaVersion": schema.version,
                    "schemaWireVersion": SCHEMA_WIRE_VERSION,
                    "schemaSignature": schema_signature(schema),
                    "role": "schema-only"
                    if schema.node_type in manifest.schema_only
                    else "executing",
                    "schema": schema_to_wire(schema),
                }
            )
    return {"doctorReport": doctor_report, "schemas": schemas}


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: python -m dinkster_registry_service.probe <manifest>")
    try:
        output = json.dumps(inspect_pack(Path(sys.argv[1])), separators=(",", ":"))
    except BaseException as exc:
        print(json.dumps({"error": {"type": type(exc).__name__}}, separators=(",", ":")))
        return 1
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
