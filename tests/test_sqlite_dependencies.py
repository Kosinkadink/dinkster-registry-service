"""SQLite storage and HTTP consume the pure model, not doctor or host machinery."""

from __future__ import annotations

import ast
from pathlib import Path


def test_sqlite_service_keeps_its_one_way_dependencies() -> None:
    source = (
        Path(__file__).resolve().parents[1]
        / "packages/dinkster-registry-sqlite/src/dinkster_registry_sqlite"
    )
    modules = list(source.rglob("*.py"))
    assert modules
    for module in modules:
        imports: set[str] = set()
        for node in ast.walk(ast.parse(module.read_text())):
            if isinstance(node, ast.Import):
                imports.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imports.add(node.module.split(".")[0])
        internal = {name for name in imports if name.startswith("dinkster_")}
        allowed = {"dinkster_registry", "dinkster_schema"}
        if module.name == "cli.py":
            allowed |= {"dinkster_registry_sqlite", "dinkster_workers"}
        assert internal <= allowed, module
