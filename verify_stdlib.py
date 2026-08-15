#!/usr/bin/env python3
"""Verify that ShipCheck runtime Python files import only stdlib modules."""

from __future__ import annotations

import ast
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RUNTIME_FILES = [ROOT / "shipcheck.py"]


def top_level_module(name: str) -> str:
    return name.split(".", 1)[0]


def main() -> int:
    if not hasattr(sys, "stdlib_module_names"):
        print("Python 3.10+ is required for this verification script.", file=sys.stderr)
        return 2

    stdlib = set(sys.stdlib_module_names)
    third_party: list[tuple[str, str]] = []

    for path in RUNTIME_FILES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules = [node.module]
            else:
                continue

            for module in modules:
                top = top_level_module(module)
                if top not in stdlib:
                    third_party.append((path.name, module))

    if third_party:
        print("Third-party runtime imports found:")
        for filename, module in third_party:
            print(f"  {filename}: {module}")
        return 1

    print("ShipCheck runtime dependency check: PASS")
    print(f"Checked: {', '.join(path.name for path in RUNTIME_FILES)}")
    print("Result: standard library imports only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
