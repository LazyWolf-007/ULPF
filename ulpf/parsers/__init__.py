from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType


def _import_parser_modules() -> list[ModuleType]:
    here = Path(__file__).parent
    modules: list[ModuleType] = []
    for path in sorted(here.glob("*.py")):
        if path.stem == "__init__":
            continue
        modules.append(importlib.import_module(f"{__package__}.{path.stem}"))
    return modules


PARSER_MODULES = _import_parser_modules()


def register_all(registry) -> None:
    for module in PARSER_MODULES:
        module.register(registry)
