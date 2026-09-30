from __future__ import annotations

import importlib
from pathlib import Path
from types import ModuleType


def _import_parser_modules() -> list[ModuleType]:
    here = Path(__file__).parent
    paths = [path for path in sorted(here.glob("*.py")) if path.stem != "__init__"]
    # `dynamic` (LLM-generated parsers) always registers last, regardless
    # of alphabetical position, so every hand-written vendor parser always
    # gets first refusal on a line - "existing parsers keep priority".
    paths.sort(key=lambda path: (path.stem == "dynamic", path.stem))
    return [importlib.import_module(f"{__package__}.{path.stem}") for path in paths]


PARSER_MODULES = _import_parser_modules()


def register_all(registry) -> None:
    for module in PARSER_MODULES:
        module.register(registry)
