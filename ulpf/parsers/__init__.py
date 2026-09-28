from __future__ import annotations

import importlib
from pathlib import Path

import yaml

from ulpf.detect import is_registered, register

_MAPPINGS_DIR = Path(__file__).resolve().parent.parent / "mappings"


def _discover() -> None:
    here = Path(__file__).parent
    for path in sorted(here.glob("*.py")):
        if path.stem == "__init__":
            continue
        module = importlib.import_module(f"{__package__}.{path.stem}")
        parse = getattr(module, "parse", None)
        if parse is None or is_registered(parse):
            continue
        mapping_path = _MAPPINGS_DIR / f"{path.stem}.yaml"
        if not mapping_path.is_file():
            continue
        mapping = yaml.safe_load(mapping_path.read_text(encoding="utf-8")) or {}
        fmt = (mapping.get("defaults") or {}).get("parse.format")
        if fmt:
            register(fmt, parse)


_discover()
