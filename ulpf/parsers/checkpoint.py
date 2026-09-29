from __future__ import annotations

import re
from typing import Any

KV_RE = re.compile(r"(\w+)=(\S+)")
CLAIM_KEYS = ("src", "dst", "action")


def parse(line: str, mapping: dict[str, Any]) -> dict[str, Any] | None:
    pairs = {key: value for key, value in KV_RE.findall(line)}
    if not all(key in pairs for key in CLAIM_KEYS):
        return None

    event: dict[str, Any] = {}
    for key, value in (mapping.get("defaults") or {}).items():
        event[key] = value

    used: set[str] = set()
    for src, dest in (mapping.get("fields") or {}).items():
        if src not in pairs:
            continue
        used.add(src)
        event[dest] = pairs[src]

    action = pairs.get("action", "")
    event.update((mapping.get("actions") or {}).get(action) or {})
    event["unmapped"] = {key: value for key, value in pairs.items() if key not in used}
    return event


def register(registry) -> None:
    registry.register("kv", parse)
