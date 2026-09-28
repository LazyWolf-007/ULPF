from __future__ import annotations

import re
from typing import Any

from ulpf.detect import register

KV_RE = re.compile(r"(\w+)=(\S+)")
PORT_FIELDS = {"network.src_port", "network.dst_port"}


def _pairs(line: str) -> dict[str, str]:
    return {key: value for key, value in KV_RE.findall(line)}


def parse(line: str, mapping: dict[str, Any]) -> dict[str, Any] | None:
    pairs = _pairs(line)
    fields = mapping.get("fields") or {}
    if not pairs or not any(key in pairs for key in fields):
        return None

    event: dict[str, Any] = {}
    for key, value in (mapping.get("defaults") or {}).items():
        event[key] = value

    used = set()
    for src, dest in fields.items():
        if src not in pairs:
            continue
        used.add(src)
        raw = pairs[src]
        if dest in PORT_FIELDS:
            event[dest] = int(raw)
        elif dest == "network.transport":
            event[dest] = (mapping.get("protocols") or {}).get(raw, raw)
        else:
            event[dest] = raw

    action = pairs.get("action", "")
    action_map = (mapping.get("actions") or {}).get(action) or {}
    event.update(action_map)

    date = pairs.get("date", "")
    time = pairs.get("time", "")
    if date or time:
        event["timestamp"] = f"{date} {time}".strip()
        used.update({"date", "time"})

    event["unmapped"] = {key: value for key, value in pairs.items() if key not in used}
    return event


register("kv", parse)
