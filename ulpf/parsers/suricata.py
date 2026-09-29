from __future__ import annotations

import json
from typing import Any

from ulpf.detect import register

PORT_FIELDS = {"network.src_port", "network.dst_port"}


def _dig(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _coerce(dest: str, raw: Any, mapping: dict[str, Any]) -> Any:
    if dest in PORT_FIELDS or dest == "event.severity":
        return int(raw)
    if dest == "network.transport":
        text = str(raw)
        return (mapping.get("protocols") or {}).get(text, text.lower())
    return raw


def parse(line: str, mapping: dict[str, Any]) -> dict[str, Any] | None:
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    if "event_type" not in payload and "alert" not in payload:
        return None

    event: dict[str, Any] = {}
    for key, value in (mapping.get("defaults") or {}).items():
        event[key] = value

    for src, dest in (mapping.get("fields") or {}).items():
        if src in payload and payload[src] is not None:
            event[dest] = _coerce(dest, payload[src], mapping)

    for src, dest in (mapping.get("nested") or {}).items():
        raw = _dig(payload, src)
        if raw is not None:
            event[dest] = _coerce(dest, raw, mapping)

    action = _dig(payload, "alert.action")
    event.update((mapping.get("actions") or {}).get(action) or {})

    signature = _dig(payload, "alert.signature")
    unmapped: dict[str, Any] = {}
    if "event_type" in payload:
        unmapped["event_type"] = payload["event_type"]
    if signature is not None:
        unmapped["signature"] = signature
        if not event.get("event.description"):
            event["event.description"] = signature

    event["unmapped"] = unmapped
    return event


register("json", parse)
