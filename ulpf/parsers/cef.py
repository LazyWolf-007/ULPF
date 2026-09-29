from __future__ import annotations

import re
from typing import Any

CEF_RE = re.compile(
    r"^CEF:(?P<version>[^|]*)\|"
    r"(?P<vendor>[^|]*)\|"
    r"(?P<product>[^|]*)\|"
    r"(?P<dev_version>[^|]*)\|"
    r"(?P<sig_id>[^|]*)\|"
    r"(?P<name>[^|]*)\|"
    r"(?P<severity>[^|]*)\|"
    r"(?P<extension>.*)$"
)
KV_RE = re.compile(r"(\w+)=(\S+)")
PORT_FIELDS = {"network.src_port", "network.dst_port"}


def parse(line: str, mapping: dict[str, Any]) -> dict[str, Any] | None:
    header = CEF_RE.match(line)
    if header is None:
        return None

    event: dict[str, Any] = {}
    for key, value in (mapping.get("defaults") or {}).items():
        event[key] = value

    event["observer.vendor"] = header.group("vendor")
    event["observer.product"] = header.group("product")
    severity = header.group("severity")
    event["event.severity"] = int(severity) if severity.isdigit() else severity
    event["event.description"] = header.group("name")

    pairs = {key: value for key, value in KV_RE.findall(header.group("extension"))}
    used = set()
    for src, dest in (mapping.get("fields") or {}).items():
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

    event["unmapped"] = {
        "version": header.group("version"),
        "device_version": header.group("dev_version"),
        "signature_id": header.group("sig_id"),
        **{key: value for key, value in pairs.items() if key not in used},
    }
    return event


def register(registry) -> None:
    registry.register("cef", parse)
