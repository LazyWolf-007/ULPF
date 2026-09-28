from __future__ import annotations

import re
from typing import Any

SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d+)>"
    r"(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+:\s+"
    r"%ASA-(?P<severity>\d+)-(?P<msgid>\d+):\s+"
    r"(?P<body>.*)$"
)

CONNECTION_RE = re.compile(
    r"^(?P<verb>Built|Teardown|Denied|Deny)\s+"
    r"(?P<direction>inbound|outbound)\s+"
    r"(?P<transport>TCP|UDP|ICMP)\s+connection\s+"
    r"(?P<conn_id>\d+)\s+for\s+"
    r"[^:]+:(?P<src_ip>\d+\.\d+\.\d+\.\d+)/(?P<src_port>\d+)\s+to\s+"
    r"[^:]+:(?P<dst_ip>\d+\.\d+\.\d+\.\d+)/(?P<dst_port>\d+)"
    r"(?:\s+user\s+(?P<user>\S+))?"
)


def parse(line: str, mapping: dict[str, Any]) -> dict[str, Any] | None:
    header = SYSLOG_RE.match(line)
    if header is None:
        return None
    body = CONNECTION_RE.match(header.group("body"))
    if body is None:
        return None

    event: dict[str, Any] = {}
    for key, value in (mapping.get("defaults") or {}).items():
        event[key] = value

    verb = body.group("verb")
    action_map = (mapping.get("actions") or {}).get(verb) or {}
    event.update(action_map)

    event["timestamp"] = header.group("timestamp")
    event["observer.name"] = header.group("host")
    event["network.src_ip"] = body.group("src_ip")
    event["network.src_port"] = int(body.group("src_port"))
    event["network.dst_ip"] = body.group("dst_ip")
    event["network.dst_port"] = int(body.group("dst_port"))
    event["network.transport"] = body.group("transport").lower()
    event["user.name"] = body.group("user") or ""
    event["event.severity"] = header.group("severity")
    event["event.description"] = header.group("body")
    event["unmapped"] = {
        "connection_id": body.group("conn_id"),
        "direction": body.group("direction"),
        "message_id": header.group("msgid"),
        "pri": header.group("pri"),
    }
    return event
