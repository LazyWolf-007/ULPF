from __future__ import annotations

import re
from typing import Any

SSHD_RE = re.compile(
    r"^<(?P<pri>\d+)>"
    r"(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<verb>Failed password) for (?P<user>\S+) "
    r"from (?P<src_ip>\d+\.\d+\.\d+\.\d+) port (?P<dst_port>\d+)"
    r"(?:\s+(?P<method>\S+))?"
)


def parse(line: str, mapping: dict[str, Any]) -> dict[str, Any] | None:
    match = SSHD_RE.match(line)
    if match is None:
        return None

    event: dict[str, Any] = {}
    for key, value in (mapping.get("defaults") or {}).items():
        event[key] = value

    verb = match.group("verb")
    event.update((mapping.get("actions") or {}).get(verb) or {})

    event["timestamp"] = match.group("timestamp")
    event["observer.name"] = match.group("host")
    event["user.name"] = match.group("user")
    event["network.src_ip"] = match.group("src_ip")
    event["network.dst_port"] = int(match.group("dst_port"))
    event["event.description"] = line.split(": ", 1)[-1]
    event["unmapped"] = {
        "pid": match.group("pid"),
        "pri": match.group("pri"),
        "method": match.group("method") or "",
    }
    return event


def register(registry) -> None:
    registry.register("syslog", parse)
