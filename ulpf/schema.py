from __future__ import annotations

import hashlib
from typing import Any

EVENT_KEYS = (
    "event_id",
    "timestamp",
    "observer.vendor",
    "observer.product",
    "observer.name",
    "network.src_ip",
    "network.src_port",
    "network.dst_ip",
    "network.dst_port",
    "network.transport",
    "user.name",
    "event.action",
    "event.category",
    "event.outcome",
    "event.severity",
    "event.description",
    "parse.status",
    "parse.format",
    "parse.parser",
    "parse.confidence",
    "provenance.raw_event_id",
    "provenance.raw_text",
    "provenance.raw_hash",
    "provenance.mapping_version",
    "provenance.ingest_time",
    "unmapped",
)

VALID_OUTCOMES = frozenset({"success", "failure", "unknown"})


def empty_event() -> dict[str, Any]:
    return {
        "event_id": "",
        "timestamp": "",
        "observer.vendor": "",
        "observer.product": "",
        "observer.name": "",
        "network.src_ip": "",
        "network.src_port": "",
        "network.dst_ip": "",
        "network.dst_port": "",
        "network.transport": "",
        "user.name": "",
        "event.action": "",
        "event.category": "",
        "event.outcome": "unknown",
        "event.severity": "",
        "event.description": "",
        "parse.status": "failed",
        "parse.format": "",
        "parse.parser": "",
        "parse.confidence": 0,
        "provenance.raw_event_id": "",
        "provenance.raw_text": "",
        "provenance.raw_hash": "",
        "provenance.mapping_version": "",
        "provenance.ingest_time": "",
        "unmapped": {},
    }


def raw_hash(raw_text: str) -> str:
    return hashlib.sha256(raw_text.encode("utf-8")).hexdigest()


def finalize_event(event: dict[str, Any]) -> dict[str, Any]:
    record = empty_event()
    for key in EVENT_KEYS:
        if key in event:
            record[key] = event[key]
    if record["event.outcome"] not in VALID_OUTCOMES:
        record["event.outcome"] = "unknown"
    if record["unmapped"] is None:
        record["unmapped"] = {}
    return record
