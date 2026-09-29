"""Export layer: maps internal shared events to OCSF-aligned records.

This module is read-only with respect to the internal schema in schema.py —
it never changes `event.py`/`schema.py` field names or shapes, it only
projects a finalized internal event dict into an OCSF-shaped dict. Class
selection, severity normalization, and activity/disposition mapping are
documented in SPEC.md.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

# OCSF schema version this export aligns to (not schema-validated against
# the official OCSF JSON schema, just field-shape compatible).
OCSF_VERSION = "1.1.0"

# Class/category constants. Values follow the public OCSF class catalog.
NETWORK_ACTIVITY_CLASS = {
    "class_uid": 4001,
    "class_name": "Network Activity",
    "category_uid": 4,
    "category_name": "Network Activity",
}
AUTHENTICATION_CLASS = {
    "class_uid": 3002,
    "class_name": "Authentication",
    "category_uid": 3,
    "category_name": "Identity & Access Management",
}
SECURITY_FINDING_CLASS = {
    "class_uid": 2004,
    "class_name": "Security Finding",
    "category_uid": 2,
    "category_name": "Findings",
}

# event.severity uses a different scale per parser (syslog 0-7, CEF 0-10,
# Suricata alert severity 1-3). Each is normalized to OCSF severity_id
# (0=Unknown .. 6=Fatal). See SPEC.md for the full table.
_CISCO_ASA_SEVERITY = {0: 6, 1: 6, 2: 5, 3: 5, 4: 4, 5: 3, 6: 2, 7: 1}
_SURICATA_SEVERITY = {1: 4, 2: 3, 3: 2}
SEVERITY_ID_NAMES = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
}

# OCSF ships an "_id" and a caption for every enum; the fixed-shape
# convention (always the same keys) matches schema.py's own approach.
OCSF_KEYS = (
    "class_uid",
    "class_name",
    "category_uid",
    "category_name",
    "activity_id",
    "activity_name",
    "severity_id",
    "severity",
    "time",
    "action",
    "disposition_id",
    "disposition",
    "src_endpoint",
    "dst_endpoint",
    "connection_info",
    "metadata",
    "unmapped",
)


def _severity_id(event: dict[str, Any]) -> int:
    raw = event.get("event.severity", "")
    if raw in ("", None):
        return 0
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return 0

    parser = event.get("parse.parser", "")
    if parser == "cisco_asa":
        return _CISCO_ASA_SEVERITY.get(value, 0)
    if parser == "suricata":
        return _SURICATA_SEVERITY.get(value, 0)
    if parser == "cef":
        # CEF severity is 0-10, 10 = most severe.
        if value <= 0:
            return 0
        if value <= 2:
            return 1
        if value <= 4:
            return 2
        if value <= 6:
            return 3
        if value <= 8:
            return 4
        return 5
    return 0


def _class_info(event: dict[str, Any]) -> dict[str, Any]:
    # Suricata is the IDS in this sample set: every line it emits is a
    # detection engine alert, so it is always a Security Finding regardless
    # of event.category (which stays "network" for traffic-field parity).
    if event.get("parse.parser") == "suricata":
        return SECURITY_FINDING_CLASS
    if event.get("event.category") == "authentication":
        return AUTHENTICATION_CLASS
    return NETWORK_ACTIVITY_CLASS


def _activity(event: dict[str, Any], class_info: dict[str, Any]) -> tuple[int, str]:
    # "partial" (the generic fallback parser) still carries real outcome
    # signal and is treated the same as "ok" here; only "failed" (no
    # signal at all) collapses to Unknown.
    if event.get("parse.status") == "failed":
        return 0, "Unknown"
    if class_info is SECURITY_FINDING_CLASS:
        return 1, "Create"
    if class_info is AUTHENTICATION_CLASS:
        return 1, "Logon"
    outcome = event.get("event.outcome", "unknown")
    if outcome == "success":
        return 1, "Open"
    if outcome == "failure":
        return 4, "Fail"
    return 6, "Traffic"


def _disposition(event: dict[str, Any]) -> tuple[int, str]:
    if event.get("parse.status") == "failed":
        return 0, "Unknown"
    outcome = event.get("event.outcome", "unknown")
    if outcome == "success":
        return 1, "Allowed"
    if outcome == "failure":
        return 2, "Blocked"
    return 0, "Unknown"


def _endpoint(ip: Any, port: Any) -> dict[str, Any]:
    # Mirrors schema.py's convention: always the same keys, "" when unknown.
    endpoint: dict[str, Any] = {"ip": ip or ""}
    if port in ("", None):
        endpoint["port"] = ""
    else:
        try:
            endpoint["port"] = int(port)
        except (TypeError, ValueError):
            endpoint["port"] = ""
    return endpoint


_TZ_NO_COLON = re.compile(r"(?<=\d{2})([+-]\d{2})(\d{2})$")


def _normalize_offset(text: str) -> str:
    """Make ISO timestamps with mixed timezone notations fromisoformat-safe.

    Handles a trailing "Z", and a numeric offset with no colon ("+0530",
    "-0700") by inserting one, so both notations parse the same way
    regardless of which one a given source uses.
    """
    if text.endswith("Z"):
        return text[:-1] + "+00:00"
    match = _TZ_NO_COLON.search(text)
    if match:
        return text[: match.start()] + match.group(1) + ":" + match.group(2)
    return text


def _parse_timestamp(text: str) -> int | None:
    if not text:
        return None
    text = text.strip()
    # ISO 8601, tolerating "Z", a space instead of "T", and mixed timezone
    # offset notations ("+05:30", "+0530", "-0700").
    try:
        iso_text = _normalize_offset(text)
        parsed = datetime.fromisoformat(iso_text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1000)
    except ValueError:
        pass
    # Classic syslog "Mon DD HH:MM:SS" carries no year (cisco_asa, sshd);
    # assume the current UTC year since the source line does not have one.
    # The year is supplied explicitly (rather than via .replace() afterwards)
    # to avoid relying on strptime's ambiguous no-year default.
    try:
        year = datetime.now(timezone.utc).year
        parsed = datetime.strptime(f"{year} {text}", "%Y %b %d %H:%M:%S")
        return int(parsed.replace(tzinfo=timezone.utc).timestamp() * 1000)
    except ValueError:
        pass
    # FortiGate "YYYY-MM-DD HH:MM:SS".
    try:
        parsed = datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        return int(parsed.timestamp() * 1000)
    except ValueError:
        pass
    return None


def _event_time(event: dict[str, Any]) -> int:
    millis = _parse_timestamp(str(event.get("timestamp", "")))
    if millis is None:
        millis = _parse_timestamp(str(event.get("provenance.ingest_time", "")))
    return millis or 0


def to_ocsf(event: dict[str, Any]) -> dict[str, Any]:
    """Project a finalized internal event (schema.py shape) to OCSF fields.

    Read-only mapping: does not consult or mutate parsers/mappings, only the
    already-normalized internal event dict.
    """
    class_info = _class_info(event)
    activity_id, activity_name = _activity(event, class_info)
    disposition_id, disposition = _disposition(event)
    severity_id = _severity_id(event)

    return {
        "class_uid": class_info["class_uid"],
        "class_name": class_info["class_name"],
        "category_uid": class_info["category_uid"],
        "category_name": class_info["category_name"],
        "activity_id": activity_id,
        "activity_name": activity_name,
        "severity_id": severity_id,
        "severity": SEVERITY_ID_NAMES[severity_id],
        "time": _event_time(event),
        "action": event.get("event.action", ""),
        "disposition_id": disposition_id,
        "disposition": disposition,
        "src_endpoint": _endpoint(event.get("network.src_ip", ""), event.get("network.src_port", "")),
        "dst_endpoint": _endpoint(event.get("network.dst_ip", ""), event.get("network.dst_port", "")),
        "connection_info": {"protocol_name": event.get("network.transport", "")},
        "metadata": {
            "product": event.get("observer.product", "") or "unknown",
            "vendor_name": event.get("observer.vendor", "") or "unknown",
            "version": OCSF_VERSION,
            "raw_data_hash": event.get("provenance.raw_hash", ""),
            "raw_event_id": event.get("provenance.raw_event_id", ""),
        },
        "unmapped": event.get("unmapped") or {},
    }
