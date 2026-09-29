"""Fallback parser: used only when no vendor parser matches a line.

Tries structural parsing in order (JSON -> CEF/LEEF -> key=value -> syslog
prefix), then heuristically fills any still-missing fields by scanning the
raw text for timestamps, IPv4/IPv6 addresses, ports, protocol names, and
action words. Every field it sets is a best-effort guess, so results carry
`parse.status = "partial"` and a 0-1 `parse.confidence` reflecting how much
signal was actually found (a fully "ok" vendor parse still beats this).

The pipeline calls `parse()` here directly, with vendor fingerprint hints
from `ulpf.detect.detect_format` threaded through `mapping["hints"]"" ---
it is not selected via per-format registry dispatch like vendor parsers,
so `register()` below wires it to a format no real line ever classifies as.
"""

from __future__ import annotations

import json
import re
from typing import Any

KV_RE = re.compile(r"(\w[\w.\-]*)=(\S+)")
CEF_RE = re.compile(
    r"^CEF:(?P<version>[^|]*)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
    r"(?P<dev_version>[^|]*)\|(?P<sig_id>[^|]*)\|(?P<name>[^|]*)\|"
    r"(?P<severity>[^|]*)\|(?P<extension>.*)$"
)
LEEF_RE = re.compile(
    r"^LEEF:(?P<version>[^|]*)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
    r"(?P<dev_version>[^|]*)\|(?P<event_id>[^|]*)\|(?P<extension>.*)$"
)
SYSLOG_PREFIX = re.compile(r"^<(?P<pri>\d+)>\s*")

IPV4_RE = re.compile(r"\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")
# Deliberately loose: grab any run of hex digits and colons, then require
# at least two colons (below) so plain hex tokens ("deadbeef") don't count.
# This handles "::" compression correctly, unlike a group-counting pattern.
IPV6_RE = re.compile(r"\b[0-9A-Fa-f:]{2,39}\b")
PORT_RE = re.compile(r"\b(?:port|sport|dport|spt|dpt)\D{0,3}(\d{1,5})\b", re.IGNORECASE)
PROTOCOL_RE = re.compile(r"\b(tcp|udp|icmp|icmpv6|sctp)\b", re.IGNORECASE)
ACTION_RE = re.compile(
    r"\b(allow(?:ed)?|accept(?:ed)?|deny|denied|drop(?:ped)?|block(?:ed)?)\b", re.IGNORECASE
)
ISO_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
SYSLOG_TS_RE = re.compile(r"\b[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\b")

# Deliberately excludes bare "source"/"destination"/"dest": those key names
# are ambiguous in real logs (e.g. Windows Event Log "Source" is a product
# name, not an IP) and produced false positives in testing. The heuristic
# IPv4/IPv6 regex scan below is the safety net for those lines instead.
SRC_IP_KEYS = {"src", "srcip", "src_ip", "source_ip", "saddr", "sip"}
DST_IP_KEYS = {"dst", "dstip", "dst_ip", "destination_ip", "daddr", "dip", "dest_ip"}
SRC_PORT_KEYS = {"spt", "srcport", "sport", "src_port"}
DST_PORT_KEYS = {"dpt", "dstport", "dport", "dst_port"}
PROTOCOL_KEYS = {"proto", "protocol", "transport", "ipproto"}
ACTION_KEYS = {"action", "act", "verdict", "disposition"}
TIMESTAMP_KEYS = {"timestamp", "ts"}

ALLOW_WORDS = {"allow", "allowed", "accept", "accepted"}
DENY_WORDS = {"deny", "denied", "drop", "dropped", "block", "blocked"}

# Every OCSF-catalog field a real vendor parser might have filled; weights
# sum to 1.0 so `parse.confidence` reads as "fraction of expected signal
# actually recovered from this line".
WEIGHTS = {
    "structure": 0.25,
    "timestamp": 0.15,
    "src_ip": 0.15,
    "dst_ip": 0.15,
    "port": 0.10,
    "protocol": 0.10,
    "action": 0.10,
}

_HINT_VENDOR_NAMES = {
    "cisco_asa": "Cisco",
    "fortigate": "Fortinet",
    "paloalto": "Palo Alto Networks",
    "checkpoint": "Check Point",
    "sshd": "OpenSSH",
    "suricata": "OISF Suricata",
}


def _kv_pairs(text: str) -> dict[str, str]:
    return {key.lower(): value for key, value in KV_RE.findall(text)}


def _lookup(pairs: dict[str, str], keys: set[str]) -> tuple[str, str] | None:
    for key in keys:
        if key in pairs:
            return key, pairs[key]
    return None


def _set_outcome(event: dict[str, Any], word: str) -> None:
    lowered = word.lower()
    if lowered in ALLOW_WORDS:
        event["event.outcome"] = "success"
    elif lowered in DENY_WORDS:
        event["event.outcome"] = "failure"


def _apply_kv_aliases(
    pairs: dict[str, str], event: dict[str, Any], found: set[str], used: set[str]
) -> None:
    hit = _lookup(pairs, SRC_IP_KEYS)
    if hit:
        event["network.src_ip"] = hit[1]
        found.add("src_ip")
        used.add(hit[0])

    hit = _lookup(pairs, DST_IP_KEYS)
    if hit:
        event["network.dst_ip"] = hit[1]
        found.add("dst_ip")
        used.add(hit[0])

    hit = _lookup(pairs, SRC_PORT_KEYS)
    if hit and hit[1].isdigit():
        event["network.src_port"] = int(hit[1])
        found.add("port")
        used.add(hit[0])

    hit = _lookup(pairs, DST_PORT_KEYS)
    if hit and hit[1].isdigit():
        event["network.dst_port"] = int(hit[1])
        found.add("port")
        used.add(hit[0])

    hit = _lookup(pairs, PROTOCOL_KEYS)
    if hit:
        event["network.transport"] = hit[1].lower()
        found.add("protocol")
        used.add(hit[0])

    hit = _lookup(pairs, ACTION_KEYS)
    if hit:
        event["event.action"] = hit[1]
        found.add("action")
        used.add(hit[0])
        _set_outcome(event, hit[1])

    hit = _lookup(pairs, TIMESTAMP_KEYS)
    if hit:
        event["timestamp"] = hit[1]
        found.add("timestamp")
        used.add(hit[0])
    else:
        date, time_ = pairs.get("date"), pairs.get("time")
        if date or time_:
            event["timestamp"] = f"{date or ''} {time_ or ''}".strip()
            found.add("timestamp")
            used.update(key for key in ("date", "time") if key in pairs)


def _heuristic_fill(text: str, event: dict[str, Any], found: set[str]) -> None:
    if "timestamp" not in found:
        match = ISO_TS_RE.search(text) or SYSLOG_TS_RE.search(text)
        if match:
            event["timestamp"] = match.group(0)
            found.add("timestamp")

    if "src_ip" not in found or "dst_ip" not in found:
        ipv4 = IPV4_RE.findall(text)
        ipv6 = [candidate for candidate in IPV6_RE.findall(text) if candidate.count(":") >= 2]
        ips = list(dict.fromkeys(ipv4 + ipv6))
        if "src_ip" not in found and ips:
            event["network.src_ip"] = ips[0]
            found.add("src_ip")
        if "dst_ip" not in found and len(ips) > 1:
            event["network.dst_ip"] = ips[1]
            found.add("dst_ip")

    if "port" not in found:
        match = PORT_RE.search(text)
        if match:
            event["network.dst_port"] = int(match.group(1))
            found.add("port")

    if "protocol" not in found:
        match = PROTOCOL_RE.search(text)
        if match:
            event["network.transport"] = match.group(1).lower()
            found.add("protocol")

    if "action" not in found:
        match = ACTION_RE.search(text)
        if match:
            word = match.group(1)
            event["event.action"] = word.lower()
            _set_outcome(event, word)
            found.add("action")


def _structural_parse(line: str) -> tuple[str, dict[str, Any], set[str]]:
    event: dict[str, Any] = {}
    found: set[str] = set()

    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, TypeError, ValueError):
        payload = None
    if isinstance(payload, dict):
        flat: dict[str, str] = {}
        key_by_lower: dict[str, str] = {}
        for key, value in payload.items():
            if isinstance(value, (str, int, float)):
                lower = str(key).lower()
                flat[lower] = str(value)
                key_by_lower[lower] = key
            elif isinstance(value, dict):
                for sub_key, sub_value in value.items():
                    if isinstance(sub_value, (str, int, float)):
                        flat.setdefault(str(sub_key).lower(), str(sub_value))
        used: set[str] = set()
        _apply_kv_aliases(flat, event, found, used)
        top_used = {key_by_lower[key] for key in used if key in key_by_lower}
        event["unmapped"] = {key: value for key, value in payload.items() if key not in top_used}
        return "json", event, found

    cef = CEF_RE.match(line)
    if cef:
        event["observer.vendor"] = cef.group("vendor").strip()
        event["observer.product"] = cef.group("product").strip()
        event["event.description"] = cef.group("name").strip()
        pairs = _kv_pairs(cef.group("extension"))
        used = set()
        _apply_kv_aliases(pairs, event, found, used)
        event["unmapped"] = {key: value for key, value in pairs.items() if key not in used}
        return "cef", event, found

    leef = LEEF_RE.match(line)
    if leef:
        event["observer.vendor"] = leef.group("vendor").strip()
        event["observer.product"] = leef.group("product").strip()
        pairs = _kv_pairs(leef.group("extension"))
        used = set()
        _apply_kv_aliases(pairs, event, found, used)
        event["unmapped"] = {key: value for key, value in pairs.items() if key not in used}
        return "leef", event, found

    kv_pairs = _kv_pairs(line)
    if kv_pairs:
        used = set()
        _apply_kv_aliases(kv_pairs, event, found, used)
        event["unmapped"] = {key: value for key, value in kv_pairs.items() if key not in used}
        return "kv", event, found

    syslog = SYSLOG_PREFIX.match(line)
    if syslog:
        event["unmapped"] = {"pri": syslog.group("pri")}
        return "syslog", event, found

    return "none", event, found


def _vendor_from_hints(hints: tuple[str, ...]) -> str:
    for hint in hints:
        if hint.startswith("cef_vendor:") or hint.startswith("leef_vendor:"):
            return hint.split(":", 1)[1]
    for hint in hints:
        if hint in _HINT_VENDOR_NAMES:
            return _HINT_VENDOR_NAMES[hint]
    return ""


def parse(line: str, mapping: dict[str, Any]) -> dict[str, Any] | None:
    structure, event, found = _structural_parse(line)
    _heuristic_fill(line, event, found)

    if structure == "none" and not found:
        return None

    confidence = WEIGHTS["structure"] if structure != "none" else 0.0
    for key in ("timestamp", "src_ip", "dst_ip", "port", "protocol", "action"):
        if key in found:
            confidence += WEIGHTS[key]
    event["parse.confidence"] = round(min(confidence, 1.0), 2)

    hints = tuple((mapping or {}).get("hints") or ())
    if not event.get("observer.vendor"):
        guess = _vendor_from_hints(hints)
        if guess:
            event["observer.vendor"] = guess

    event.setdefault("event.outcome", "unknown")
    event.setdefault("event.category", "network")
    event["parse.status"] = "partial"
    event["parse.format"] = structure if structure != "none" else "unknown"
    event["parse.parser"] = "generic"
    return event


def register(registry: Any) -> None:
    # Deliberately not "json"/"cef"/"leef"/"kv"/"syslog"/"unknown": this
    # parser is invoked explicitly by the pipeline as the last-resort
    # fallback (with vendor hints threaded in), never through per-format
    # registry dispatch like the vendor parsers.
    registry.register("_generic_fallback", parse)
