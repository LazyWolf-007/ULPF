"""Deterministic detection and tokenization for the LLM parser generator.

The model never writes the extractor for a structured line. This module
turns each sample into a flat dict of source keys, and the model only
maps those keys onto ULPF fields. A regex is reserved for text that matches
none of the deterministic detectors.

Detection order for one line:

1. Split an RFC 5424 or RFC 3164 syslog prefix, with or without ``<PRI>``.
2. Classify the remaining body: JSON object, then CEF/LEEF, then key=value.
3. Syslog prefix plus a key=value body is ``syslog_kv``.
4. Two or more key=value pairs and no syslog prefix is ``kv``.
5. Positional ``RT_FLOW_SESSION_CREATE|DENY|CLOSE`` is ``rt_flow``.
   Quoted ``source-address=`` lines stay ``syslog_kv``.
6. A RouterOS firewall sentence is ``mikrotik``.
7. Anything else is ``regex``. One stray ``token=value`` in a sentence is
   not a kv log; a syslog header plus a single pair is ``syslog_kv``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from ulpf.detect import detect as detect_format

STRUCTURED_MODES = frozenset({"kv", "json", "cef", "syslog_kv", "rt_flow", "mikrotik"})
REGEX_MODE = "regex"
MODES = STRUCTURED_MODES | {REGEX_MODE}
# Detection chooses these. The generator overwrites a model-supplied mode.
FORCED_MODES = frozenset({"rt_flow", "mikrotik"})

# Regex mode is the unstructured fallback. More groups than this means the
# model is trying to re-implement a structured parser as one giant pattern.
MAX_CAPTURE_GROUPS = 6

_MONTHS = frozenset(
    {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
)

# key=value, value either a double-quoted string (spaces and backslash
# escapes allowed) or a single non-space token. Quoted alternative is
# first so a value like `"hello world"` is one token, not `"hello`.
_KV_RE = re.compile(r'([A-Za-z_][\w.\-]*)=("(?:\\.|[^"\\])*"|[^\s]+)')

_CEF_RE = re.compile(
    r"^CEF:(?P<version>[^|]*)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
    r"(?P<device_version>[^|]*)\|(?P<signature_id>[^|]*)\|(?P<name>[^|]*)\|"
    r"(?P<severity>[^|]*)\|(?P<extension>.*)$"
)
_LEEF_RE = re.compile(
    r"^LEEF:(?P<version>[^|]*)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
    r"(?P<device_version>[^|]*)\|(?P<event_id>[^|]*)\|(?P<extension>.*)$"
)

_RFC5424_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<version>\d{1,3})\s+"
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<procid>\S+)\s+(?P<msgid>\S+)\s+"
    r"(?P<msg>.*)$"
)
_RFC3164_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>[^\s:\[\]]+)(?:\[(?P<procid>\d+)\])?:\s*"
    r"(?P<msg>.*)$"
)
_RFC3164_LOOSE_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<msg>.*)$"
)
_PRI_ONLY_RE = re.compile(r"^<(?P<pri>\d{1,3})>(?P<msg>.*)$")

_MODE_ROUTE = {
    "kv": "kv",
    "json": "json",
    "cef": "cef",
    "syslog_kv": "syslog",
    "rt_flow": "syslog",
    "mikrotik": "unknown",
    "regex": "unknown",
}

# Positional Juniper RT_FLOW. The kv form (source-address="...") is left
# to the kv tokenizer. CREATE, DENY, and CLOSE do not share a column layout
# after the first flow tuple, so only fields that are identified by the
# verb's own grammar are emitted — not policy, zones, or session id.
_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
_FLOW = (
    rf"(?P<src_ip>{_IPV4})/(?P<src_port>\d+)->"
    rf"(?P<dst_ip>{_IPV4})/(?P<dst_port>\d+)"
)
_RT_EVENT_RE = re.compile(
    r"RT_FLOW_SESSION_(?P<verb>CREATE|DENY|CLOSE)\s*:\s*"
    r"session\s+(?:created|denied|closed)\b(?P<tail>.*)\Z",
    re.IGNORECASE | re.DOTALL,
)
# After "session created": flow, tag, service, nat-flow, tag, nat-rule, nat-rule, protocol.
_RT_CREATE_RE = re.compile(
    rf"\s*{_FLOW}\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<protocol>\d+)\b"
)
# After "session denied": flow, service, protocol(type).
_RT_DENY_RE = re.compile(rf"\s*{_FLOW}\s+\S+\s+(?P<protocol>\d+)\(\d+\)")
# After "session closed <reason>:": flow, service, nat-flow, nat-rule, nat-rule, protocol.
_RT_CLOSE_RE = re.compile(
    rf".*?:\s*{_FLOW}\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<protocol>\d+)\b",
    re.DOTALL,
)
_RT_TAILS = {"CREATE": _RT_CREATE_RE, "DENY": _RT_DENY_RE, "CLOSE": _RT_CLOSE_RE}

# RouterOS firewall log. Not key=value: "in:ether1" and "proto TCP (SYN)".
# Timestamp is "sep/30 10:00:08" or syslog "Sep 30 10:27:08" / "Sep  3 10:00:08".
_MIKROTIK_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<timestamp>(?:[A-Za-z]{3}/\d{1,2}|[A-Z][a-z]{2}\s+\d{1,2})\s+\d{2}:\d{2}:\d{2})"
    r"(?:\s+(?P<host>(?!firewall\b)\S+))?"
    r"\s+firewall,(?P<severity>\w+)\s+(?P<action>[^:]+):\s+"
    r"in:(?P<in_if>\S+)\s+out:(?P<out_if>.+?),\s+"
    r"(?:src-mac\s+(?P<src_mac>\S+),\s+)?"
    r"(?:connection-state:(?P<connection_state>.+?)\s+)?"
    r"proto\s+(?P<protocol>[A-Za-z0-9]+)"
    r"(?:\s+\((?P<protocol_detail>[^)]*)\))?,\s+"
    rf"(?P<src_ip>{_IPV4})(?::(?P<src_port>\d+))?->"
    rf"(?P<dst_ip>{_IPV4})(?::(?P<dst_port>\d+))?"
    r"(?:,\s+NAT\s+(?P<nat>.+?))?"
    r",\s+len\s+(?P<length>\d+)\s*$"
)
_MIKROTIK_FIELDS = (
    "pri",
    "timestamp",
    "host",
    "severity",
    "action",
    "in_if",
    "out_if",
    "src_mac",
    "connection_state",
    "protocol",
    "protocol_detail",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "nat",
    "length",
)

_EXAMPLE_VALUE_LIMIT = 40


@dataclass(frozen=True)
class Tokenized:
    """One line turned into a mode plus a flat source-key dict."""

    mode: str
    fields: dict[str, str]


def tokenize(line: str) -> Tokenized:
    """Tokenize one raw line. Never raises on ordinary log text."""
    text = line.strip()
    if not text:
        return Tokenized(REGEX_MODE, {})

    header, body = _split_syslog(text)
    parsed = _parse_json(body)
    if parsed is not None:
        return Tokenized("json", _merge(header, parsed))

    parsed = _parse_cef(body)
    if parsed is not None:
        return Tokenized("cef", _merge(header, parsed))

    pairs = _parse_kv(body)
    if header and pairs:
        return Tokenized("syslog_kv", _merge(header, pairs))
    if not header and len(pairs) >= 2:
        return Tokenized("kv", pairs)

    rt_flow = _parse_rt_flow(header, body)
    if rt_flow is not None:
        return Tokenized("rt_flow", rt_flow)

    mikrotik = _parse_mikrotik(text)
    if mikrotik is not None:
        return Tokenized("mikrotik", mikrotik)

    if header:
        return Tokenized(REGEX_MODE, dict(header))
    return Tokenized(REGEX_MODE, {})


def detect_mode(lines: list[str]) -> str:
    """Mode shared by the samples. Ties prefer a structured mode over regex."""
    counts: dict[str, int] = {}
    for line in lines:
        if not line.strip():
            continue
        mode = tokenize(line).mode
        counts[mode] = counts.get(mode, 0) + 1
    if not counts:
        return REGEX_MODE
    return max(counts, key=lambda name: (counts[name], name != REGEX_MODE))


def example_values(lines: list[str], limit: int = 2) -> dict[str, list[str]]:
    """Source key -> up to `limit` distinct example values, first-seen order.

    Used to build the model prompt. Raw lines are not included.
    """
    mode = detect_mode(lines)
    if mode == REGEX_MODE:
        return {}
    found: dict[str, list[str]] = {}
    for line in lines:
        tokenized = tokenize(line)
        if tokenized.mode != mode:
            continue
        for key, value in tokenized.fields.items():
            bucket = found.setdefault(key, [])
            short = _short(value)
            if short not in bucket and len(bucket) < limit:
                bucket.append(short)
    return found


def keys_for_mode(lines: list[str], mode: str) -> list[str]:
    """Source keys actually produced by `mode`, in first-seen order."""
    if mode not in STRUCTURED_MODES:
        return []
    seen: dict[str, None] = {}
    for line in lines:
        tokenized = tokenize(line)
        if tokenized.mode != mode:
            continue
        for key in tokenized.fields:
            seen.setdefault(key, None)
    return list(seen)


def route_for(lines: list[str]) -> str:
    """detect.py format the pipeline will dispatch these lines to.

    This can differ from `detect_mode`: a `<PRI>` line is routed as
    ``syslog`` even when the body tokenizes as ``cef`` or ``json``.
    """
    counts: dict[str, int] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        route = detect_format(stripped)
        counts[route] = counts.get(route, 0) + 1
    if not counts:
        return "unknown"
    return max(counts, key=lambda name: counts[name])


def route_for_mode(mode: str) -> str:
    """Fallback route when no sample lines are available."""
    return _MODE_ROUTE.get(mode, "unknown")


def attach_route(config: dict[str, Any], samples: list[str]) -> None:
    """Stamp `format_hint` so dynamic.py registers on the pipeline's route.

    The model does not choose this. It is the detect.py format of the
    samples, overwritten even if the model invented one.
    """
    if samples:
        config["format_hint"] = route_for(samples)
        return
    hint = config.get("format_hint")
    if isinstance(hint, str) and hint.strip():
        return
    config["format_hint"] = route_for_mode(str(config.get("mode") or ""))


def apply_field_map(
    fields: dict[str, str],
    field_map: dict[str, Any],
    timestamp: dict[str, Any] | None = None,
) -> tuple[dict[str, str], set[str]]:
    """Apply `{internal_field: source_key}` plus `timestamp.keys`.

    Returns `(extracted, used_source_keys)`. Timestamp keys fill
    `timestamp` only when field_map did not already set it. Multiple
    timestamp keys are joined with a single space, in listed order
    (the usual date + time pair).
    """
    extracted: dict[str, str] = {}
    used: set[str] = set()
    for target, source in field_map.items():
        if not isinstance(target, str) or not isinstance(source, str):
            continue
        value = fields.get(source)
        if not value:
            continue
        extracted[target] = value
        used.add(source)

    spec = timestamp if isinstance(timestamp, dict) else {}
    keys = spec.get("keys") if isinstance(spec.get("keys"), list) else []
    if "timestamp" not in extracted:
        parts: list[str] = []
        for key in keys:
            if not isinstance(key, str):
                continue
            value = fields.get(key)
            if not value:
                continue
            parts.append(value)
            used.add(key)
        if parts:
            extracted["timestamp"] = " ".join(parts)
    return extracted, used


def source_fields(
    config: dict[str, Any],
    line: str,
    pattern: re.Pattern[str] | None = None,
) -> tuple[bool, dict[str, str]]:
    """Source fields for one line under `config`'s mode.

    Regex mode reads named groups from `pattern` (the caller compiles
    once). Structured modes use `tokenize` and require the same mode.
    """
    mode = config.get("mode")
    if mode == REGEX_MODE:
        if pattern is None:
            return False, {}
        match = pattern.match(line)
        if match is None:
            return False, {}
        return True, {name: value for name, value in match.groupdict().items() if value is not None}
    if mode == "rt_flow":
        # Positional lines tokenize as rt_flow. The bracketed SD twin
        # (msgid RT_FLOW_SESSION_*, source-address=) stays syslog_kv for
        # callers that ask for that mode, and is projected here so one
        # rt_flow field_map covers both shapes.
        fields = rt_flow_fields(line)
        if not fields:
            return False, {}
        return True, fields
    if mode not in STRUCTURED_MODES:
        return False, {}
    tokenized = tokenize(line)
    if tokenized.mode != mode or not tokenized.fields:
        return False, {}
    return True, tokenized.fields


def rt_flow_fields(line: str) -> dict[str, str] | None:
    """Canonical RT_FLOW fields for a positional line or its SD twin.

    The SD twin keeps ``tokenize().mode == "syslog_kv"`` so a key=value
    config still sees ``source-address``. This projection only renames the
    same endpoints, host, timestamp, event, and protocol number.
    """
    tokenized = tokenize(line)
    if tokenized.mode == "rt_flow":
        return tokenized.fields
    if tokenized.mode != "syslog_kv":
        return None
    fields = tokenized.fields
    event = fields.get("syslog_msgid") or ""
    if not event.startswith("RT_FLOW_SESSION_"):
        return None
    src = fields.get("source-address")
    dst = fields.get("destination-address")
    if not src or not dst:
        return None
    projected = {"src_ip": src, "dst_ip": dst, "event": event}
    _copy_if(projected, "src_port", fields.get("source-port"))
    _copy_if(projected, "dst_port", fields.get("destination-port"))
    _copy_if(projected, "protocol", fields.get("protocol-id") or fields.get("protocol"))
    _copy_if(projected, "host", fields.get("syslog_host"))
    _copy_if(projected, "timestamp", fields.get("syslog_timestamp"))
    return projected


def _copy_if(out: dict[str, str], key: str, value: str | None) -> None:
    if value:
        out[key] = value


def _parse_rt_flow(header: dict[str, str] | None, body: str) -> dict[str, str] | None:
    """Positional RT_FLOW_SESSION_{CREATE,DENY,CLOSE}.

    CREATE, DENY, and CLOSE put the service, policy, and zones in different
    columns, and a structured-data line does not use columns at all. The
    fields below are the ones every positional line can fill: endpoints,
    host, timestamp, event name, and the protocol number.
    """
    match = _RT_EVENT_RE.search(body)
    if match is None:
        return None
    verb = match.group("verb").upper()
    tail = _RT_TAILS[verb].search(match.group("tail"))
    if tail is None:
        return None
    fields = {
        "src_ip": tail.group("src_ip"),
        "src_port": tail.group("src_port"),
        "dst_ip": tail.group("dst_ip"),
        "dst_port": tail.group("dst_port"),
        "event": f"RT_FLOW_SESSION_{verb}",
        "protocol": tail.group("protocol"),
    }
    if header:
        host = header.get("syslog_host")
        timestamp = header.get("syslog_timestamp")
        if host:
            fields["host"] = host
        if timestamp:
            fields["timestamp"] = timestamp
    return fields


def _parse_mikrotik(text: str) -> dict[str, str] | None:
    """RouterOS firewall sentence. Returns None when the shape does not match."""
    match = _MIKROTIK_RE.match(text)
    if match is None:
        return None
    fields: dict[str, str] = {}
    for name in _MIKROTIK_FIELDS:
        value = match.group(name)
        if value:
            fields[name] = value.strip()
    return fields or None


def _parse_kv(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in _KV_RE.finditer(text):
        key, raw = match.group(1), match.group(2)
        if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
            fields[key] = _unescape(raw[1:-1])
        else:
            fields[key] = raw
    return fields


def _unescape(value: str) -> str:
    out: list[str] = []
    index = 0
    named = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"'}
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            out.append(named.get(value[index + 1], value[index + 1]))
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _parse_json(text: str) -> dict[str, str] | None:
    if not text.startswith("{"):
        return None
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    fields: dict[str, str] = {}
    _flatten(payload, "", fields, 0)
    return fields


def _flatten(value: Any, prefix: str, out: dict[str, str], depth: int) -> None:
    if depth > 4 or not isinstance(value, dict):
        return
    for key, child in value.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        if isinstance(child, dict):
            _flatten(child, name, out, depth + 1)
        elif isinstance(child, (str, int, float, bool)):
            out.setdefault(name, str(child))


def _parse_cef(text: str) -> dict[str, str] | None:
    cef = _CEF_RE.match(text)
    if cef:
        fields = _header_pairs(
            "cef",
            (
                ("version", cef.group("version")),
                ("vendor", cef.group("vendor")),
                ("product", cef.group("product")),
                ("device_version", cef.group("device_version")),
                ("signature_id", cef.group("signature_id")),
                ("name", cef.group("name")),
                ("severity", cef.group("severity")),
            ),
        )
        fields.update(_parse_kv(cef.group("extension")))
        return fields

    leef = _LEEF_RE.match(text)
    if leef:
        fields = _header_pairs(
            "leef",
            (
                ("version", leef.group("version")),
                ("vendor", leef.group("vendor")),
                ("product", leef.group("product")),
                ("device_version", leef.group("device_version")),
                ("event_id", leef.group("event_id")),
            ),
        )
        fields.update(_parse_kv(leef.group("extension")))
        return fields
    return None


def _header_pairs(prefix: str, pairs: tuple[tuple[str, str], ...]) -> dict[str, str]:
    fields: dict[str, str] = {}
    for name, value in pairs:
        cleaned = value.strip()
        if cleaned:
            fields[f"{prefix}_{name}"] = cleaned
    return fields


def _split_syslog(text: str) -> tuple[dict[str, str] | None, str]:
    """Return `(header_fields, body)`. Header is None when this is not syslog."""
    for pattern, check_month in (
        (_RFC5424_RE, False),
        (_RFC3164_RE, True),
        (_RFC3164_LOOSE_RE, True),
        (_PRI_ONLY_RE, False),
    ):
        match = pattern.match(text)
        if match is None:
            continue
        data = match.groupdict()
        timestamp = data.get("timestamp") or ""
        if check_month and timestamp[:3] not in _MONTHS:
            continue
        header = _syslog_header(data)
        if not header:
            continue
        return header, (data.get("msg") or "").strip()
    return None, text


def _syslog_header(data: dict[str, str | None]) -> dict[str, str]:
    names = {
        "pri": "syslog_pri",
        "version": "syslog_version",
        "timestamp": "syslog_timestamp",
        "host": "syslog_host",
        "app": "syslog_app",
        "procid": "syslog_procid",
        "msgid": "syslog_msgid",
    }
    fields: dict[str, str] = {}
    for source, dest in names.items():
        value = data.get(source)
        if value and value != "-":
            fields[dest] = value
    return fields


def _merge(header: dict[str, str] | None, body: dict[str, str]) -> dict[str, str]:
    if not header:
        return body
    merged = dict(header)
    merged.update(body)
    return merged


def _short(value: str, limit: int = _EXAMPLE_VALUE_LIMIT) -> str:
    value = value.replace("\n", " ").replace("\r", " ")
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."
