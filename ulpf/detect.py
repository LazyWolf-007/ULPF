from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable

SYSLOG_PREFIX = re.compile(r"^<\d+>")
KV_PAIR = re.compile(r"\w+=\S+")
CEF_VENDOR = re.compile(r"^CEF:[^|]*\|(?P<vendor>[^|]*)\|")
LEEF_VENDOR = re.compile(r"^LEEF:[^|]*\|(?P<vendor>[^|]*)\|")

ParseFn = Callable[[str, dict[str, Any]], dict[str, Any] | None]

_REGISTRY: list[tuple[str, ParseFn]] = []


@dataclass(frozen=True)
class Detection:
    """A detected line format plus best-effort vendor fingerprint hints.

    `hints` never changes which parser the registry dispatches to (that is
    still driven solely by `format`); it is auxiliary signal a fallback
    parser can use to make an informed vendor guess when no registered
    parser recognizes the line.
    """

    format: str
    hints: tuple[str, ...] = ()


def register(fmt: str, parser: ParseFn) -> None:
    if any(parser is existing for _, existing in _REGISTRY):
        return
    _REGISTRY.append((fmt, parser))


def is_registered(parser: ParseFn) -> bool:
    return any(parser is existing for _, existing in _REGISTRY)


def parsers_for(fmt: str) -> list[ParseFn]:
    return [parser for name, parser in _REGISTRY if name == fmt]


def _classify(line: str) -> str:
    if line.startswith("CEF:"):
        return "cef"
    if line.startswith("LEEF:"):
        return "leef"
    if line.startswith("{"):
        try:
            json.loads(line)
            return "json"
        except (json.JSONDecodeError, TypeError, ValueError):
            pass
    if SYSLOG_PREFIX.match(line):
        return "syslog"
    if KV_PAIR.search(line):
        return "kv"
    return "unknown"


def _fingerprint(line: str, fmt: str) -> tuple[str, ...]:
    """Cheap substring/structural hints naming a likely vendor or product.

    These are independent of `fmt` classification on purpose: a mangled
    line that fails structural detection can still carry a recognizable
    vendor fingerprint (e.g. "%ASA-" surviving in an otherwise malformed
    syslog line).
    """
    hints: list[str] = []
    if "%ASA-" in line:
        hints.append("cisco_asa")
    if "devname=" in line:
        hints.append("fortigate")
    if "sshd[" in line:
        hints.append("sshd")
    if "PA-" in line:
        hints.append("paloalto")

    if fmt == "cef":
        match = CEF_VENDOR.match(line)
        if match:
            vendor = match.group("vendor").strip()
            if vendor:
                hints.append(f"cef_vendor:{vendor}")
                lowered = vendor.lower()
                if "palo alto" in lowered:
                    hints.append("paloalto")
                if "check point" in lowered:
                    hints.append("checkpoint")

    if fmt == "leef":
        match = LEEF_VENDOR.match(line)
        if match:
            vendor = match.group("vendor").strip()
            if vendor:
                hints.append(f"leef_vendor:{vendor}")

    if fmt == "json":
        try:
            payload = json.loads(line)
        except (json.JSONDecodeError, TypeError, ValueError):
            payload = None
        if isinstance(payload, dict) and ("event_type" in payload or "alert" in payload):
            hints.append("suricata")

    return tuple(dict.fromkeys(hints))


def detect_format(line: str) -> Detection:
    """Classify a raw line and attach vendor fingerprint hints.

    The pipeline uses `.format` to select registered parsers automatically
    (no manual per-file/per-vendor flag); `.hints` is available to the
    generic fallback parser (`ulpf/parsers/generic.py`) when no registered
    parser matches the detected format.
    """
    fmt = _classify(line)
    return Detection(format=fmt, hints=_fingerprint(line, fmt))


def detect(line: str) -> str:
    """Backwards-compatible shorthand: just the format string."""
    return _classify(line)
