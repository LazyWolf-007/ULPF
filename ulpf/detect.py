from __future__ import annotations

import json
import re
from typing import Any, Callable

SYSLOG_PREFIX = re.compile(r"^<\d+>")
KV_PAIR = re.compile(r"\w+=\S+")

ParseFn = Callable[[str, dict[str, Any]], dict[str, Any] | None]

_REGISTRY: list[tuple[str, ParseFn]] = []


def register(fmt: str, parser: ParseFn) -> None:
    if any(parser is existing for _, existing in _REGISTRY):
        return
    _REGISTRY.append((fmt, parser))


def is_registered(parser: ParseFn) -> bool:
    return any(parser is existing for _, existing in _REGISTRY)


def parsers_for(fmt: str) -> list[ParseFn]:
    return [parser for name, parser in _REGISTRY if name == fmt]


def detect(line: str) -> str:
    if line.startswith("CEF:"):
        return "cef"
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
