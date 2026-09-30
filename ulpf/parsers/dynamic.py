"""Data-driven parser for LLM-generated vendor configs.

One Python module handles every LLM-onboarded vendor - "no new Python file
per vendor" - by scanning `ulpf/mappings/*.yaml` at registration time for
configs carrying `generator: "ulpf.llm"` (written by
`python -m ulpf.llm.generate` after human approval; see
`ulpf/llm/generate.py`), compiling each one's `line_regex`, and registering
a small closure per vendor under its `format_hint`.

This never executes model-authored code: each config's `line_regex` is
only ever passed to `re.compile(...).match(...)`, exactly like every
hand-written parser's own regexes.

`ulpf/parsers/__init__.py` imports this module *last* (regardless of
alphabetical order) specifically so every hand-written vendor parser always
gets first refusal on a line before any dynamic one is tried - "existing
parsers keep priority".
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

import yaml

ParseFn = Callable[[str, dict[str, Any]], dict[str, Any] | None]

PORT_FIELDS = {"network.src_port", "network.dst_port"}
ALLOW_WORDS = {"allow", "allowed", "accept", "accepted"}
DENY_WORDS = {"deny", "denied", "drop", "dropped", "block", "blocked"}

# Cache of already-built parser closures, keyed by mapping file path. This
# is required for correctness, not just an optimization: `register()` runs
# once per `ulpf.pipeline.load_mappings()` call (i.e. every pipeline run /
# ingest server start), and the registry dedupes repeat registrations by
# function *identity* (see ulpf/detect.py's `register`). Without this
# cache, each call would mint a brand-new closure object for the same
# config file and the registry would grow without bound across repeated
# runs in one process.
_PARSER_CACHE: dict[str, ParseFn] = {}


def _set_outcome(event: dict[str, Any], action: str) -> None:
    lowered = action.lower()
    if lowered in ALLOW_WORDS:
        event["event.outcome"] = "success"
    elif lowered in DENY_WORDS:
        event["event.outcome"] = "failure"


def _make_parser(path: Path, config: dict[str, Any]) -> ParseFn:
    pattern = re.compile(config["line_regex"])
    field_map: dict[str, str] = config.get("field_map") or {}
    action_rules: list[dict[str, str]] = config.get("action_rules") or []
    vendor = str(config.get("vendor") or "")
    product = str(config.get("product") or "")
    category = str(config.get("category") or "network")
    format_hint = str(config.get("format_hint") or "")
    parser_name = f"llm:{vendor}" if vendor else f"llm:{path.stem}"

    def parse(line: str, mapping: dict[str, Any]) -> dict[str, Any] | None:
        match = pattern.match(line)
        if match is None:
            return None

        groups = match.groupdict()
        event: dict[str, Any] = {
            "observer.vendor": vendor,
            "observer.product": product,
            "event.category": category,
            "parse.format": format_hint,
            "parse.parser": parser_name,
            "parse.status": "ok",
            "parse.confidence": 1.0,
        }

        used_groups: set[str] = set()
        for target, group_name in field_map.items():
            value = groups.get(group_name)
            if value is None:
                continue
            used_groups.add(group_name)
            if target in PORT_FIELDS:
                if value.isdigit():
                    event[target] = int(value)
            else:
                event[target] = value

        action_value = event.get("event.action", "")
        for rule in action_rules:
            if rule.get("match") == action_value:
                action_value = str(rule.get("action", action_value))
                event["event.action"] = action_value
                break
        if action_value:
            _set_outcome(event, action_value)

        event["unmapped"] = {
            name: value
            for name, value in groups.items()
            if name not in used_groups and value is not None
        }
        return event

    return parse


def _load_dynamic_configs(mappings_dir: Path) -> list[tuple[Path, dict[str, Any]]]:
    configs: list[tuple[Path, dict[str, Any]]] = []
    if not mappings_dir.is_dir():
        return configs
    for path in sorted(mappings_dir.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if isinstance(data, dict) and data.get("generator") == "ulpf.llm":
            configs.append((path, data))
    return configs


def register(registry: Any) -> None:
    mappings_dir = Path(__file__).resolve().parent.parent / "mappings"
    for path, config in _load_dynamic_configs(mappings_dir):
        key = str(path)
        parse_fn = _PARSER_CACHE.get(key)
        if parse_fn is None:
            try:
                parse_fn = _make_parser(path, config)
            except Exception:
                # A malformed/hand-edited dynamic config must never take
                # down the whole pipeline at startup - skip it silently
                # (it simply won't be registered) rather than crash import.
                continue
            _PARSER_CACHE[key] = parse_fn
        registry.register(str(config.get("format_hint") or ""), parse_fn)
