"""Data-driven parser for LLM-generated vendor configs.

One Python module handles every LLM-onboarded vendor. At registration it
scans `ulpf/mappings/*.yaml` for configs carrying `generator: "ulpf.llm"`
(written by `python -m ulpf.llm.generate` after human approval).

Structured modes (`kv`, `json`, `cef`, `syslog_kv`, `rt_flow`, `mikrotik`)
never compile a model regex. The line is tokenized with `ulpf.llm.structure`
and `field_map` copies source keys onto internal fields. Regex mode is the
unstructured fallback and is limited to 6 capture groups.

`rt_flow` rewrites protocol numbers 6/17/1 to tcp/udp/icmp, and
`RT_FLOW_SESSION_CREATE` / `RT_FLOW_SESSION_DENY` to allow / deny.
`mikrotik` rewrites the verdict word `drop` to deny and `accept` to allow.
The chain name (`forward`, `input`) is not an action.

Configs written before `mode` existed (a `line_regex` and a `format_hint`,
no `mode`) still load. That path is what the original dynamic-parser tests
exercise; new configs go through the tokenizer.

`ulpf/parsers/__init__.py` imports this module last so every hand-written
vendor parser gets first refusal on a line.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Callable

import yaml

from ulpf.llm import structure

ParseFn = Callable[[str, dict[str, Any]], dict[str, Any] | None]

PORT_FIELDS = {"network.src_port", "network.dst_port"}
ALLOW_WORDS = {"allow", "allowed", "accept", "accepted"}
DENY_WORDS = {"deny", "denied", "drop", "dropped", "block", "blocked"}
_RT_PROTO = {"6": "tcp", "17": "udp", "1": "icmp"}
# Chain names from a RouterOS firewall sentence. Not verdicts.
_MT_CHAINS = frozenset({"forward", "input"})

# Cache of already-built parser closures, keyed by mapping file path. This
# is required for correctness, not just an optimization: `register()` runs
# once per `ulpf.pipeline.load_mappings()` call, and the registry dedupes
# repeat registrations by function *identity*. Without this cache each call
# would mint a new closure and the registry would grow without bound.
_PARSER_CACHE: dict[str, ParseFn] = {}


def _set_outcome(event: dict[str, Any], action: str) -> None:
    lowered = action.lower()
    if lowered in ALLOW_WORDS:
        event["event.outcome"] = "success"
    elif lowered in DENY_WORDS:
        event["event.outcome"] = "failure"


def _apply_action_rules(action_value: str, rules: list[Any]) -> str:
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        # New configs say match_value. Older regex configs say match.
        if "match_value" in rule:
            needle = rule.get("match_value")
        else:
            needle = rule.get("match")
        if needle == action_value:
            return str(rule.get("action", action_value))
    return action_value


def _apply_rt_flow(event: dict[str, Any], fields: dict[str, str], used: set[str]) -> None:
    """Protocol numbers and session verbs are grammar, not model output."""
    protocol = fields.get("protocol")
    if protocol in _RT_PROTO:
        event["network.transport"] = _RT_PROTO[protocol]
        used.add("protocol")
    event_name = fields.get("event") or ""
    if "SESSION_CREATE" in event_name:
        event["event.action"] = "allow"
        used.add("event")
        _set_outcome(event, "allow")
    elif "SESSION_DENY" in event_name:
        event["event.action"] = "deny"
        used.add("event")
        _set_outcome(event, "deny")


def _apply_mikrotik(event: dict[str, Any], fields: dict[str, str], used: set[str]) -> None:
    """`drop` is deny and `accept` is allow. The chain is not an action."""
    chain = (fields.get("chain") or "").strip().lower()
    current = str(event.get("event.action") or "").strip().lower()
    if current in _MT_CHAINS or (chain and current == chain):
        event.pop("event.action", None)
        event.pop("event.outcome", None)
        if chain:
            used.discard("chain")
    verb = (fields.get("action") or "").strip().lower()
    if verb == "drop":
        event["event.action"] = "deny"
        used.add("action")
        _set_outcome(event, "deny")
    elif verb == "accept":
        event["event.action"] = "allow"
        used.add("action")
        _set_outcome(event, "allow")


def _finish_action(event: dict[str, Any], rules: list[Any]) -> None:
    action_value = str(event.get("event.action") or "")
    action_value = _apply_action_rules(action_value, rules)
    if action_value:
        event["event.action"] = action_value
        _set_outcome(event, action_value)


def _base_event(config: dict[str, Any], path: Path, route: str) -> dict[str, Any]:
    vendor = str(config.get("vendor") or "")
    product = str(config.get("product") or "")
    return {
        "observer.vendor": vendor,
        "observer.product": product,
        "event.category": str(config.get("category") or "network"),
        "parse.format": route or str(config.get("mode") or ""),
        "parse.parser": f"llm:{vendor}" if vendor else f"llm:{path.stem}",
        "parse.status": "ok",
        "parse.confidence": 1.0,
    }


def _claims(fields: dict[str, str], field_map: dict[str, Any], timestamp: dict[str, Any]) -> bool:
    """True when at least one mapped source key is actually on this line.

    A kv-mode config must not claim every kv line on the box — only lines
    that carry one of its own keys. Hand-written parsers still run first.
    """
    wanted: list[str] = []
    if isinstance(field_map, dict):
        wanted.extend(value for value in field_map.values() if isinstance(value, str))
    keys = timestamp.get("keys") if isinstance(timestamp, dict) else None
    if isinstance(keys, list):
        wanted.extend(key for key in keys if isinstance(key, str))
    return any(fields.get(name) for name in wanted)


def _assign_extracted(event: dict[str, Any], extracted: dict[str, str]) -> None:
    for target, value in extracted.items():
        if target in PORT_FIELDS:
            if str(value).isdigit():
                event[target] = int(value)
        else:
            event[target] = value


def _route(config: dict[str, Any]) -> str:
    hint = config.get("format_hint")
    if isinstance(hint, str) and hint.strip():
        return hint.strip()
    return structure.route_for_mode(str(config.get("mode") or ""))


def _make_structured_parser(path: Path, config: dict[str, Any]) -> ParseFn:
    field_map = config.get("field_map")
    if not isinstance(field_map, dict):
        raise ValueError(f"{path.name}: field_map must be an object")
    timestamp = config.get("timestamp") if isinstance(config.get("timestamp"), dict) else {}
    action_rules = config.get("action_rules") if isinstance(config.get("action_rules"), list) else []
    mode = str(config.get("mode") or "")
    route = _route(config)
    base = _base_event(config, path, route)

    def parse(line: str, mapping: dict[str, Any]) -> dict[str, Any] | None:
        del mapping  # the approved config is closed over; YAML is not re-read per line
        if mode == "rt_flow":
            fields = structure.rt_flow_fields(line)
        else:
            tokenized = structure.tokenize(line)
            fields = tokenized.fields if tokenized.mode == mode else None
        if not fields:
            return None
        if not _claims(fields, field_map, timestamp):
            return None
        extracted, used = structure.apply_field_map(fields, field_map, timestamp)
        event = dict(base)
        _assign_extracted(event, extracted)
        _finish_action(event, action_rules)
        if mode == "rt_flow":
            _apply_rt_flow(event, fields, used)
        elif mode == "mikrotik":
            _apply_mikrotik(event, fields, used)
        event["unmapped"] = {
            key: value for key, value in fields.items() if key not in used
        }
        return event

    return parse


def _make_regex_parser(path: Path, config: dict[str, Any], limit_groups: bool) -> ParseFn:
    pattern_text = config.get("line_regex")
    if not isinstance(pattern_text, str) or not pattern_text.strip():
        raise ValueError(f"{path.name}: regex mode requires line_regex")
    pattern = re.compile(pattern_text)
    if limit_groups and pattern.groups > structure.MAX_CAPTURE_GROUPS:
        raise ValueError(
            f"{path.name}: line_regex has {pattern.groups} capture groups; "
            f"the limit is {structure.MAX_CAPTURE_GROUPS}"
        )
    field_map: dict[str, str] = config.get("field_map") or {}
    action_rules: list[Any] = config.get("action_rules") or []
    route = _route(config)
    base = _base_event(config, path, route)

    def parse(line: str, mapping: dict[str, Any]) -> dict[str, Any] | None:
        del mapping
        match = pattern.match(line)
        if match is None:
            return None
        groups = match.groupdict()
        event = dict(base)
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
        _finish_action(event, action_rules)
        event["unmapped"] = {
            name: value for name, value in groups.items() if name not in used_groups and value is not None
        }
        return event

    return parse


def _make_parser(path: Path, config: dict[str, Any]) -> ParseFn:
    mode = config.get("mode")
    if mode in structure.STRUCTURED_MODES:
        return _make_structured_parser(path, config)
    # `mode: regex` is the new unstructured fallback (6-group cap).
    # A line_regex with no mode is a config from the previous generator.
    if mode == structure.REGEX_MODE or (mode is None and isinstance(config.get("line_regex"), str)):
        return _make_regex_parser(path, config, limit_groups=(mode == structure.REGEX_MODE))
    raise ValueError(f"unsupported dynamic config in {path.name}")


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
        registry.register(_route(config), parse_fn)
