"""Validates an LLM-proposed parser config before it's ever trusted.

Five checks, per the design:
  (a) the config matches the required schema (keys, types, allowed values).
  (b) `line_regex` compiles and shows no catastrophic backtracking.
  (c) the compiled regex matches >= 80% of the sample lines.
  (d) src_ip/dst_ip/timestamp/action get extracted on lines that plainly
      contain one (checked against independent oracle regexes, not the
      config's own claims).
  (e) all of the above rolled into a `ValidationReport` with a per-line
      breakdown and a 0-1 score.

None of this executes model-authored *code* - `line_regex` is compiled with
`re.compile` and only ever used for `.match()`/`.groupdict()`; there is no
`eval`/`exec` anywhere in this module.
"""

from __future__ import annotations

import multiprocessing
import re
from dataclasses import dataclass, field
from typing import Any

# Reuse the same independent IP/timestamp/action oracles the generic
# fallback parser uses, so "does this line plainly contain a src/dst IP, a
# timestamp, an action word" is judged the same way everywhere in ULPF
# rather than re-implemented a second, possibly-inconsistent way here.
from ulpf.parsers.generic import ACTION_RE, IPV4_RE, IPV6_RE, ISO_TS_RE, SYSLOG_TS_RE

REQUIRED_FORMAT_HINTS = frozenset({"json", "cef", "leef", "kv", "syslog", "unknown"})

# Fields a regex capture is actually allowed to populate. Deliberately a
# subset of schema.EVENT_KEYS: identity/provenance/parse-status fields
# (event_id, parse.*, provenance.*, unmapped) are pipeline-owned, not
# something a line_regex capture should set directly.
ALLOWED_FIELD_MAP_TARGETS = frozenset(
    {
        "network.src_ip",
        "network.src_port",
        "network.dst_ip",
        "network.dst_port",
        "network.transport",
        "user.name",
        "event.action",
        "event.description",
        "event.severity",
        "observer.name",
        "timestamp",
    }
)

REQUIRED_TOP_LEVEL_KEYS = {
    "vendor": str,
    "product": str,
    "format_hint": str,
    "line_regex": str,
    "field_map": dict,
    "action_rules": list,
    "timestamp_format": str,
    "category": str,
}

# Content-safety net for item 3 ("never Python code"): even syntactically
# valid JSON could smuggle a code string in some field. Reject anything
# containing a giveaway token - cheap, and this config is never eval'd
# regardless, so this is defense in depth, not the only protection.
_CODE_MARKERS = ("import ", "def ", "class ", "eval(", "exec(", "__import__", "subprocess", "os.system")

# Adversarial-but-short probe strings for the catastrophic-backtracking
# guard. Kept short (<=31 chars) - a genuinely catastrophic pattern blows
# up exponentially even at this length, while keeping the process-based
# guard's overhead low for the common (safe) case.
_STRESS_STRINGS: tuple[str, ...] = ("a" * 30 + "!", "0" * 30 + "x")
_BACKTRACK_TIMEOUT = 1.0


@dataclass
class LineResult:
    line: str
    matched: bool
    extracted: dict[str, str] = field(default_factory=dict)
    missing_required: list[str] = field(default_factory=list)


@dataclass
class ValidationReport:
    ok: bool
    score: float
    schema_errors: list[str] = field(default_factory=list)
    regex_error: str | None = None
    catastrophic_backtracking: bool = False
    match_rate: float = 0.0
    required_field_rate: float = 0.0
    per_line: list[LineResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "score": self.score,
            "schema_errors": self.schema_errors,
            "regex_error": self.regex_error,
            "catastrophic_backtracking": self.catastrophic_backtracking,
            "match_rate": self.match_rate,
            "required_field_rate": self.required_field_rate,
            "per_line": [
                {
                    "line": r.line,
                    "matched": r.matched,
                    "extracted": r.extracted,
                    "missing_required": r.missing_required,
                }
                for r in self.per_line
            ],
        }

    def error_summary(self) -> str:
        """Short human/LLM-readable text of what's wrong, for a retry prompt."""
        parts = list(self.schema_errors)
        if self.regex_error:
            parts.append(f"line_regex does not compile: {self.regex_error}")
        if self.catastrophic_backtracking:
            parts.append("line_regex shows catastrophic backtracking on a stress test string")
        if self.match_rate < 0.8:
            parts.append(f"line_regex only matched {self.match_rate:.0%} of sample lines (need >= 80%)")
        if self.required_field_rate < 0.8:
            parts.append(
                f"only {self.required_field_rate:.0%} of present src_ip/dst_ip/timestamp/action "
                "values were actually captured (need >= 80%)"
            )
        return "; ".join(parts) if parts else "no errors"


def _schema_errors(config: Any) -> list[str]:
    errors: list[str] = []
    if not isinstance(config, dict):
        return [f"config must be a JSON object, got {type(config).__name__}"]

    for key, expected_type in REQUIRED_TOP_LEVEL_KEYS.items():
        if key not in config:
            errors.append(f"missing required key {key!r}")
            continue
        if not isinstance(config[key], expected_type):
            errors.append(
                f"{key!r} must be a {expected_type.__name__}, got {type(config[key]).__name__}"
            )

    if isinstance(config.get("format_hint"), str) and config["format_hint"] not in REQUIRED_FORMAT_HINTS:
        errors.append(
            f"format_hint {config['format_hint']!r} not in {sorted(REQUIRED_FORMAT_HINTS)}"
        )

    field_map = config.get("field_map")
    if isinstance(field_map, dict):
        for target, group in field_map.items():
            if not isinstance(target, str) or not isinstance(group, str):
                errors.append(f"field_map entry {target!r}: {group!r} must be string -> string")
                continue
            if target not in ALLOWED_FIELD_MAP_TARGETS:
                errors.append(
                    f"field_map key {target!r} is not a valid target field; use one of "
                    f"{sorted(ALLOWED_FIELD_MAP_TARGETS)}"
                )

    action_rules = config.get("action_rules")
    if isinstance(action_rules, list):
        for i, rule in enumerate(action_rules):
            if not isinstance(rule, dict) or "match" not in rule or "action" not in rule:
                errors.append(f"action_rules[{i}] must be an object with 'match' and 'action' keys")

    # Content-safety: scan every string value (recursively) for code markers.
    for path, value in _walk_strings(config):
        lowered = value.lower()
        if any(marker in lowered for marker in _CODE_MARKERS):
            errors.append(f"value at {path} looks like code, not data: {value[:60]!r}")

    return errors


def _walk_strings(value: Any, path: str = "$") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(value, str):
        found.append((path, value))
    elif isinstance(value, dict):
        for key, sub in value.items():
            found.extend(_walk_strings(sub, f"{path}.{key}"))
    elif isinstance(value, list):
        for i, sub in enumerate(value):
            found.extend(_walk_strings(sub, f"{path}[{i}]"))
    return found


def _match_worker(pattern_str: str, text: str) -> None:
    re.compile(pattern_str).match(text)


def _has_catastrophic_backtracking(pattern_str: str, timeout: float = _BACKTRACK_TIMEOUT) -> bool:
    """Best-effort ReDoS guard.

    Must use a *process*, not a thread: CPython's `re` engine does not
    release the GIL during a match, so a thread-based timeout cannot
    actually interrupt a runaway match - only OS-level process termination
    can (verified directly: a thread-based version left the whole
    interpreter unresponsive for 30+ seconds on the exact stress string
    used here). A subprocess can be killed regardless of what it's stuck
    doing internally.
    """
    try:
        ctx = multiprocessing.get_context("spawn")
        for stress in _STRESS_STRINGS:
            process = ctx.Process(target=_match_worker, args=(pattern_str, stress))
            process.start()
            process.join(timeout=timeout)
            if process.is_alive():
                process.terminate()
                process.join(timeout=1.0)
                if process.is_alive():
                    process.kill()
                return True
    except OSError:
        # Could not even spawn a probe process - treat as "unverified", and
        # conservatively refuse rather than silently assume the regex is safe.
        return True
    return False


def _oracle_requirements(line: str) -> set[str]:
    """What an independent, config-agnostic scan thinks this line contains."""
    present: set[str] = set()
    if IPV4_RE.search(line) or any(c.count(":") >= 2 for c in IPV6_RE.findall(line)):
        present.add("src_ip")
        present.add("dst_ip")
    if ISO_TS_RE.search(line) or SYSLOG_TS_RE.search(line):
        present.add("timestamp")
    if ACTION_RE.search(line):
        present.add("action")
    return present


_REQUIRED_ORACLE_TO_FIELD = {
    "src_ip": "network.src_ip",
    "dst_ip": "network.dst_ip",
    "timestamp": "timestamp",
    "action": "event.action",
}


def validate_schema_only(config: Any) -> ValidationReport:
    """Schema + regex-compile + backtracking checks, with no sample lines.

    Used by `ulpf.llm.generate --replay` when no `--samples` file is given:
    there's nothing to compute a match rate against, but a replayed config
    should still be checked for being well-formed rather than trusted
    blindly (a stale or hand-edited replay file could be broken).
    """
    schema_errors = _schema_errors(config)
    if schema_errors:
        return ValidationReport(ok=False, score=0.0, schema_errors=schema_errors)
    try:
        re.compile(config["line_regex"])
    except re.error as exc:
        return ValidationReport(ok=False, score=0.0, regex_error=str(exc))
    catastrophic = _has_catastrophic_backtracking(config["line_regex"])
    return ValidationReport(ok=not catastrophic, score=0.0 if catastrophic else 1.0, catastrophic_backtracking=catastrophic)


def validate(
    config: Any, samples: list[str], check_backtracking: bool = True
) -> ValidationReport:
    """Run all five checks against `config` and `samples`.

    `check_backtracking=False` skips the (comparatively slow, subprocess-
    spawning) ReDoS guard - used by generator-loop tests that are
    exercising retry behavior, not regex safety, to keep the test suite
    fast; the CLI and the dedicated validator tests always leave it on.
    """
    schema_errors = _schema_errors(config)
    if schema_errors:
        return ValidationReport(ok=False, score=0.0, schema_errors=schema_errors)

    pattern_str = config["line_regex"]
    try:
        pattern = re.compile(pattern_str)
    except re.error as exc:
        return ValidationReport(ok=False, score=0.0, regex_error=str(exc))

    catastrophic = check_backtracking and _has_catastrophic_backtracking(pattern_str)
    if catastrophic:
        return ValidationReport(ok=False, score=0.0, catastrophic_backtracking=True)

    field_map: dict[str, str] = config["field_map"]
    per_line: list[LineResult] = []
    matched_count = 0
    required_present = 0
    required_extracted = 0

    for line in samples:
        match = pattern.match(line)
        if match is None:
            per_line.append(LineResult(line=line, matched=False))
            continue
        matched_count += 1
        groups = match.groupdict()
        extracted = {
            target: groups[group_name]
            for target, group_name in field_map.items()
            if group_name in groups and groups[group_name] is not None
        }

        oracle = _oracle_requirements(line)
        missing = []
        for oracle_key in oracle:
            required_present += 1
            target_field = _REQUIRED_ORACLE_TO_FIELD[oracle_key]
            if extracted.get(target_field):
                required_extracted += 1
            else:
                missing.append(target_field)

        per_line.append(LineResult(line=line, matched=True, extracted=extracted, missing_required=missing))

    total = len(samples)
    match_rate = matched_count / total if total else 0.0
    required_field_rate = required_extracted / required_present if required_present else 1.0

    ok = match_rate >= 0.8
    score = round(0.6 * match_rate + 0.4 * required_field_rate, 4)

    return ValidationReport(
        ok=ok,
        score=score,
        match_rate=round(match_rate, 4),
        required_field_rate=round(required_field_rate, 4),
        per_line=per_line,
    )
