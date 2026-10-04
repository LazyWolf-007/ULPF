"""Validates an LLM-proposed parser config before it's ever trusted.

Structured modes (`kv`, `json`, `cef`, `syslog_kv`, `rt_flow`, `mikrotik`)
carry no regex. Fields come from `ulpf.llm.structure`. Regex mode is only
for text that matches none of those detectors, and its pattern may have
at most 6 capture groups.

Checks, per the design:
  (a) the config matches the required schema (keys, types, allowed values).
  (b) regex mode: `line_regex` compiles, stays within 6 groups, and shows
      no catastrophic backtracking. Structured modes reject `line_regex`.
  (c) the tokenizer (or the regex) maps >= 80% of the sample lines.
  (d) src_ip/dst_ip/timestamp/action get extracted on lines that plainly
      contain one (checked against independent oracle regexes).
  (e) all of the above rolled into a `ValidationReport`.

None of this executes model-authored *code*. A regex, when one is allowed,
is compiled with `re.compile` and only used for `.match()`/`.groupdict()`.
There is no `eval`/`exec` anywhere in this module.
"""

from __future__ import annotations

import multiprocessing
import re
from dataclasses import dataclass, field
from typing import Any

# Reuse the same independent IP/timestamp/action oracles the generic
# fallback parser uses, so "does this line plainly contain a src/dst IP, a
# timestamp, an action word" is judged the same way everywhere in ULPF.
from ulpf.parsers.generic import ACTION_RE, IPV4_RE, IPV6_RE, ISO_TS_RE, SYSLOG_TS_RE

from ulpf.llm import structure

# Fields a capture is allowed to populate. Deliberately a subset of
# schema.EVENT_KEYS: identity/provenance/parse-status fields are
# pipeline-owned, not something a mapping should set directly.
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
    "mode": str,
    "field_map": dict,
    "action_rules": list,
    "timestamp": dict,
    "category": str,
}

MIN_RATE = 0.8

# Content-safety net: even syntactically valid JSON could smuggle a code
# string. Reject anything containing a giveaway token. The config is never
# eval'd regardless, so this is defense in depth.
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
    unmapped_required: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "score": self.score,
            "schema_errors": self.schema_errors,
            "regex_error": self.regex_error,
            "catastrophic_backtracking": self.catastrophic_backtracking,
            "match_rate": self.match_rate,
            "required_field_rate": self.required_field_rate,
            "unmapped_required": self.unmapped_required,
            "per_line": [
                {
                    "line": row.line,
                    "matched": row.matched,
                    "extracted": row.extracted,
                    "missing_required": row.missing_required,
                }
                for row in self.per_line
            ],
        }

    def error_summary(self) -> str:
        """Short human/LLM-readable text of what's wrong, for a retry prompt."""
        parts = list(self.schema_errors)
        if self.regex_error:
            parts.append(f"line_regex does not compile: {self.regex_error}")
        if self.catastrophic_backtracking:
            parts.append("line_regex shows catastrophic backtracking on a stress test string")
        # Rate lines only after coverage actually ran. A schema failure
        # returns before per_line is filled, and a 0.0 default would
        # otherwise look like a match-rate problem.
        if self.per_line:
            if self.match_rate < MIN_RATE:
                parts.append(f"only matched {self.match_rate:.0%} of sample lines (need >= 80%)")
            if self.required_field_rate < MIN_RATE:
                if self.unmapped_required:
                    parts.append("unmapped required fields: " + ", ".join(self.unmapped_required))
                else:
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
            errors.append(f"{key!r} must be a {expected_type.__name__}, got {type(config[key]).__name__}")

    mode = config.get("mode")
    if isinstance(mode, str) and mode not in structure.MODES:
        errors.append(f"mode {mode!r} not in {sorted(structure.MODES)}")

    if mode in structure.STRUCTURED_MODES and "line_regex" in config:
        errors.append(
            f"mode {mode!r} must not include line_regex; structured fields come from the tokenizer"
        )
    if mode == structure.REGEX_MODE and not (
        isinstance(config.get("line_regex"), str) and config["line_regex"].strip()
    ):
        errors.append("regex mode requires a non-empty line_regex")

    field_map = config.get("field_map")
    if isinstance(field_map, dict):
        for target, source in field_map.items():
            if not isinstance(target, str) or not isinstance(source, str):
                errors.append(f"field_map entry {target!r}: {source!r} must be string -> string")
                continue
            if target not in ALLOWED_FIELD_MAP_TARGETS:
                errors.append(
                    f"field_map key {target!r} is not a valid target field; use one of "
                    f"{sorted(ALLOWED_FIELD_MAP_TARGETS)}"
                )

    action_rules = config.get("action_rules")
    if isinstance(action_rules, list):
        for index, rule in enumerate(action_rules):
            if not isinstance(rule, dict) or "match_value" not in rule or "action" not in rule:
                errors.append(f"action_rules[{index}] must be an object with 'match_value' and 'action' keys")
            elif not isinstance(rule.get("match_value"), str) or not isinstance(rule.get("action"), str):
                errors.append(f"action_rules[{index}] 'match_value' and 'action' must be strings")

    timestamp = config.get("timestamp")
    if isinstance(timestamp, dict):
        keys = timestamp.get("keys")
        if not isinstance(keys, list) or not all(isinstance(item, str) for item in keys):
            errors.append("timestamp.keys must be a list of strings")
        if not isinstance(timestamp.get("format"), str):
            errors.append("timestamp.format must be a string")

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
        for index, sub in enumerate(value):
            found.extend(_walk_strings(sub, f"{path}[{index}]"))
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


def _prepare_regex(
    config: dict[str, Any], check_backtracking: bool
) -> tuple[re.Pattern[str] | None, ValidationReport | None]:
    """Compile a regex-mode pattern. Returns `(pattern, error_report)`."""
    pattern_text = config.get("line_regex")
    if not isinstance(pattern_text, str) or not pattern_text.strip():
        return None, ValidationReport(
            ok=False, score=0.0, schema_errors=["regex mode requires a non-empty line_regex"]
        )
    try:
        pattern = re.compile(pattern_text)
    except re.error as exc:
        return None, ValidationReport(ok=False, score=0.0, regex_error=str(exc))
    if pattern.groups > structure.MAX_CAPTURE_GROUPS:
        return None, ValidationReport(
            ok=False,
            score=0.0,
            schema_errors=[
                f"line_regex has {pattern.groups} capture groups; "
                f"the limit is {structure.MAX_CAPTURE_GROUPS}"
            ],
        )
    if check_backtracking and _has_catastrophic_backtracking(pattern_text):
        return None, ValidationReport(ok=False, score=0.0, catastrophic_backtracking=True)
    return pattern, None


def _reference_errors(config: dict[str, Any], names: set[str], kind: str) -> list[str]:
    """field_map values and timestamp keys must name real sources.

    `kind` is ``"key"`` (structured) or ``"group"`` (regex). `names` is
    the allow-list. Empty `names` means "we have nothing to compare
    against" (wrong mode, no samples) and is not itself an error here.
    """
    if not names:
        return []
    listed = ", ".join(sorted(names))
    label = "named group in line_regex" if kind == "group" else "key extracted from the samples"
    known = f"groups: {listed}" if kind == "group" else f"known keys: {listed}"
    errors: list[str] = []
    field_map = config.get("field_map")
    if isinstance(field_map, dict):
        for source in field_map.values():
            if isinstance(source, str) and source not in names:
                errors.append(f"field_map value {source!r} is not a {label}; {known}")
    timestamp = config.get("timestamp")
    if isinstance(timestamp, dict):
        for source in timestamp.get("keys") or []:
            if isinstance(source, str) and source not in names:
                errors.append(f"timestamp key {source!r} is not a {label}; {known}")
    return errors


def _oracle_requirements(line: str) -> set[str]:
    """What an independent, config-agnostic scan thinks this line contains."""
    present: set[str] = set()
    if IPV4_RE.search(line) or any(candidate.count(":") >= 2 for candidate in IPV6_RE.findall(line)):
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


def _coverage(
    config: dict[str, Any], samples: list[str], pattern: re.Pattern[str] | None
) -> tuple[float, float, list[LineResult], list[str]]:
    field_map = config.get("field_map") if isinstance(config.get("field_map"), dict) else {}
    timestamp = config.get("timestamp") if isinstance(config.get("timestamp"), dict) else {}
    per_line: list[LineResult] = []
    matched_count = 0
    required_present = 0
    required_extracted = 0
    missing_seen: set[str] = set()

    for line in samples:
        ok_line, fields = structure.source_fields(config, line, pattern)
        if not ok_line:
            per_line.append(LineResult(line=line, matched=False))
            continue
        matched_count += 1
        extracted, _used = structure.apply_field_map(fields, field_map, timestamp)
        oracle = _oracle_requirements(line)
        missing: list[str] = []
        for oracle_key in oracle:
            required_present += 1
            target_field = _REQUIRED_ORACLE_TO_FIELD[oracle_key]
            if extracted.get(target_field):
                required_extracted += 1
            else:
                missing.append(target_field)
                missing_seen.add(target_field)
        per_line.append(
            LineResult(line=line, matched=True, extracted=extracted, missing_required=sorted(missing))
        )

    total = len(samples)
    match_rate = matched_count / total if total else 0.0
    required_field_rate = required_extracted / required_present if required_present else 1.0
    return match_rate, required_field_rate, per_line, sorted(missing_seen)


def validate_schema_only(config: Any) -> ValidationReport:
    """Schema checks, plus regex compile/group-limit/backtracking when needed.

    Used by `ulpf.llm.generate --replay` when no `--samples` file is given.
    There is nothing to compute a match rate against, but a replayed config
    should still be well-formed rather than trusted blindly.
    """
    schema_errors = _schema_errors(config)
    if schema_errors or not isinstance(config, dict):
        return ValidationReport(ok=False, score=0.0, schema_errors=schema_errors)
    if config.get("mode") != structure.REGEX_MODE:
        return ValidationReport(ok=True, score=1.0)
    pattern, problem = _prepare_regex(config, check_backtracking=True)
    if problem is not None:
        return problem
    assert pattern is not None
    group_errors = _reference_errors(config, set(pattern.groupindex), "group")
    if group_errors:
        return ValidationReport(ok=False, score=0.0, schema_errors=group_errors)
    return ValidationReport(ok=True, score=1.0)


def validate(
    config: Any, samples: list[str], check_backtracking: bool = True
) -> ValidationReport:
    """Run every check against `config` and `samples`.

    `check_backtracking=False` skips the (comparatively slow, subprocess-
    spawning) ReDoS guard - used by generator-loop tests that are
    exercising retry behavior, not regex safety, to keep the test suite
    fast; the CLI and the dedicated validator tests always leave it on.

    `ok` requires both match_rate >= 80% and required-field coverage >= 80%,
    and no schema / regex / backtracking errors. Coverage below the line
    is what makes the retry loop name the unmapped required fields.
    """
    schema_errors = _schema_errors(config)
    if schema_errors or not isinstance(config, dict):
        return ValidationReport(ok=False, score=0.0, schema_errors=schema_errors)

    mode = config.get("mode")
    detected = structure.detect_mode(samples) if samples else structure.REGEX_MODE
    if mode == structure.REGEX_MODE and detected in structure.STRUCTURED_MODES:
        return ValidationReport(
            ok=False,
            score=0.0,
            schema_errors=[
                f"samples are structured ({detected}); regex mode is not allowed "
                "and line_regex will not be used"
            ],
        )

    pattern: re.Pattern[str] | None = None
    reference_errors: list[str] = []
    if mode == structure.REGEX_MODE:
        pattern, problem = _prepare_regex(config, check_backtracking=check_backtracking)
        if problem is not None:
            return problem
        assert pattern is not None
        reference_errors = _reference_errors(config, set(pattern.groupindex), "group")
    elif mode in structure.STRUCTURED_MODES:
        reference_errors = _reference_errors(config, set(structure.keys_for_mode(samples, str(mode))), "key")

    match_rate, required_field_rate, per_line, unmapped = _coverage(config, samples, pattern)
    score = round(0.6 * match_rate + 0.4 * required_field_rate, 4)
    ok = (
        not reference_errors
        and match_rate >= MIN_RATE
        and required_field_rate >= MIN_RATE
    )
    return ValidationReport(
        ok=ok,
        score=score,
        schema_errors=reference_errors,
        match_rate=round(match_rate, 4),
        required_field_rate=round(required_field_rate, 4),
        per_line=per_line,
        unmapped_required=unmapped,
    )
