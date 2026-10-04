"""Builds the prompt and runs the generate -> validate -> retry loop.

The model never sees raw lines for a structured format and never writes
the regex that pulls fields out of them. `ulpf.llm.structure` tokenizes
the samples; the prompt shows each source key with up to two example
values and asks for a field map. Regex mode is only the fallback for
unstructured text, and that pattern is capped at 6 capture groups.

Every attempt is checked with `validator.validate`. Up to `max_retries`
retries feed the previous attempt, the validator error summary, and the
names of required fields that are still unmapped back into the prompt.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from ulpf.llm import structure, validator

# The first prompt (no retry suffix) stays under this. ~4 characters per
# token is a conservative stand-in for a real tokenizer; the prompt is
# key names and two short examples, not raw lines or few-shot YAML.
PROMPT_TOKEN_BUDGET = 800


class LLMClient(Protocol):
    def generate(self, prompt: str) -> str: ...


@dataclass
class GenerationResult:
    config: dict[str, Any] | None
    report: validator.ValidationReport
    attempts: int
    seconds: float
    raw_responses: list[str] = field(default_factory=list)


def estimate_tokens(text: str) -> int:
    """Rough upper bound used to keep the structured prompt small."""
    return (len(text) + 3) // 4


def _field_list() -> str:
    return ", ".join(sorted(validator.ALLOWED_FIELD_MAP_TARGETS))


def _retry_suffix(
    previous_attempt: dict[str, Any] | None,
    previous_errors: str | None,
    unmapped_required: list[str] | None,
) -> str:
    if previous_attempt is None:
        return ""
    lines = [
        "Your previous attempt was:",
        json.dumps(previous_attempt, ensure_ascii=False),
        "It failed validation: " + (previous_errors or "unknown error"),
    ]
    if unmapped_required:
        lines.append("Unmapped required fields: " + ", ".join(unmapped_required))
        lines.append("Map each of these internal fields from the keys or groups above.")
    return "\n" + "\n".join(lines)


def _structured_prompt(
    samples: list[str],
    vendor_hint: str | None,
    detected: str,
    previous_attempt: dict[str, Any] | None,
    previous_errors: str | None,
    unmapped_required: list[str] | None,
) -> str:
    examples = structure.example_values(samples, limit=2)
    key_lines = [f"  {key}: {' | '.join(values)}" for key, values in examples.items()]
    keys_block = "\n".join(key_lines) if key_lines else "  (none)"
    vendor = f"Vendor hint: {vendor_hint}\n" if vendor_hint else ""
    shape = (
        '{"vendor":"","product":"","mode":"' + detected + '",'
        '"field_map":{"<internal>":"<source key>"},'
        '"action_rules":[{"match_value":"<raw>","action":"<canonical>"}],'
        '"timestamp":{"keys":[],"format":""},"category":"network"}'
    )
    body = (
        "Map log fields for ULPF. Reply with one JSON object only.\n"
        f"Detected mode: {detected}\n"
        "Source keys and up to two example values:\n"
        f"{keys_block}\n"
        "Fill field_map. Use only the source keys above. Do not output a regular expression.\n"
        f'mode must be "{detected}".\n'
        "field_map key is an internal field; field_map value is a source key.\n"
        f"Internal fields: {_field_list()}\n"
        f"JSON: {shape}\n"
        f"{vendor}"
        "category is network or authentication."
    )
    return body + _retry_suffix(previous_attempt, previous_errors, unmapped_required)


def _regex_prompt(
    samples: list[str],
    vendor_hint: str | None,
    previous_attempt: dict[str, Any] | None,
    previous_errors: str | None,
    unmapped_required: list[str] | None,
) -> str:
    shown = "\n".join(f"{index + 1}. {line[:180]}" for index, line in enumerate(samples[:8]))
    vendor = f"Vendor hint: {vendor_hint}\n" if vendor_hint else ""
    body = (
        "These log lines have no kv, JSON, CEF, or syslog key structure.\n"
        'Reply with one JSON object only. mode must be "regex".\n'
        f"line_regex: a Python re pattern applied with re.match, at most "
        f"{structure.MAX_CAPTURE_GROUPS} named capture groups.\n"
        "field_map maps an internal field to a group name.\n"
        f"Internal fields: {_field_list()}\n"
        "JSON keys: vendor, product, mode, line_regex, field_map, "
        "action_rules [{match_value, action}], timestamp {keys, format}, category.\n"
        f"{vendor}"
        f"Lines:\n{shown}"
    )
    return body + _retry_suffix(previous_attempt, previous_errors, unmapped_required)


def build_prompt(
    samples: list[str],
    vendor_hint: str | None,
    model: str,
    previous_attempt: dict[str, Any] | None = None,
    previous_errors: str | None = None,
    unmapped_required: list[str] | None = None,
) -> str:
    """Assemble the prompt. `model` is accepted for callers; size no longer changes the prompt.

    Structured samples: source keys and two example values, asking only
    for field_map (plus the short shell of vendor/product/mode/rules/
    timestamp/category). Unstructured samples: the lines themselves and a
    regex capped at 6 capture groups.
    """
    _ = model  # prompt budget is fixed; model size used to add a second few-shot file
    detected = structure.detect_mode(samples)
    if detected == structure.REGEX_MODE:
        return _regex_prompt(samples, vendor_hint, previous_attempt, previous_errors, unmapped_required)
    return _structured_prompt(
        samples, vendor_hint, detected, previous_attempt, previous_errors, unmapped_required
    )


def apply_detected_mode(
    config: Any,
    samples: list[str],
    vendor_hint: str | None = None,
) -> Any:
    """Force `rt_flow` / `mikrotik` when detection says so.

    The model may return only field_map, action_rules, a timestamp format,
    and category. A `mode` of ``regex`` and any `line_regex` are discarded.
    A missing category becomes ``network``. Other modes are left untouched
    so a wrong guess (json on kv samples) still fails and retries.
    """
    if not isinstance(config, dict):
        return config
    detected = structure.detect_mode(samples)
    if detected not in structure.FORCED_MODES:
        return config

    cleaned = {key: value for key, value in config.items() if key != "line_regex"}
    cleaned["mode"] = detected
    category = cleaned.get("category")
    if not isinstance(category, str) or not category.strip():
        cleaned["category"] = "network"
    if not isinstance(cleaned.get("vendor"), str):
        cleaned["vendor"] = vendor_hint or ""
    if not isinstance(cleaned.get("product"), str):
        cleaned["product"] = ""
    if not isinstance(cleaned.get("field_map"), dict):
        cleaned["field_map"] = {}
    if not isinstance(cleaned.get("action_rules"), list):
        cleaned["action_rules"] = []

    timestamp = cleaned.get("timestamp")
    if isinstance(timestamp, str):
        timestamp = {"keys": [], "format": timestamp}
    elif isinstance(timestamp, dict):
        timestamp = dict(timestamp)
    else:
        timestamp = {"keys": [], "format": ""}
    if not isinstance(timestamp.get("format"), str):
        timestamp["format"] = ""
    keys = timestamp.get("keys")
    if not isinstance(keys, list):
        keys = []
    if not keys and "timestamp" in structure.keys_for_mode(samples, detected):
        keys = ["timestamp"]
    timestamp["keys"] = keys
    cleaned["timestamp"] = timestamp
    return cleaned


def _extract_json(text: str) -> str:
    """Strip a markdown code fence some models add despite format=json."""
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    return stripped


def generate_config(
    client: LLMClient,
    samples: list[str],
    vendor_hint: str | None = None,
    max_retries: int = 2,
    check_backtracking: bool = True,
) -> GenerationResult:
    """Generate -> validate -> (on failure) retry, up to `max_retries` times.

    Always returns the *last* attempted config (even if it never passed
    validation) alongside its report, so a human can still inspect - and
    choose to approve - a close-but-imperfect result rather than getting
    nothing back. On the way out, `format_hint` is set from detect.py so
    the dynamic parser registers on the route the pipeline actually uses.
    """
    start = time.monotonic()
    model = getattr(client, "model", "unknown")
    previous_attempt: dict[str, Any] | None = None
    previous_errors: str | None = None
    unmapped: list[str] = []
    raw_responses: list[str] = []
    last_report = validator.ValidationReport(ok=False, score=0.0, schema_errors=["no attempt made"])
    last_config: dict[str, Any] | None = None
    attempt = 0

    for attempt in range(max_retries + 1):
        prompt = build_prompt(
            samples, vendor_hint, model, previous_attempt, previous_errors, unmapped
        )
        raw_text = client.generate(prompt)
        raw_responses.append(raw_text)

        try:
            config = json.loads(_extract_json(raw_text))
        except json.JSONDecodeError as exc:
            last_report = validator.ValidationReport(
                ok=False, score=0.0, schema_errors=[f"response was not valid JSON: {exc}"]
            )
            previous_attempt = {"_raw_non_json_response": raw_text[:500]}
            previous_errors = last_report.error_summary()
            unmapped = []
            continue

        config = apply_detected_mode(config, samples, vendor_hint)
        report = validator.validate(config, samples, check_backtracking=check_backtracking)
        last_report = report
        last_config = config if isinstance(config, dict) else None
        if report.ok:
            break
        previous_attempt = config if isinstance(config, dict) else {"_non_object": str(config)[:500]}
        previous_errors = report.error_summary()
        unmapped = list(report.unmapped_required)

    if isinstance(last_config, dict):
        structure.attach_route(last_config, samples)

    return GenerationResult(
        config=last_config,
        report=last_report,
        attempts=attempt + 1,
        seconds=round(time.monotonic() - start, 3),
        raw_responses=raw_responses,
    )
