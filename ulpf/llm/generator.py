"""Builds the few-shot prompt and runs the generate -> validate -> retry loop.

The model never sees or writes Python code: the prompt asks for exactly one
JSON object matching the schema in `ulpf.llm.validator`, and every attempt
is checked with `validator.validate` before being accepted. Up to
`max_retries` retries feed the previous attempt and its validator error
summary back into the prompt, so the model can self-correct.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from ulpf.llm import validator

PACKAGE_DIR = Path(__file__).resolve().parent.parent  # .../ulpf
MAPPINGS_DIR = PACKAGE_DIR / "mappings"

# Two real, hand-written mappings covering the two most common line shapes
# (key=value, syslog-with-header) - used as style/structure context only;
# the model's *output* schema (below) is deliberately different and
# stricter. Read from disk (not hardcoded) so the examples never drift out
# of sync with the actual files.
FEW_SHOT_KV_STYLE = "fortigate.yaml"
FEW_SHOT_SYSLOG_STYLE = "cisco_asa.yaml"

_LARGE_MODEL_TAGS = ("7b", "8b", "13b", "14b", "22b", "32b", "34b", "70b")


class LLMClient(Protocol):
    def generate(self, prompt: str) -> str: ...


@dataclass
class GenerationResult:
    config: dict[str, Any] | None
    report: validator.ValidationReport
    attempts: int
    seconds: float
    raw_responses: list[str] = field(default_factory=list)


def _model_is_large(model: str) -> bool:
    lowered = model.lower()
    return any(tag in lowered for tag in _LARGE_MODEL_TAGS)


def _load_example(name: str) -> str:
    return (MAPPINGS_DIR / name).read_text(encoding="utf-8").strip()


def _schema_block() -> str:
    formats = ", ".join(sorted(validator.REQUIRED_FORMAT_HINTS))
    fields = ", ".join(sorted(validator.ALLOWED_FIELD_MAP_TARGETS))
    return (
        "Output ONLY one JSON object - no prose, no markdown fences, no code - "
        "with exactly these keys:\n"
        "{\n"
        '  "vendor": "<short vendor name>",\n'
        '  "product": "<short product name>",\n'
        f'  "format_hint": "<one of: {formats}>",\n'
        '  "line_regex": "<a Python re pattern with named groups, applied with re.match>",\n'
        '  "field_map": {"<internal field>": "<regex group name>"},\n'
        '  "action_rules": [{"match": "<raw captured action value>", "action": "<canonical action>"}],\n'
        '  "timestamp_format": "<free-text description of the captured timestamp shape>",\n'
        '  "category": "<network or authentication>"\n'
        "}\n"
        f"Valid field_map keys (the ONLY strings allowed on the left): {fields}.\n"
        "field_map direction: KEY is one of those internal field names, VALUE is "
        "your regex group name - e.g. if your regex has (?P<ip1>...), and that "
        "group is the source IP, write \"network.src_ip\": \"ip1\". This is the "
        "OPPOSITE direction from the example mapping's \"fields:\" section above "
        "(which maps raw-log-key -> internal-field) - do not reuse its left-hand "
        "key names (like \"srcip\") as field_map keys; only the internal field "
        "names listed above are valid there.\n"
        "line_regex must match from the start of the line and use a named "
        "group (?P<name>...) for every piece of data you extract."
    )


def build_prompt(
    samples: list[str],
    vendor_hint: str | None,
    model: str,
    previous_attempt: dict[str, Any] | None = None,
    previous_errors: str | None = None,
) -> str:
    """Assemble the prompt: few-shot example(s) + target schema + samples.

    Item 12: keep this under ~1500 tokens and use only ONE few-shot example
    unless the model is 7b+ - a single real mapping (~15-25 lines of YAML)
    plus the schema plus up to 10 sample lines comfortably fits that budget;
    a second example roughly doubles the example-YAML portion, which is
    still fine for a larger model's context but wasted on a 3b one.
    """
    example_names = [FEW_SHOT_KV_STYLE]
    if _model_is_large(model):
        example_names.append(FEW_SHOT_SYSLOG_STYLE)
    example_blocks = [
        f"# Existing hand-written mapping ({name}) - for style/context only, "
        f"your output schema is different (given below):\n{_load_example(name)}"
        for name in example_names
    ]

    sample_block = "\n".join(f"  {i + 1}. {line}" for i, line in enumerate(samples))
    vendor_line = f"The user says this vendor/product is: {vendor_hint}\n" if vendor_hint else ""

    parts = [
        "You are configuring a log parser for ULPF, an offline log pre-processing tool.",
        "\n\n".join(example_blocks),
        _schema_block(),
        vendor_line + "Sample log lines from an unrecognized source:\n" + sample_block,
        "Respond with only the JSON object described above.",
    ]

    if previous_attempt is not None:
        parts.append(
            "Your previous attempt was:\n"
            + json.dumps(previous_attempt, ensure_ascii=False)
            + "\nIt failed validation: "
            + (previous_errors or "unknown error")
            + "\nFix it and respond with only the corrected JSON object."
        )

    return "\n\n".join(parts)


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
    nothing back.
    """
    start = time.monotonic()
    model = getattr(client, "model", "unknown")
    previous_attempt: dict[str, Any] | None = None
    previous_errors: str | None = None
    raw_responses: list[str] = []
    last_report = validator.ValidationReport(ok=False, score=0.0, schema_errors=["no attempt made"])
    last_config: dict[str, Any] | None = None
    attempt = 0

    for attempt in range(max_retries + 1):
        prompt = build_prompt(samples, vendor_hint, model, previous_attempt, previous_errors)
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
            continue

        report = validator.validate(config, samples, check_backtracking=check_backtracking)
        last_report = report
        last_config = config
        if report.ok:
            break
        previous_attempt = config
        previous_errors = report.error_summary()

    return GenerationResult(
        config=last_config,
        report=last_report,
        attempts=attempt + 1,
        seconds=round(time.monotonic() - start, 3),
        raw_responses=raw_responses,
    )
