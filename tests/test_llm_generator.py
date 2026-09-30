from __future__ import annotations

import json

from ulpf.llm import generator

VALID_JSON = json.dumps(
    {
        "vendor": "Acme",
        "product": "NetGuard",
        "format_hint": "kv",
        "line_regex": r"^src=(?P<src_ip>\S+) dst=(?P<dst_ip>\S+) act=(?P<action>\S+)$",
        "field_map": {
            "network.src_ip": "src_ip",
            "network.dst_ip": "dst_ip",
            "event.action": "action",
        },
        "action_rules": [{"match": "deny", "action": "deny"}],
        "timestamp_format": "none",
        "category": "network",
    }
)

LOW_MATCH_JSON = json.dumps(
    {
        "vendor": "Acme",
        "product": "NetGuard",
        "format_hint": "kv",
        "line_regex": r"^this-never-matches$",
        "field_map": {"network.src_ip": "src_ip"},
        "action_rules": [],
        "timestamp_format": "none",
        "category": "network",
    }
)

BAD_REGEX_JSON = json.dumps(
    {
        "vendor": "Acme",
        "product": "NetGuard",
        "format_hint": "kv",
        "line_regex": r"^src=(?P<src_ip>\S+",  # unbalanced -> compile error
        "field_map": {"network.src_ip": "src_ip"},
        "action_rules": [],
        "timestamp_format": "none",
        "category": "network",
    }
)

SAMPLES = [
    "src=10.1.1.1 dst=10.1.1.2 act=deny",
    "src=10.1.1.3 dst=10.1.1.4 act=allow",
    "src=10.1.1.5 dst=10.1.1.6 act=deny",
]


class _ScriptedClient:
    """Returns each entry of `responses` in order, one per `.generate()` call."""

    def __init__(self, responses: list[str], model: str = "qwen2.5-coder:3b") -> None:
        self.responses = list(responses)
        self.model = model
        self.prompts: list[str] = []

    def generate(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.responses.pop(0)


def test_valid_config_on_first_try_needs_no_retry() -> None:
    client = _ScriptedClient([VALID_JSON])
    result = generator.generate_config(client, SAMPLES, check_backtracking=False)

    assert result.attempts == 1
    assert result.report.ok is True
    assert result.config["vendor"] == "Acme"
    assert len(client.prompts) == 1


def test_bad_regex_then_good_triggers_exactly_one_retry() -> None:
    client = _ScriptedClient([BAD_REGEX_JSON, VALID_JSON])
    result = generator.generate_config(client, SAMPLES, check_backtracking=False)

    assert result.attempts == 2
    assert result.report.ok is True
    assert len(client.prompts) == 2
    # The retry prompt must feed the previous failure back in.
    assert "regex" in client.prompts[1].lower() or "compile" in client.prompts[1].lower()
    assert "Your previous attempt was" in client.prompts[1]


def test_low_match_rate_triggers_retry() -> None:
    client = _ScriptedClient([LOW_MATCH_JSON, VALID_JSON])
    result = generator.generate_config(client, SAMPLES, check_backtracking=False)

    assert result.attempts == 2
    assert result.report.ok is True
    assert "80%" in client.prompts[1] or "match" in client.prompts[1].lower()


def test_always_bad_exhausts_all_retries_and_returns_last_attempt() -> None:
    client = _ScriptedClient([BAD_REGEX_JSON, LOW_MATCH_JSON, LOW_MATCH_JSON])
    result = generator.generate_config(client, SAMPLES, max_retries=2, check_backtracking=False)

    assert result.attempts == 3
    assert result.report.ok is False
    assert result.config is not None  # still returns the last attempt, not None
    assert len(client.prompts) == 3


def test_non_json_response_is_treated_as_a_failed_attempt_and_retried() -> None:
    client = _ScriptedClient(["not json at all", VALID_JSON])
    result = generator.generate_config(client, SAMPLES, check_backtracking=False)

    assert result.attempts == 2
    assert result.report.ok is True


def test_markdown_fenced_json_response_is_extracted() -> None:
    fenced = "```json\n" + VALID_JSON + "\n```"
    client = _ScriptedClient([fenced])
    result = generator.generate_config(client, SAMPLES, check_backtracking=False)

    assert result.attempts == 1
    assert result.report.ok is True


def test_records_elapsed_seconds() -> None:
    client = _ScriptedClient([VALID_JSON])
    result = generator.generate_config(client, SAMPLES, check_backtracking=False)
    assert result.seconds >= 0.0


def test_vendor_hint_is_included_in_prompt() -> None:
    client = _ScriptedClient([VALID_JSON])
    generator.generate_config(client, SAMPLES, vendor_hint="SuperFirewall 9000", check_backtracking=False)
    assert "SuperFirewall 9000" in client.prompts[0]


# ---------------------------------------------------------------------------
# Few-shot example selection (item 12: one example unless model is 7b+).
# ---------------------------------------------------------------------------


def test_small_model_gets_only_one_few_shot_example() -> None:
    prompt = generator.build_prompt(SAMPLES, None, "qwen2.5-coder:3b")
    assert prompt.count("mapping_version:") == 1


def test_large_model_gets_two_few_shot_examples() -> None:
    prompt = generator.build_prompt(SAMPLES, None, "qwen2.5-coder:7b")
    assert prompt.count("mapping_version:") == 2


def test_prompt_includes_schema_and_samples() -> None:
    prompt = generator.build_prompt(SAMPLES, None, "qwen2.5-coder:3b")
    assert "line_regex" in prompt
    assert "field_map" in prompt
    for line in SAMPLES:
        assert line in prompt
