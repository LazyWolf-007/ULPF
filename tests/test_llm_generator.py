from __future__ import annotations

import json

from ulpf.llm import generator

VALID_JSON = json.dumps(
    {
        "vendor": "Acme",
        "product": "NetGuard",
        "mode": "kv",
        "field_map": {
            "network.src_ip": "src",
            "network.dst_ip": "dst",
            "event.action": "act",
        },
        "action_rules": [{"match_value": "deny", "action": "deny"}],
        "timestamp": {"keys": [], "format": ""},
        "category": "network",
    }
)

LOW_MATCH_JSON = json.dumps(
    {
        "vendor": "Acme",
        "product": "NetGuard",
        "mode": "json",
        "field_map": {"network.src_ip": "src"},
        "action_rules": [],
        "timestamp": {"keys": [], "format": ""},
        "category": "network",
    }
)

UNSTRUCTURED = [
    "connection denied from alpha to beta",
    "connection allowed from gamma to delta",
    "connection denied from epsilon to zeta",
]

GOOD_REGEX_JSON = json.dumps(
    {
        "vendor": "Acme",
        "product": "NetGuard",
        "mode": "regex",
        "line_regex": r"^connection (?P<action>\w+) from \S+ to \S+$",
        "field_map": {"event.action": "action"},
        "action_rules": [],
        "timestamp": {"keys": [], "format": ""},
        "category": "network",
    }
)

BAD_REGEX_JSON = json.dumps(
    {
        "vendor": "Acme",
        "product": "NetGuard",
        "mode": "regex",
        "line_regex": r"^connection (?P<action>\w+",  # unbalanced -> compile error
        "field_map": {"event.action": "action"},
        "action_rules": [],
        "timestamp": {"keys": [], "format": ""},
        "category": "network",
    }
)

UNKNOWN_KEY_JSON = json.dumps(
    {
        "vendor": "Acme",
        "product": "NetGuard",
        "mode": "kv",
        "field_map": {
            "network.src_ip": "src",
            "network.dst_ip": "not_a_real_key",
            "event.action": "act",
        },
        "action_rules": [],
        "timestamp": {"keys": [], "format": ""},
        "category": "network",
    }
)

PARTIAL_MAP_JSON = json.dumps(
    {
        "vendor": "Acme",
        "product": "NetGuard",
        "mode": "kv",
        "field_map": {"network.src_ip": "src"},
        "action_rules": [],
        "timestamp": {"keys": [], "format": ""},
        "category": "network",
    }
)

SOPHOS_LINES = [
    'device_name="SFW" timestamp="2026-10-04 12:00:00" src_ip="10.1.1.1" dst_ip="10.2.2.2" '
    'protocol="TCP" status="Deny" msg="hello world"',
    'device_name="SFW" timestamp="2026-10-04 12:00:01" src_ip="10.1.1.8" dst_ip="10.2.2.9" '
    'protocol="TCP" status="Allow" msg="hello there"',
    'device_name="SFW" timestamp="2026-10-04 12:00:02" src_ip="10.9.9.9" dst_ip="10.8.8.8" '
    'protocol="UDP" status="Deny" msg="third message"',
]

SOPHOS_JSON = json.dumps(
    {
        "vendor": "Sophos",
        "product": "XG",
        "mode": "kv",
        "field_map": {
            "network.src_ip": "src_ip",
            "network.dst_ip": "dst_ip",
            "network.transport": "protocol",
            "event.action": "status",
            "event.description": "msg",
        },
        "action_rules": [{"match_value": "Deny", "action": "deny"}],
        "timestamp": {"keys": ["timestamp"], "format": "YYYY-MM-DD HH:MM:SS"},
        "category": "network",
    }
)

JUNIPER_LINES = [
    '<14>Oct  4 12:00:01 srx1 RT_FLOW: RT_FLOW_SESSION_DENY: source-address="10.1.1.1" '
    'source-port="111" destination-address="10.2.2.2" destination-port="443" protocol="tcp" action="deny"',
    '<14>Oct  4 12:00:02 srx1 RT_FLOW: RT_FLOW_SESSION_CREATE: source-address="10.1.1.8" '
    'source-port="222" destination-address="10.2.2.9" destination-port="80" protocol="tcp" action="allow"',
    '<14>Oct  4 12:00:03 srx1 RT_FLOW: RT_FLOW_SESSION_DENY: source-address="10.9.9.9" '
    'source-port="333" destination-address="10.8.8.8" destination-port="53" protocol="udp" action="deny"',
]

JUNIPER_JSON = json.dumps(
    {
        "vendor": "Juniper",
        "product": "SRX",
        "mode": "syslog_kv",
        "field_map": {
            "network.src_ip": "source-address",
            "network.dst_ip": "destination-address",
            "network.src_port": "source-port",
            "network.dst_port": "destination-port",
            "network.transport": "protocol",
            "event.action": "action",
        },
        "action_rules": [{"match_value": "deny", "action": "deny"}],
        "timestamp": {"keys": ["syslog_timestamp"], "format": "Mmm dd HH:MM:SS"},
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
    assert result.config["mode"] == "kv"
    assert result.config["format_hint"] == "kv"
    assert "line_regex" not in result.config
    assert len(client.prompts) == 1


def test_bad_regex_then_good_triggers_exactly_one_retry() -> None:
    client = _ScriptedClient([BAD_REGEX_JSON, GOOD_REGEX_JSON])
    result = generator.generate_config(client, UNSTRUCTURED, check_backtracking=False)

    assert result.attempts == 2
    assert result.report.ok is True
    assert len(client.prompts) == 2
    # The retry prompt must feed the previous failure back in.
    assert "does not compile" in client.prompts[1] or "compile" in client.prompts[1].lower()
    assert "Your previous attempt was" in client.prompts[1]


def test_low_match_rate_triggers_retry() -> None:
    client = _ScriptedClient([LOW_MATCH_JSON, VALID_JSON])
    result = generator.generate_config(client, SAMPLES, check_backtracking=False)

    assert result.attempts == 2
    assert result.report.ok is True
    assert "80%" in client.prompts[1] or "match" in client.prompts[1].lower()


def test_always_bad_exhausts_all_retries_and_returns_last_attempt() -> None:
    client = _ScriptedClient([LOW_MATCH_JSON, LOW_MATCH_JSON, LOW_MATCH_JSON])
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


def test_small_model_gets_only_one_few_shot_example() -> None:
    # Few-shot YAML mappings are gone: they blew the token budget and taught
    # the model the wrong field_map direction. A 3b model gets keys only.
    prompt = generator.build_prompt(SAMPLES, None, "qwen2.5-coder:3b")
    assert prompt.count("mapping_version:") == 0
    assert generator.estimate_tokens(prompt) <= generator.PROMPT_TOKEN_BUDGET


def test_large_model_gets_two_few_shot_examples() -> None:
    # Model size no longer adds a second example. Both stay under the budget.
    small = generator.build_prompt(SAMPLES, None, "qwen2.5-coder:3b")
    large = generator.build_prompt(SAMPLES, None, "qwen2.5-coder:7b")
    assert small == large
    assert large.count("mapping_version:") == 0
    assert generator.estimate_tokens(large) <= generator.PROMPT_TOKEN_BUDGET


def test_prompt_includes_schema_and_samples() -> None:
    prompt = generator.build_prompt(SAMPLES, None, "qwen2.5-coder:3b")
    assert "field_map" in prompt
    assert "line_regex" not in prompt
    assert "src: 10.1.1.1 | 10.1.1.3" in prompt
    assert "10.1.1.5" not in prompt
    for line in SAMPLES:
        assert line not in prompt
    assert generator.estimate_tokens(prompt) <= generator.PROMPT_TOKEN_BUDGET


def test_regex_prompt_shows_lines_and_group_limit() -> None:
    prompt = generator.build_prompt(UNSTRUCTURED, None, "qwen2.5-coder:3b")
    assert "line_regex" in prompt
    assert "6" in prompt
    assert UNSTRUCTURED[0] in prompt


def test_quoted_kv_prompt_uses_keys_and_accepts_the_map() -> None:
    client = _ScriptedClient([SOPHOS_JSON])
    result = generator.generate_config(client, SOPHOS_LINES, check_backtracking=False)

    assert result.attempts == 1
    assert result.report.ok is True
    assert result.config["mode"] == "kv"
    prompt = client.prompts[0]
    assert "src_ip: 10.1.1.1 | 10.1.1.8" in prompt
    assert "10.9.9.9" not in prompt
    assert 'msg="hello world"' not in prompt
    assert "hello world" in prompt
    assert "line_regex" not in prompt
    assert generator.estimate_tokens(prompt) <= generator.PROMPT_TOKEN_BUDGET
    assert result.report.per_line[0].extracted["event.description"] == "hello world"


def test_syslog_kv_juniper_prompt_and_validation() -> None:
    client = _ScriptedClient([JUNIPER_JSON])
    result = generator.generate_config(client, JUNIPER_LINES, check_backtracking=False)

    assert result.attempts == 1
    assert result.report.ok is True
    assert result.config["mode"] == "syslog_kv"
    assert result.config["format_hint"] == "syslog"
    prompt = client.prompts[0]
    assert 'Detected mode: syslog_kv' in prompt
    assert "source-address: 10.1.1.1 | 10.1.1.8" in prompt
    assert "10.9.9.9" not in prompt
    assert "RT_FLOW_SESSION_DENY" not in prompt
    assert "line_regex" not in prompt
    assert generator.estimate_tokens(prompt) <= generator.PROMPT_TOKEN_BUDGET
    assert result.report.per_line[0].extracted["network.src_ip"] == "10.1.1.1"
    assert result.report.per_line[0].extracted["timestamp"].startswith("Oct")


def test_unknown_source_key_is_fed_back_on_retry() -> None:
    client = _ScriptedClient([UNKNOWN_KEY_JSON, VALID_JSON])
    result = generator.generate_config(client, SAMPLES, check_backtracking=False)

    assert result.attempts == 2
    assert result.report.ok is True
    assert "not_a_real_key" not in client.prompts[0]
    assert "not_a_real_key" in client.prompts[1]
    assert "Your previous attempt was" in client.prompts[1]


def test_unmapped_required_fields_are_fed_back_on_retry() -> None:
    client = _ScriptedClient([PARTIAL_MAP_JSON, VALID_JSON])
    result = generator.generate_config(client, SAMPLES, check_backtracking=False)

    assert result.attempts == 2
    assert result.report.ok is True
    assert "Unmapped required fields:" in client.prompts[1]
    feedback = client.prompts[1].split("Unmapped required fields: ", 1)[1].split("\n", 1)[0]
    assert "network.dst_ip" in feedback
    assert "event.action" in feedback


RT_FLOW_LINE = (
    "<14>Sep  3 09:01:03 edge-test RT_FLOW: RT_FLOW_SESSION_DENY: "
    "session denied 10.7.7.7/2000->10.8.8.8/22 junos-ssh 6(0) "
    "untrust-to-trust untrust trust NO_POLICY 6"
)

# The model still tries to hand back a regex. Detection has already chosen
# rt_flow, so the regex is discarded and the field_map is what gets scored.
RT_FLOW_REGEX_REPLY = json.dumps(
    {
        "vendor": "Juniper",
        "product": "SRX",
        "mode": "regex",
        "line_regex": r"^(?P<src_ip>\S+)$",
        "field_map": {
            "network.src_ip": "src_ip",
            "network.dst_ip": "dst_ip",
            "network.src_port": "src_port",
            "network.dst_port": "dst_port",
            "event.action": "event",
            "observer.name": "host",
        },
        "action_rules": [{"match_value": "RT_FLOW_SESSION_DENY", "action": "deny"}],
        "timestamp": {"format": "Mmm dd HH:MM:SS"},
    }
)


def test_rt_flow_reply_with_line_regex_still_passes() -> None:
    client = _ScriptedClient([RT_FLOW_REGEX_REPLY])
    result = generator.generate_config(client, [RT_FLOW_LINE], check_backtracking=False)

    assert result.attempts == 1
    assert result.report.ok is True
    assert result.report.score == 1.0
    assert result.config["mode"] == "rt_flow"
    assert result.config["category"] == "network"
    assert result.config["format_hint"] == "syslog"
    assert "line_regex" not in result.config
    assert result.config["timestamp"]["keys"] == ["timestamp"]
    assert result.report.per_line[0].extracted["network.src_ip"] == "10.7.7.7"
    assert result.report.per_line[0].extracted["event.action"] == "RT_FLOW_SESSION_DENY"
    assert result.report.per_line[0].extracted["timestamp"] == "Sep  3 09:01:03"
    prompt = client.prompts[0]
    assert "Detected mode: rt_flow" in prompt
    assert "line_regex" not in prompt
    assert RT_FLOW_LINE not in prompt
    assert "src_ip: 10.7.7.7" in prompt
    assert generator.estimate_tokens(prompt) <= generator.PROMPT_TOKEN_BUDGET
