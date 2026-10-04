from __future__ import annotations

from ulpf.llm import validator

SAMPLES = [
    "src=10.1.1.1 dst=10.1.1.2 act=deny",
    "src=10.1.1.3 dst=10.1.1.4 act=allow",
    "src=10.1.1.5 dst=10.1.1.6 act=deny",
]

UNSTRUCTURED = [
    "connection denied from alpha to beta",
    "connection allowed from gamma to delta",
    "connection denied from epsilon to zeta",
]

SOPHOS_SAMPLES = [
    'device_name="SFW" timestamp="2026-10-04 12:00:00" src_ip="10.1.1.1" dst_ip="10.2.2.2" '
    'protocol="TCP" status="Deny" msg="hello world"',
    'device_name="SFW" timestamp="2026-10-04 12:00:01" src_ip="10.1.1.8" dst_ip="10.2.2.9" '
    'protocol="TCP" status="Allow" msg="hello there"',
]


def _config(**overrides: object) -> dict:
    config: dict = {
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
    config.update(overrides)
    return config


def _regex_config(**overrides: object) -> dict:
    config: dict = {
        "vendor": "Acme",
        "product": "NetGuard",
        "mode": "regex",
        "line_regex": r"^connection (?P<action>\w+) from \S+ to \S+$",
        "field_map": {"event.action": "action"},
        "action_rules": [{"match_value": "denied", "action": "deny"}],
        "timestamp": {"keys": [], "format": ""},
        "category": "network",
    }
    config.update(overrides)
    return config


VALID_CONFIG = _config()


def test_valid_config_passes() -> None:
    report = validator.validate(VALID_CONFIG, SAMPLES)
    assert report.ok is True
    assert report.schema_errors == []
    assert report.regex_error is None
    assert report.catastrophic_backtracking is False
    assert report.match_rate == 1.0
    assert report.required_field_rate == 1.0
    assert report.score > 0.9
    assert report.unmapped_required == []
    assert len(report.per_line) == 3
    assert all(row.matched for row in report.per_line)


def test_missing_required_key_fails_schema() -> None:
    bad = dict(VALID_CONFIG)
    del bad["mode"]
    report = validator.validate(bad, SAMPLES)
    assert report.ok is False
    assert any("mode" in error for error in report.schema_errors)


def test_wrong_type_fails_schema() -> None:
    bad = dict(VALID_CONFIG)
    bad["field_map"] = "not a dict"
    report = validator.validate(bad, SAMPLES)
    assert report.ok is False
    assert any("field_map" in error for error in report.schema_errors)


def test_invalid_format_hint_fails_schema() -> None:
    bad = dict(VALID_CONFIG)
    bad["mode"] = "xml"
    report = validator.validate(bad, SAMPLES)
    assert report.ok is False
    assert any("mode" in error for error in report.schema_errors)


def test_unknown_field_map_target_fails_schema() -> None:
    bad = dict(VALID_CONFIG)
    bad["field_map"] = {"totally.bogus.field": "src"}
    report = validator.validate(bad, SAMPLES)
    assert report.ok is False
    assert any("totally.bogus.field" in error for error in report.schema_errors)


def test_unknown_source_key_fails_and_names_unmapped_fields() -> None:
    bad = _config(
        field_map={
            "network.src_ip": "src",
            "network.dst_ip": "not_a_real_key",
            "event.action": "act",
        }
    )
    report = validator.validate(bad, SAMPLES)
    assert report.ok is False
    assert any("not_a_real_key" in error for error in report.schema_errors)
    assert "network.dst_ip" in report.unmapped_required


def test_code_marker_in_string_value_is_rejected() -> None:
    bad = dict(VALID_CONFIG)
    bad["timestamp"] = {"keys": [], "format": "import os; os.system('rm -rf /')"}
    report = validator.validate(bad, SAMPLES)
    assert report.ok is False
    assert any("code" in error for error in report.schema_errors)


def test_config_must_be_an_object() -> None:
    report = validator.validate(["not", "an", "object"], SAMPLES)
    assert report.ok is False
    assert report.schema_errors


def test_structured_mode_rejects_line_regex() -> None:
    bad = dict(VALID_CONFIG)
    bad["line_regex"] = r"^(?P<x>a+)+$"
    report = validator.validate(bad, SAMPLES, check_backtracking=True)
    assert report.ok is False
    assert report.catastrophic_backtracking is False
    assert any("line_regex" in error for error in report.schema_errors)


def test_regex_mode_rejected_for_structured_samples() -> None:
    report = validator.validate(_regex_config(), SAMPLES)
    assert report.ok is False
    assert any("not allowed" in error for error in report.schema_errors)


def test_regex_does_not_compile() -> None:
    bad = _regex_config(line_regex=r"^connection (?P<action>\w+")
    report = validator.validate(bad, UNSTRUCTURED)
    assert report.ok is False
    assert report.regex_error is not None


def test_regex_mode_rejects_more_than_six_capture_groups() -> None:
    pattern = r"^(?P<a>.)(?P<b>.)(?P<c>.)(?P<d>.)(?P<e>.)(?P<f>.)(?P<g>.)$"
    report = validator.validate_schema_only(
        _regex_config(line_regex=pattern, field_map={"event.action": "a"})
    )
    assert report.ok is False
    assert any(str(validator.structure.MAX_CAPTURE_GROUPS) in error for error in report.schema_errors)


def test_regex_mode_allows_six_capture_groups() -> None:
    pattern = r"^(?P<a>.)(?P<b>.)(?P<c>.)(?P<d>.)(?P<e>.)(?P<f>.)$"
    report = validator.validate_schema_only(
        _regex_config(line_regex=pattern, field_map={"event.action": "a"})
    )
    assert report.ok is True
    assert report.catastrophic_backtracking is False


def test_low_match_rate_fails() -> None:
    bad = _config(mode="json")
    report = validator.validate(bad, SAMPLES)
    assert report.ok is False
    assert report.match_rate == 0.0


def test_required_fields_missing_from_field_map_lowers_required_field_rate() -> None:
    # Tokenizer sees every key, but field_map only wires src. dst and action
    # are plainly present and stay unmapped, which fails the coverage bar.
    partial = _config(field_map={"network.src_ip": "src"})
    report = validator.validate(partial, SAMPLES)
    assert report.ok is False
    assert report.match_rate == 1.0
    assert report.required_field_rate < 1.0
    assert any(row.missing_required for row in report.per_line)
    assert "network.dst_ip" in report.unmapped_required
    assert "event.action" in report.unmapped_required


def test_quoted_kv_values_cover_required_fields() -> None:
    config = _config(
        field_map={
            "network.src_ip": "src_ip",
            "network.dst_ip": "dst_ip",
            "event.action": "status",
            "event.description": "msg",
        },
        timestamp={"keys": ["timestamp"], "format": "YYYY-MM-DD HH:MM:SS"},
    )
    report = validator.validate(config, SOPHOS_SAMPLES)
    assert report.ok is True
    assert report.match_rate == 1.0
    assert report.per_line[0].extracted["event.description"] == "hello world"
    assert report.per_line[0].extracted["network.src_ip"] == "10.1.1.1"


def test_catastrophic_backtracking_is_flagged() -> None:
    bad = _regex_config(line_regex=r"^(?P<x>a+)+$", field_map={"event.description": "x"})
    report = validator.validate(bad, ["a" * 30 + "!"])
    assert report.ok is False
    assert report.catastrophic_backtracking is True
    assert report.score == 0.0


def test_safe_regex_is_not_flagged_as_catastrophic() -> None:
    report = validator.validate(_regex_config(), UNSTRUCTURED, check_backtracking=True)
    assert report.ok is True
    assert report.catastrophic_backtracking is False


def test_check_backtracking_false_skips_the_guard() -> None:
    bad = _regex_config(line_regex=r"^(?P<x>a+)+$", field_map={})
    # Guard off, and the samples are not the stress string, so this must
    # return quickly and must not be flagged as catastrophic.
    report = validator.validate(bad, UNSTRUCTURED, check_backtracking=False)
    assert report.catastrophic_backtracking is False


def test_error_summary_is_nonempty_when_not_ok() -> None:
    bad = _config(mode="json")
    report = validator.validate(bad, SAMPLES)
    assert report.error_summary() != "no errors"


def test_error_summary_reports_no_errors_when_ok() -> None:
    report = validator.validate(VALID_CONFIG, SAMPLES)
    assert report.error_summary() == "no errors"


def test_to_dict_is_json_serializable() -> None:
    import json

    report = validator.validate(VALID_CONFIG, SAMPLES)
    json.dumps(report.to_dict())  # must not raise


def test_validate_schema_only_checks_schema_and_regex_without_samples() -> None:
    report = validator.validate_schema_only(VALID_CONFIG)
    assert report.ok is True

    bad = _regex_config(line_regex="(")
    report = validator.validate_schema_only(bad)
    assert report.ok is False
    assert report.regex_error is not None
