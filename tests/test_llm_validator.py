from __future__ import annotations

from ulpf.llm import validator

VALID_CONFIG = {
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

SAMPLES = [
    "src=10.1.1.1 dst=10.1.1.2 act=deny",
    "src=10.1.1.3 dst=10.1.1.4 act=allow",
    "src=10.1.1.5 dst=10.1.1.6 act=deny",
]


def test_valid_config_passes() -> None:
    report = validator.validate(VALID_CONFIG, SAMPLES)
    assert report.ok is True
    assert report.schema_errors == []
    assert report.regex_error is None
    assert report.catastrophic_backtracking is False
    assert report.match_rate == 1.0
    assert report.required_field_rate == 1.0
    assert report.score > 0.9
    assert len(report.per_line) == 3
    assert all(r.matched for r in report.per_line)


def test_missing_required_key_fails_schema() -> None:
    bad = dict(VALID_CONFIG)
    del bad["line_regex"]
    report = validator.validate(bad, SAMPLES)
    assert report.ok is False
    assert any("line_regex" in e for e in report.schema_errors)


def test_wrong_type_fails_schema() -> None:
    bad = dict(VALID_CONFIG)
    bad["field_map"] = "not a dict"
    report = validator.validate(bad, SAMPLES)
    assert report.ok is False
    assert any("field_map" in e for e in report.schema_errors)


def test_invalid_format_hint_fails_schema() -> None:
    bad = dict(VALID_CONFIG)
    bad["format_hint"] = "xml"
    report = validator.validate(bad, SAMPLES)
    assert report.ok is False
    assert any("format_hint" in e for e in report.schema_errors)


def test_unknown_field_map_target_fails_schema() -> None:
    bad = dict(VALID_CONFIG)
    bad["field_map"] = {"totally.bogus.field": "src_ip"}
    report = validator.validate(bad, SAMPLES)
    assert report.ok is False
    assert any("totally.bogus.field" in e for e in report.schema_errors)


def test_code_marker_in_string_value_is_rejected() -> None:
    bad = dict(VALID_CONFIG)
    bad["timestamp_format"] = "import os; os.system('rm -rf /')"
    report = validator.validate(bad, SAMPLES)
    assert report.ok is False
    assert any("code" in e for e in report.schema_errors)


def test_config_must_be_an_object() -> None:
    report = validator.validate(["not", "an", "object"], SAMPLES)
    assert report.ok is False
    assert report.schema_errors


def test_regex_does_not_compile() -> None:
    bad = dict(VALID_CONFIG)
    bad["line_regex"] = r"^src=(?P<src_ip>\S+"  # unbalanced group
    report = validator.validate(bad, SAMPLES)
    assert report.ok is False
    assert report.regex_error is not None


def test_low_match_rate_fails() -> None:
    bad = dict(VALID_CONFIG)
    bad["line_regex"] = r"^this-will-never-match-anything-here$"
    report = validator.validate(bad, SAMPLES)
    assert report.ok is False
    assert report.match_rate == 0.0


def test_required_fields_missing_from_field_map_lowers_required_field_rate() -> None:
    # Regex matches fine, but the field_map only wires up src_ip - dst_ip and
    # action, both plainly present in every sample line, are never captured
    # into an internal field even though they *are* named groups.
    partial = dict(VALID_CONFIG)
    partial["field_map"] = {"network.src_ip": "src_ip"}
    report = validator.validate(partial, SAMPLES)
    assert report.match_rate == 1.0
    assert report.required_field_rate < 1.0
    assert any(r.missing_required for r in report.per_line)


def test_catastrophic_backtracking_is_flagged() -> None:
    bad = dict(VALID_CONFIG)
    bad["line_regex"] = r"^(?P<x>a+)+$"
    report = validator.validate(bad, ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"])
    assert report.ok is False
    assert report.catastrophic_backtracking is True
    assert report.score == 0.0


def test_safe_regex_is_not_flagged_as_catastrophic() -> None:
    report = validator.validate(VALID_CONFIG, SAMPLES, check_backtracking=True)
    assert report.catastrophic_backtracking is False


def test_check_backtracking_false_skips_the_guard() -> None:
    bad = dict(VALID_CONFIG)
    bad["line_regex"] = r"^(?P<x>a+)+$"
    # With the guard off, this can't be flagged as catastrophic (it will
    # instead just fail to match the kv-shaped samples -> low match rate).
    report = validator.validate(bad, SAMPLES, check_backtracking=False)
    assert report.catastrophic_backtracking is False


def test_error_summary_is_nonempty_when_not_ok() -> None:
    bad = dict(VALID_CONFIG)
    bad["line_regex"] = r"^nope$"
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

    bad = dict(VALID_CONFIG)
    bad["line_regex"] = "("
    report = validator.validate_schema_only(bad)
    assert report.ok is False
    assert report.regex_error is not None
