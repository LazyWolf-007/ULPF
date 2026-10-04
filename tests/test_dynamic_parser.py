from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from ulpf import detect as detect_mod
from ulpf.parsers import dynamic
from ulpf.pipeline import run

ROOT = Path(__file__).resolve().parents[1]
MAPPINGS_DIR = ROOT / "ulpf" / "mappings"

# Deliberately unique tokens that cannot collide with anything in samples/
# or in any hand-written parser's claim keys (src=/dst=/action=/srcip=/...)
# - this test writes into the *real* ulpf/mappings/ directory (that's where
# ulpf/parsers/dynamic.py actually looks), so safety here means: (a) an
# isolated `detect._REGISTRY` per test via monkeypatch, so nothing leaks
# into other tests even if cleanup below were somehow skipped, and (b) a
# regex/sample shape that cannot accidentally match real fixture data even
# without that isolation.
TEST_LINE = "ZZDEVICE9827: zzsrc=10.55.55.55 zzdst=10.66.66.66 zzact=allow zzproto=tcp"

DYNAMIC_CONFIG = {
    "vendor": "ZZTestVendor",
    "product": "ZZBox",
    "format_hint": "kv",
    "line_regex": (
        r"^ZZDEVICE9827: zzsrc=(?P<src_ip>\S+) zzdst=(?P<dst_ip>\S+) "
        r"zzact=(?P<action>\S+) zzproto=(?P<proto>\S+)$"
    ),
    "field_map": {
        "network.src_ip": "src_ip",
        "network.dst_ip": "dst_ip",
        "event.action": "action",
        "network.transport": "proto",
    },
    "action_rules": [{"match": "allow", "action": "allow"}],
    "timestamp_format": "none",
    "category": "network",
    "generator": "ulpf.llm",
}


@pytest.fixture
def isolated_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Give this test its own empty parser registry and dynamic-parser
    cache, so anything it registers can never leak into another test's
    `pipeline.run()` call (see module docstring)."""
    monkeypatch.setattr(detect_mod, "_REGISTRY", [])
    monkeypatch.setattr(dynamic, "_PARSER_CACHE", {})


@pytest.fixture
def temp_dynamic_mapping():
    """Write DYNAMIC_CONFIG into the real ulpf/mappings/ dir (where
    dynamic.py actually scans) and guarantee its removal afterward, pass or
    fail."""
    path = MAPPINGS_DIR / "zztestvendor.yaml"
    assert not path.exists(), "test fixture file already exists - aborting rather than overwrite"
    path.write_text(yaml.safe_dump(DYNAMIC_CONFIG, sort_keys=False), encoding="utf-8")
    try:
        yield path
    finally:
        path.unlink(missing_ok=True)


def _write_samples_dir(tmp_path: Path, lines: list[str]) -> Path:
    samples_dir = tmp_path / "samples"
    samples_dir.mkdir()
    (samples_dir / "zztest.log").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return samples_dir


def _load_events(out_dir: Path) -> list[dict]:
    return [json.loads(line) for line in (out_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()]


def test_before_mapping_exists_line_is_only_partially_parsed(
    tmp_path: Path, isolated_registry: None
) -> None:
    samples_dir = _write_samples_dir(tmp_path, [TEST_LINE])
    out_dir = tmp_path / "out"
    run(samples_dir, out_dir)

    events = _load_events(out_dir)
    assert len(events) == 1
    assert events[0]["parse.status"] == "partial"
    assert events[0]["parse.parser"] == "generic"


def test_saved_mapping_turns_the_same_line_into_ok(
    tmp_path: Path, isolated_registry: None, temp_dynamic_mapping: Path
) -> None:
    samples_dir = _write_samples_dir(tmp_path, [TEST_LINE])
    out_dir = tmp_path / "out"
    run(samples_dir, out_dir)

    events = _load_events(out_dir)
    assert len(events) == 1
    event = events[0]
    assert event["parse.status"] == "ok"
    assert event["parse.parser"] == "llm:ZZTestVendor"
    assert event["observer.vendor"] == "ZZTestVendor"
    assert event["observer.product"] == "ZZBox"
    assert event["network.src_ip"] == "10.55.55.55"
    assert event["network.dst_ip"] == "10.66.66.66"
    assert event["network.transport"] == "tcp"
    assert event["event.action"] == "allow"
    assert event["event.outcome"] == "success"


def test_existing_hand_written_parser_still_wins_over_a_dynamic_one(
    tmp_path: Path, isolated_registry: None
) -> None:
    """A dynamic "kv" config broad enough to also match a FortiGate-shaped
    line must never actually claim it - fortigate.py is tried first."""
    fortigate_line = (
        "date=2026-09-27 time=10:31:00 devname=FG1 srcip=172.16.1.10 srcport=1234 "
        "dstip=8.8.8.8 dstport=53 proto=17 action=deny"
    )
    broad_config = {
        "vendor": "ZZImpostor",
        "product": "ZZImpostorBox",
        "format_hint": "kv",
        "line_regex": r"^.*action=(?P<action>\w+).*$",
        "field_map": {"event.action": "action"},
        "action_rules": [],
        "timestamp_format": "none",
        "category": "network",
        "generator": "ulpf.llm",
    }
    path = MAPPINGS_DIR / "zzimpostor.yaml"
    assert not path.exists()
    path.write_text(yaml.safe_dump(broad_config, sort_keys=False), encoding="utf-8")
    try:
        samples_dir = _write_samples_dir(tmp_path, [fortigate_line])
        out_dir = tmp_path / "out"
        run(samples_dir, out_dir)

        events = _load_events(out_dir)
        assert len(events) == 1
        assert events[0]["observer.vendor"] == "Fortinet"
        assert events[0]["parse.parser"] == "fortigate"
    finally:
        path.unlink(missing_ok=True)


def test_register_called_twice_does_not_duplicate_registry_entries(
    isolated_registry: None, temp_dynamic_mapping: Path
) -> None:
    class _CountingRegistry:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []

        def register(self, fmt: str, parser: object) -> None:
            self.calls.append((fmt, parser))

    registry = _CountingRegistry()
    dynamic.register(registry)
    dynamic.register(registry)

    zz_calls = [c for c in registry.calls if c[0] == "kv"]
    assert len(zz_calls) == 2  # register() itself has no dedup - that's detect._REGISTRY's job
    # But the same underlying function object must be reused both times,
    # so detect.register()'s identity-based dedup actually works.
    assert zz_calls[0][1] is zz_calls[1][1]


def test_malformed_dynamic_config_is_skipped_not_fatal(
    tmp_path: Path, isolated_registry: None
) -> None:
    bad_path = MAPPINGS_DIR / "zzbroken.yaml"
    bad_path.write_text(
        yaml.safe_dump({"generator": "ulpf.llm", "line_regex": "("}, sort_keys=False),
        encoding="utf-8",
    )
    try:
        samples_dir = _write_samples_dir(tmp_path, [TEST_LINE])
        out_dir = tmp_path / "out"
        run(samples_dir, out_dir)  # must not raise
        events = _load_events(out_dir)
        assert events[0]["parse.status"] == "partial"  # falls back to generic, as before
    finally:
        bad_path.unlink(missing_ok=True)


def test_hand_written_mappings_are_never_picked_up_as_dynamic() -> None:
    configs = dynamic._load_dynamic_configs(MAPPINGS_DIR)
    names = {path.name for path, _ in configs}
    assert "fortigate.yaml" not in names
    assert "cisco_asa.yaml" not in names
    assert "checkpoint.yaml" not in names


def test_quoted_kv_mapping_turns_partial_line_into_ok(
    tmp_path: Path, isolated_registry: None
) -> None:
    """Sophos-style quoted values, including a value that contains a space.

    Before the mapping exists the generic fallback owns the line. After a
    mode=kv config is saved, the same line is ok and the quoted text is
    intact — the model never supplied a regex.
    """
    line = (
        'device_name="ZZSophos9827" timestamp="2026-10-04 12:00:00" '
        'src_ip="10.55.55.55" dst_ip="10.66.66.66" src_port="4431" dst_port="443" '
        'protocol="tcp" status="allow" msg="hello world"'
    )
    samples_dir = _write_samples_dir(tmp_path, [line])
    before = _load_events_from(tmp_path, samples_dir, "out_before")
    assert before[0]["parse.status"] == "partial"
    assert before[0]["parse.parser"] == "generic"

    config = {
        "vendor": "ZZSophos9827",
        "product": "ZZXG",
        "mode": "kv",
        "format_hint": "kv",
        "field_map": {
            "network.src_ip": "src_ip",
            "network.dst_ip": "dst_ip",
            "network.src_port": "src_port",
            "network.dst_port": "dst_port",
            "network.transport": "protocol",
            "event.action": "status",
            "event.description": "msg",
        },
        "action_rules": [{"match_value": "allow", "action": "allow"}],
        "timestamp": {"keys": ["timestamp"], "format": "YYYY-MM-DD HH:MM:SS"},
        "category": "network",
        "generator": "ulpf.llm",
    }
    path = MAPPINGS_DIR / "zzsophos9827.yaml"
    assert not path.exists()
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    try:
        after = _load_events_from(tmp_path, samples_dir, "out_after")
    finally:
        path.unlink(missing_ok=True)

    assert len(after) == 1
    event = after[0]
    assert event["parse.status"] == "ok"
    assert event["parse.parser"] == "llm:ZZSophos9827"
    assert event["parse.format"] == "kv"
    assert event["observer.vendor"] == "ZZSophos9827"
    assert event["network.src_ip"] == "10.55.55.55"
    assert event["network.dst_ip"] == "10.66.66.66"
    assert event["network.src_port"] == 4431
    assert event["network.dst_port"] == 443
    assert event["network.transport"] == "tcp"
    assert event["event.action"] == "allow"
    assert event["event.outcome"] == "success"
    assert event["event.description"] == "hello world"
    assert event["timestamp"] == "2026-10-04 12:00:00"
    assert event["provenance.raw_text"] == line


def test_syslog_kv_mapping_turns_partial_line_into_ok(
    tmp_path: Path, isolated_registry: None
) -> None:
    """Juniper RT_FLOW: syslog prefix plus hyphenated quoted key=value pairs."""
    line = (
        "<14>Oct  4 12:00:01 zzsrx1 RT_FLOW: RT_FLOW_SESSION_DENY: "
        'source-address="10.55.55.55" source-port="12345" '
        'destination-address="10.66.66.66" destination-port="443" '
        'protocol="tcp" action="deny"'
    )
    samples_dir = _write_samples_dir(tmp_path, [line])
    before = _load_events_from(tmp_path, samples_dir, "out_before")
    assert before[0]["parse.status"] == "partial"
    assert before[0]["parse.parser"] == "generic"

    config = {
        "vendor": "ZZJuniper9827",
        "product": "ZZSRX",
        "mode": "syslog_kv",
        "format_hint": "syslog",
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
        "generator": "ulpf.llm",
    }
    path = MAPPINGS_DIR / "zzjuniper9827.yaml"
    assert not path.exists()
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    try:
        after = _load_events_from(tmp_path, samples_dir, "out_after")
    finally:
        path.unlink(missing_ok=True)

    assert len(after) == 1
    event = after[0]
    assert event["parse.status"] == "ok"
    assert event["parse.parser"] == "llm:ZZJuniper9827"
    assert event["parse.format"] == "syslog"
    assert event["observer.vendor"] == "ZZJuniper9827"
    assert event["network.src_ip"] == "10.55.55.55"
    assert event["network.dst_ip"] == "10.66.66.66"
    assert event["network.src_port"] == 12345
    assert event["network.dst_port"] == 443
    assert event["network.transport"] == "tcp"
    assert event["event.action"] == "deny"
    assert event["event.outcome"] == "failure"
    assert event["timestamp"] == "Oct  4 12:00:01"
    assert event["provenance.raw_text"] == line


def test_rt_flow_mapping_turns_partial_lines_into_ok(
    tmp_path: Path, isolated_registry: None
) -> None:
    """Positional RT_FLOW: protocol numbers and session verbs are rewritten."""
    create = (
        "<14>Sep  3 09:01:02 ZZEDGE9827 RT_FLOW: RT_FLOW_SESSION_CREATE: "
        "session created 10.55.55.55/49811->10.66.66.66/443 0x0 junos-https "
        "10.55.55.55/49811->10.66.66.66/443 0x0 N/A N/A 6 zz-policy zzone uzone 42"
    )
    deny = (
        "<14>Sep 30 09:01:03 ZZEDGE9827 RT_FLOW: RT_FLOW_SESSION_DENY: "
        "session denied 10.55.55.56/1200->10.66.66.67/53 junos-dns-udp 17(0) "
        "untrust-to-trust untrust trust NO_POLICY 17"
    )
    icmp = (
        "<14>Sep 30 09:01:04 ZZEDGE9827 RT_FLOW: RT_FLOW_SESSION_CREATE: "
        "session created 10.55.55.55/0->10.66.66.66/0 0x0 junos-icmp-ping "
        "10.55.55.55/0->10.66.66.66/0 0x0 N/A N/A 1 zz-policy zzone uzone 43"
    )
    samples_dir = _write_samples_dir(tmp_path, [create, deny, icmp])
    before = _load_events_from(tmp_path, samples_dir, "out_before")
    assert [row["parse.status"] for row in before] == ["partial", "partial", "partial"]
    assert before[0]["parse.parser"] == "generic"

    config = {
        "vendor": "ZZRtFlow9827",
        "product": "ZZSRX",
        "mode": "rt_flow",
        "format_hint": "syslog",
        "field_map": {
            "network.src_ip": "src_ip",
            "network.dst_ip": "dst_ip",
            "network.src_port": "src_port",
            "network.dst_port": "dst_port",
            "observer.name": "host",
        },
        "action_rules": [],
        "timestamp": {"keys": ["timestamp"], "format": "Mmm dd HH:MM:SS"},
        "category": "network",
        "generator": "ulpf.llm",
    }
    path = MAPPINGS_DIR / "zzrtflow9827.yaml"
    assert not path.exists()
    path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
    try:
        after = _load_events_from(tmp_path, samples_dir, "out_after")
    finally:
        path.unlink(missing_ok=True)

    assert len(after) == 3
    created, denied, ping = after
    assert created["parse.status"] == "ok"
    assert created["parse.parser"] == "llm:ZZRtFlow9827"
    assert created["parse.format"] == "syslog"
    assert created["network.src_ip"] == "10.55.55.55"
    assert created["network.dst_port"] == 443
    assert created["network.transport"] == "tcp"
    assert created["event.action"] == "allow"
    assert created["event.outcome"] == "success"
    assert created["timestamp"] == "Sep  3 09:01:02"
    assert created["provenance.raw_text"] == create
    assert denied["network.transport"] == "udp"
    assert denied["event.action"] == "deny"
    assert denied["event.outcome"] == "failure"
    assert ping["network.transport"] == "icmp"
    assert ping["network.src_port"] == 0
    assert ping["event.action"] == "allow"


def _load_events_from(tmp_path: Path, samples_dir: Path, name: str) -> list[dict]:
    out_dir = tmp_path / name
    run(samples_dir, out_dir)
    return _load_events(out_dir)
