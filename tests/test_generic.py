from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ulpf.detect import detect_format
from ulpf.parsers import generic
from ulpf.pipeline import run

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
MESSY_LOG = SAMPLES / "messy.log"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _run_samples(tmp_path: Path) -> dict[str, dict]:
    """Run the full samples/ pipeline once, keyed by raw_hash for lookup."""
    out = tmp_path / "out"
    run(SAMPLES, out)
    raw = {r["raw_hash"]: r for r in _load_jsonl(out / "raw.jsonl")}
    events = {e["provenance.raw_hash"]: e for e in _load_jsonl(out / "events.jsonl")}
    ocsf = {r["raw_hash"]: o for r, o in zip(_load_jsonl(out / "raw.jsonl"), _load_jsonl(out / "ocsf.jsonl"))}
    merged = {}
    for digest, r in raw.items():
        merged[digest] = {"raw": r, "event": events[digest], "ocsf": ocsf[digest]}
    return merged


# ---------------------------------------------------------------------------
# detect_format: new "leef" format, and vendor fingerprint hints.
# ---------------------------------------------------------------------------


def test_detect_format_recognizes_leef() -> None:
    detection = detect_format("LEEF:2.0|Juniper|SRX|1.0|allow|src=10.3.3.3\tact=allow")
    assert detection.format == "leef"


def test_detect_format_hints_are_independent_of_classification() -> None:
    # "%ASA-" hint survives even though this line doesn't match cisco_asa's
    # strict syslog+connection regex and classifies as "unknown".
    detection = detect_format("%ASA-6-302013 malformed body no pri prefix")
    assert detection.format == "unknown"
    assert "cisco_asa" in detection.hints

    detection = detect_format("date=2026-01-01 devname=FG1 action=deny")
    assert "fortigate" in detection.hints

    detection = detect_format(
        'CEF:0|Palo Alto Networks|PanOS|10.1|1|THREAT|5|src=1.1.1.1 dst=2.2.2.2'
    )
    assert "paloalto" in detection.hints
    assert any(h.startswith("cef_vendor:Palo Alto Networks") for h in detection.hints)

    detection = detect_format(
        '{"event_type":"alert","alert":{"action":"allowed","signature":"x","severity":1}}'
    )
    assert "suricata" in detection.hints


def test_pipeline_auto_selects_parser_with_no_manual_flag() -> None:
    # No format/vendor argument anywhere in run()'s signature or callers.
    import inspect

    from ulpf.pipeline import run as run_fn

    params = list(inspect.signature(run_fn).parameters)
    assert params == ["input_dir", "output_dir"]


# ---------------------------------------------------------------------------
# generic.py unit tests (no pipeline needed).
# ---------------------------------------------------------------------------


def test_generic_parse_returns_none_for_truly_opaque_text() -> None:
    assert generic.parse("this is not a log", {}) is None


def test_generic_parse_extracts_ip_and_action_from_freeform_text() -> None:
    event = generic.parse(
        "Perimeter sensor noticed traffic from 198.51.100.9 towards 198.51.100.10 was blocked", {}
    )
    assert event is not None
    assert event["network.src_ip"] == "198.51.100.9"
    assert event["network.dst_ip"] == "198.51.100.10"
    assert event["event.action"] == "blocked"
    assert event["event.outcome"] == "failure"
    assert event["parse.status"] == "partial"
    assert 0 < event["parse.confidence"] <= 1.0


def test_generic_parse_uses_hints_for_vendor_guess_only_when_unset() -> None:
    event = generic.parse("some deny traffic 5.5.5.5 6.6.6.6", {"hints": ("cisco_asa",)})
    assert event is not None
    assert event["observer.vendor"] == "Cisco"

    cef_event = generic.parse(
        "CEF:0|Acme|Firewall|1.0|1|Weird|3|src=1.1.1.1 dst=2.2.2.2",
        {"hints": ("cisco_asa",)},
    )
    # CEF header vendor wins over a hint guess.
    assert cef_event is not None
    assert cef_event["observer.vendor"] == "Acme"


# ---------------------------------------------------------------------------
# End-to-end: every record in samples/messy.log, via the real pipeline.
# ---------------------------------------------------------------------------


def test_messy_log_has_fifteen_logical_records() -> None:
    raw_bytes = MESSY_LOG.read_bytes()
    # Continuation lines (leading space/tab) don't start a new record.
    logical = 0
    for physical in raw_bytes.split(b"\n"):
        line = physical[:-1] if physical.endswith(b"\r") else physical
        if line == b"":
            continue
        if line[:1] not in (b" ", b"\t"):
            logical += 1
    assert logical == 15


def test_non_utf8_byte_preserved_and_flagged_lossy(tmp_path: Path) -> None:
    merged = _run_samples(tmp_path)
    record = next(
        m for m in merged.values() if m["raw"]["source_file"] == "messy.log" and m["raw"]["raw_text_lossy"]
    )
    raw = record["raw"]
    assert "�" in raw["raw_text"]
    original_bytes = base64_decode(raw["raw_bytes_b64"])
    assert b"\xff" in original_bytes
    assert raw["raw_hash"] == _sha256(original_bytes)
    # Despite the bad byte, generic still extracted the surrounding fields.
    event = record["event"]
    assert event["network.src_ip"] == "10.0.0.9"
    assert event["network.dst_ip"] == "10.0.0.10"
    assert event["event.action"] == "deny"
    assert event["parse.status"] == "partial"


def base64_decode(text: str) -> bytes:
    import base64

    return base64.b64decode(text)


def test_multiline_record_merges_continuation_lines(tmp_path: Path) -> None:
    merged = _run_samples(tmp_path)
    record = next(
        m
        for m in merged.values()
        if m["raw"]["source_file"] == "messy.log" and "BEGIN_TRACE" in m["raw"]["raw_text"]
    )
    raw_text = record["raw"]["raw_text"]
    assert "caused by: connection refused" in raw_text
    assert "at native stack frame" in raw_text
    assert raw_text.count("\n") == 2
    event = record["event"]
    assert event["parse.status"] == "ok"
    assert event["observer.vendor"] == "Check Point"
    assert event["network.src_ip"] == "10.4.4.4"
    assert event["network.dst_ip"] == "10.4.4.5"


def test_mixed_timezone_json_records_parsed_by_generic(tmp_path: Path) -> None:
    merged = _run_samples(tmp_path)
    events_by_marker = {}
    for m in merged.values():
        text = m["raw"]["raw_text"]
        if "Nasty Test Signature 1" in text:
            events_by_marker["plus_offset"] = m
        elif "Nasty Test Signature 2" in text:
            events_by_marker["minus_offset_no_colon"] = m

    plus = events_by_marker["plus_offset"]
    assert plus["event"]["parse.status"] == "partial"
    assert plus["event"]["parse.parser"] == "generic"
    assert plus["event"]["network.src_ip"] == "10.2.2.2"
    assert plus["event"]["timestamp"] == "2026-09-28T09:05:00+05:30"
    assert plus["ocsf"]["time"] > 0

    minus = events_by_marker["minus_offset_no_colon"]
    assert minus["event"]["network.dst_ip"] == "10.2.2.5"
    assert minus["event"]["timestamp"] == "2026-09-28T09:06:00-0700"
    assert minus["ocsf"]["time"] > 0
    # Different offsets/instants must not collapse to the same epoch millis.
    assert plus["ocsf"]["time"] != minus["ocsf"]["time"]


def test_leef_record_parsed_by_generic_fallback(tmp_path: Path) -> None:
    merged = _run_samples(tmp_path)
    record = next(m for m in merged.values() if m["raw"]["raw_text"].startswith("LEEF:"))
    event = record["event"]
    assert event["parse.format"] == "leef"
    assert event["parse.parser"] == "generic"
    assert event["parse.status"] == "partial"
    assert event["observer.vendor"] == "Juniper"
    assert event["observer.product"] == "SRX"
    assert event["network.src_ip"] == "10.3.3.3"
    assert event["network.dst_ip"] == "10.3.3.4"
    assert event["network.src_port"] == 1111
    assert event["network.dst_port"] == 443
    assert event["network.transport"] == "tcp"
    assert event["event.outcome"] == "success"


def test_ipv6_heuristic_extraction(tmp_path: Path) -> None:
    merged = _run_samples(tmp_path)
    record = next(m for m in merged.values() if "flow_src" in m["raw"]["raw_text"])
    event = record["event"]
    assert event["parse.status"] == "partial"
    assert event["network.src_ip"] == "2001:0db8:0000:0000:0000:0000:0000:0001"
    assert event["network.dst_ip"] == "2001:0db8:0000:0000:0000:0000:0000:0002"
    assert event["event.action"] == "drop"
    assert event["event.outcome"] == "failure"


def test_unparseable_garbage_line_still_fails_cleanly(tmp_path: Path) -> None:
    merged = _run_samples(tmp_path)
    record = next(m for m in merged.values() if "fluffernutter" in m["raw"]["raw_text"])
    event = record["event"]
    assert event["parse.status"] == "failed"
    assert event["parse.parser"] == ""
    assert event["network.src_ip"] == ""


def test_syslog_prefixed_kv_body_falls_back_to_generic(tmp_path: Path) -> None:
    merged = _run_samples(tmp_path)
    record = next(m for m in merged.values() if "policy_violation" in m["raw"]["raw_text"])
    event = record["event"]
    assert event["parse.format"] == "kv"
    assert event["parse.parser"] == "generic"
    assert event["network.src_ip"] == "172.20.0.5"
    assert event["network.dst_ip"] == "172.20.0.6"
    assert event["network.src_port"] == 5000
    assert event["network.dst_port"] == 443
    assert event["network.transport"] == "tcp"
    assert event["event.action"] == "deny"
    assert event["event.outcome"] == "failure"
    # Heuristic fill recovered the syslog timestamp even though it wasn't
    # under a recognized key=value timestamp field.
    assert event["timestamp"] == "Sep 28 09:10:00"
    assert record["ocsf"]["time"] > 0


def test_timestamp_gap_falls_back_to_ingest_time(tmp_path: Path) -> None:
    merged = _run_samples(tmp_path)
    record = next(m for m in merged.values() if "when=1758960000" in m["raw"]["raw_text"])
    event = record["event"]
    assert event["timestamp"] == ""
    assert event["network.src_ip"] == "10.6.6.6"
    assert record["ocsf"]["time"] > 0


def test_suricata_edge_case_stays_on_vendor_parser(tmp_path: Path) -> None:
    merged = _run_samples(tmp_path)
    record = next(m for m in merged.values() if "Nasty Suricata Edge Case" in m["raw"]["raw_text"])
    event = record["event"]
    ocsf = record["ocsf"]
    assert event["parse.parser"] == "suricata"
    assert event["parse.status"] == "ok"
    assert event["network.src_ip"] == "2001:db8::10"
    assert event["network.transport"] == "sctp"
    assert ocsf["class_uid"] == 2004
    assert ocsf["class_name"] == "Security Finding"
    assert ocsf["disposition"] == "Blocked"
    assert ocsf["severity_id"] == 4


def test_pa_hint_sets_vendor_guess_via_generic(tmp_path: Path) -> None:
    merged = _run_samples(tmp_path)
    record = next(m for m in merged.values() if m["raw"]["raw_text"].startswith("PA-5220"))
    event = record["event"]
    assert event["parse.parser"] == "generic"
    assert event["observer.vendor"] == "Palo Alto Networks"
    assert event["network.src_ip"] == "10.7.7.7"
    assert event["network.dst_ip"] == "10.7.7.8"
    assert event["event.outcome"] == "success"


def test_ambiguous_source_key_does_not_produce_false_ip(tmp_path: Path) -> None:
    merged = _run_samples(tmp_path)
    record = next(m for m in merged.values() if "WinDefender" in m["raw"]["raw_text"])
    event = record["event"]
    # "Source=WinDefender" is a product name, not an IP; the real IPs come
    # from the heuristic regex scan over LocalAddress/RemoteAddress.
    assert event["network.src_ip"] == "10.8.8.8"
    assert event["network.dst_ip"] == "203.0.113.99"
    assert event["event.action"] == "blocked"
    assert event["unmapped"]["source"] == "WinDefender"


def test_cef_with_nonnumeric_severity_and_odd_keys_stays_on_vendor_parser(tmp_path: Path) -> None:
    merged = _run_samples(tmp_path)
    record = next(m for m in merged.values() if "Zscaler" in m["raw"]["raw_text"])
    event = record["event"]
    ocsf = record["ocsf"]
    assert event["parse.parser"] == "cef"
    assert event["parse.status"] == "ok"
    assert event["event.severity"] == "High"
    assert event["network.src_ip"] == ""  # "sip" isn't in cef.yaml's field map
    assert event["network.src_port"] == 51000
    # ocsf.py doesn't crash on the non-numeric severity; falls back to Unknown.
    assert ocsf["severity_id"] == 0


def test_all_messy_log_records_present_and_shaped(tmp_path: Path) -> None:
    merged = _run_samples(tmp_path)
    messy_records = [m for m in merged.values() if m["raw"]["source_file"] == "messy.log"]
    assert len(messy_records) == 15
    for m in messy_records:
        assert m["event"]["parse.status"] in {"ok", "partial", "failed"}
        assert m["ocsf"]["class_uid"] in {2004, 3002, 4001}
        assert m["ocsf"]["metadata"]["raw_data_hash"] == m["raw"]["raw_hash"]
