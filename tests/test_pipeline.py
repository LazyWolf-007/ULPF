from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ulpf.detect import detect
from ulpf.pipeline import run
from ulpf.schema import EVENT_KEYS

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
CISCO_LOG = SAMPLES / "cisco.log"
FORTIGATE_LOG = SAMPLES / "fortigate.log"
PALOALTO_LOG = SAMPLES / "paloalto.log"
SURICATA_LOG = SAMPLES / "suricata.log"
SSHD_LOG = SAMPLES / "sshd.log"
CHECKPOINT_LOG = SAMPLES / "checkpoint.log"

CISCO_OK = (
    "<166>Sep 27 10:30:12 fw1 : %ASA-6-302013: Built outbound TCP connection "
    "224811914 for outside:10.0.0.1/80 to inside:192.168.10.5/53421 user jdoe"
)
CISCO_GARBAGE = "this is not a log"
FG1 = (
    "date=2026-09-27 time=10:31:00 devname=FG1 srcip=172.16.1.10 srcport=1234 "
    "dstip=8.8.8.8 dstport=53 proto=17 action=deny"
)
FG2 = (
    "date=2026-09-27 time=10:32:00 devname=FG1 srcip=203.0.113.5 srcport=41000 "
    "dstip=198.51.100.1 dstport=443 proto=6 action=deny"
)
PALOALTO = (
    "CEF:0|Palo Alto Networks|PanOS|10.1|30514|THREAT|10|src=203.0.113.5 "
    "dst=198.51.100.1 spt=34567 dpt=443 proto=6 act=alert"
)
SURICATA = (
    '{"timestamp":"2026-09-27T10:33:00.123456Z","event_type":"alert",'
    '"src_ip":"10.0.0.2","src_port":54321,"dest_ip":"8.8.8.8","dest_port":53,'
    '"proto":"UDP","alert":{"action":"allowed","signature":"Allowed DNS Query","severity":2}}'
)
SSHD = "<38>Sep 27 10:34:00 host sshd[9999]: Failed password for alice from 10.0.0.3 port 22 ssh2"
CHECKPOINT = "src=1.1.1.1 dst=2.2.2.2 action=Drop"


def _load_events(out_dir: Path) -> list[dict]:
    path = out_dir / "events.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def _by_text(events: list[dict]) -> dict[str, dict]:
    return {event["provenance.raw_text"]: event for event in events}


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_detect_first_match_wins() -> None:
    assert detect(PALOALTO) == "cef"
    assert detect('{"a": 1}') == "json"
    assert detect(SURICATA) == "json"
    assert detect(CISCO_OK) == "syslog"
    assert detect(SSHD) == "syslog"
    assert detect(FG1) == "kv"
    assert detect(CISCO_GARBAGE) == "unknown"


def test_pipeline_parses_cisco_sample_and_keeps_failed_line(tmp_path: Path) -> None:
    out1 = tmp_path / "run1"
    out2 = tmp_path / "run2"
    run(SAMPLES, out1)
    run(SAMPLES, out2)

    events1 = _load_events(out1)
    events2 = _load_events(out2)
    # 8 records from the original 6 vendor samples + 15 logical records from
    # samples/messy.log (one of which merges 3 physical lines into 1).
    assert len(events1) == 23
    assert (out1 / "raw.jsonl").is_file()
    assert (out1 / "events.jsonl").is_file()
    assert (out1 / "ocsf.jsonl").is_file()
    assert len((out1 / "raw.jsonl").read_text(encoding="utf-8").splitlines()) == 23

    raw_lines = CISCO_LOG.read_text(encoding="utf-8").splitlines()
    assert raw_lines == [CISCO_OK, CISCO_GARBAGE]
    assert FORTIGATE_LOG.read_text(encoding="utf-8").splitlines() == [FG1, FG2]
    assert PALOALTO_LOG.read_text(encoding="utf-8").splitlines() == [PALOALTO]
    assert SURICATA_LOG.read_text(encoding="utf-8").splitlines() == [SURICATA]
    assert SSHD_LOG.read_text(encoding="utf-8").splitlines() == [SSHD]
    assert CHECKPOINT_LOG.read_text(encoding="utf-8").splitlines() == [CHECKPOINT]

    by_text = _by_text(events1)
    for event in events1:
        assert list(event.keys()) == list(EVENT_KEYS)

    ok_event = by_text[CISCO_OK]
    failed_event = by_text[CISCO_GARBAGE]
    assert ok_event["observer.vendor"] == "Cisco"
    assert ok_event["observer.product"] == "ASA"
    assert ok_event["network.src_ip"] == "10.0.0.1"
    assert ok_event["network.src_port"] == 80
    assert ok_event["network.dst_ip"] == "192.168.10.5"
    assert ok_event["network.dst_port"] == 53421
    assert ok_event["network.transport"] == "tcp"
    assert ok_event["user.name"] == "jdoe"
    assert ok_event["event.action"] == "built"
    assert ok_event["event.outcome"] == "success"
    assert ok_event["event.category"] == "network"
    assert ok_event["parse.format"] == "syslog"
    assert ok_event["parse.status"] == "ok"
    assert ok_event["provenance.raw_text"] == raw_lines[0]
    assert ok_event["provenance.raw_hash"] == _sha256(raw_lines[0])

    assert failed_event["parse.status"] == "failed"
    assert failed_event["provenance.raw_text"] == "this is not a log"
    assert failed_event["network.src_ip"] == ""
    assert failed_event["network.src_port"] == ""
    assert failed_event["network.dst_ip"] == ""
    assert failed_event["network.dst_port"] == ""
    assert failed_event["network.transport"] == ""
    assert failed_event["provenance.raw_hash"] == _sha256("this is not a log")

    fg1 = by_text[FG1]
    fg2 = by_text[FG2]
    for fg in (fg1, fg2):
        assert fg["parse.format"] == "kv"
        assert fg["observer.vendor"] == "Fortinet"
        assert fg["observer.product"] == "FortiGate"
        assert fg["event.outcome"] == "failure"
        assert fg["observer.name"] == "FG1"
        assert fg["parse.status"] == "ok"

    assert fg1["network.src_ip"] == "172.16.1.10"
    assert fg1["network.src_port"] == 1234
    assert fg1["network.dst_ip"] == "8.8.8.8"
    assert fg1["network.dst_port"] == 53
    assert fg1["network.transport"] == "udp"

    assert fg2["network.src_ip"] == "203.0.113.5"
    assert fg2["network.src_port"] == 41000
    assert fg2["network.dst_ip"] == "198.51.100.1"
    assert fg2["network.dst_port"] == 443
    assert fg2["network.transport"] == "tcp"

    palo = by_text[PALOALTO]
    assert palo["parse.format"] == "cef"
    assert palo["observer.vendor"] == "Palo Alto Networks"
    assert palo["observer.product"] == "PanOS"
    assert palo["network.src_ip"] == "203.0.113.5"
    assert palo["network.src_port"] == 34567
    assert palo["network.dst_ip"] == "198.51.100.1"
    assert palo["network.dst_port"] == 443
    assert palo["network.transport"] == "tcp"
    assert palo["event.action"] == "alert"
    assert palo["event.severity"] == 10
    assert palo["parse.status"] == "ok"

    suricata = by_text[SURICATA]
    assert suricata["parse.format"] == "json"
    assert suricata["timestamp"] == "2026-09-27T10:33:00.123456Z"
    assert suricata["timestamp"] != suricata["provenance.ingest_time"]
    assert suricata["network.src_ip"] == "10.0.0.2"
    assert suricata["network.src_port"] == 54321
    assert suricata["network.dst_ip"] == "8.8.8.8"
    assert suricata["network.dst_port"] == 53
    assert suricata["network.transport"] == "udp"
    assert suricata["event.action"] == "allowed"
    assert suricata["event.outcome"] == "success"
    assert suricata["event.category"] == "network"
    assert suricata["event.description"] == "Allowed DNS Query"
    assert suricata["event.severity"] == 2
    assert suricata["parse.status"] == "ok"
    assert suricata["unmapped"]["signature"] == "Allowed DNS Query"

    sshd = by_text[SSHD]
    assert sshd["parse.format"] == "syslog"
    assert sshd["user.name"] == "alice"
    assert sshd["network.src_ip"] == "10.0.0.3"
    assert sshd["network.dst_port"] == 22
    assert sshd["network.dst_ip"] == ""
    assert sshd["event.action"] == "failed password"
    assert sshd["event.outcome"] == "failure"
    assert sshd["event.category"] == "authentication"
    assert sshd["parse.status"] == "ok"

    checkpoint = by_text[CHECKPOINT]
    assert checkpoint["observer.vendor"] == "Check Point"
    assert checkpoint["network.src_ip"] == "1.1.1.1"
    assert checkpoint["network.dst_ip"] == "2.2.2.2"
    assert checkpoint["event.action"] == "Drop"
    assert checkpoint["event.outcome"] == "failure"
    assert checkpoint["parse.format"] == "kv"
    assert checkpoint["parse.status"] == "ok"

    by_text2 = _by_text(events2)
    for raw in (CISCO_OK, CISCO_GARBAGE, FG1, FG2, PALOALTO, SURICATA, SSHD, CHECKPOINT):
        assert by_text[raw]["provenance.raw_hash"] == by_text2[raw]["provenance.raw_hash"]
        assert by_text[raw]["provenance.raw_hash"] == _sha256(raw)


def test_checkpoint_does_not_require_pipeline_edit(tmp_path: Path) -> None:
    source = (ROOT / "ulpf" / "pipeline.py").read_text(encoding="utf-8")
    assert "checkpoint" not in source
    assert "Check Point" not in source

    out = tmp_path / "out"
    run(SAMPLES, out)
    event = _by_text(_load_events(out))[CHECKPOINT]
    assert event["observer.vendor"] == "Check Point"
    assert event["network.src_ip"] == "1.1.1.1"
    assert event["network.dst_ip"] == "2.2.2.2"
    assert event["event.action"] == "Drop"
    assert event["event.outcome"] == "failure"
    assert event["parse.format"] == "kv"
