from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ulpf.pipeline import run
from ulpf.schema import EVENT_KEYS

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
CISCO_LOG = SAMPLES / "cisco.log"


def _load_events(out_dir: Path) -> list[dict]:
    path = out_dir / "events.jsonl"
    lines = path.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_pipeline_parses_cisco_sample_and_keeps_failed_line(tmp_path: Path) -> None:
    out1 = tmp_path / "run1"
    out2 = tmp_path / "run2"
    run(SAMPLES, out1)
    run(SAMPLES, out2)

    events1 = _load_events(out1)
    events2 = _load_events(out2)
    assert len(events1) == 2
    assert (out1 / "raw.jsonl").is_file()
    assert (out1 / "events.jsonl").is_file()

    raw_lines = CISCO_LOG.read_text(encoding="utf-8").splitlines()
    assert raw_lines == [
        "<166>Sep 27 10:30:12 fw1 : %ASA-6-302013: Built outbound TCP connection 224811914 for outside:10.0.0.1/80 to inside:192.168.10.5/53421 user jdoe",
        "this is not a log",
    ]

    ok_event, failed_event = events1
    for event in events1:
        assert list(event.keys()) == list(EVENT_KEYS)

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

    assert events1[0]["provenance.raw_hash"] == events2[0]["provenance.raw_hash"]
    assert events1[1]["provenance.raw_hash"] == events2[1]["provenance.raw_hash"]
    assert events1[0]["provenance.raw_hash"] == _sha256(raw_lines[0])
    assert events1[1]["provenance.raw_hash"] == _sha256(raw_lines[1])
