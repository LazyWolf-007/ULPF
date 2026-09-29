from __future__ import annotations

import hashlib
import json
from pathlib import Path

from ulpf.ocsf import OCSF_KEYS, to_ocsf
from ulpf.pipeline import run
from ulpf.schema import empty_event, finalize_event

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _by_hash(ocsf_events: list[dict]) -> dict[str, dict]:
    return {event["metadata"]["raw_data_hash"]: event for event in ocsf_events}


def _by_hash_events(events: list[dict]) -> dict[str, dict]:
    return {event["provenance.raw_hash"]: event for event in events}


def test_pipeline_writes_ocsf_jsonl(tmp_path: Path) -> None:
    out = tmp_path / "out"
    run(SAMPLES, out)

    ocsf_path = out / "ocsf.jsonl"
    events_path = out / "events.jsonl"
    assert ocsf_path.is_file()

    ocsf_events = _load_jsonl(ocsf_path)
    events = _load_jsonl(events_path)
    assert len(ocsf_events) == len(events)

    for record in ocsf_events:
        assert list(record.keys()) == list(OCSF_KEYS)


def test_ocsf_maps_all_six_vendor_samples(tmp_path: Path) -> None:
    out = tmp_path / "out"
    run(SAMPLES, out)

    events = _by_hash_events(_load_jsonl(out / "events.jsonl"))
    ocsf = _by_hash(_load_jsonl(out / "ocsf.jsonl"))

    # Cisco ASA -> Network Activity, allowed connection.
    cisco_text = (
        "<166>Sep 27 10:30:12 fw1 : %ASA-6-302013: Built outbound TCP connection "
        "224811914 for outside:10.0.0.1/80 to inside:192.168.10.5/53421 user jdoe"
    )
    cisco = ocsf[_sha256(cisco_text)]
    assert cisco["class_uid"] == 4001
    assert cisco["class_name"] == "Network Activity"
    assert cisco["category_uid"] == 4
    assert cisco["disposition"] == "Allowed"
    assert cisco["action"] == "built"
    assert cisco["src_endpoint"] == {"ip": "10.0.0.1", "port": 80}
    assert cisco["dst_endpoint"] == {"ip": "192.168.10.5", "port": 53421}
    assert cisco["connection_info"]["protocol_name"] == "tcp"
    assert cisco["metadata"]["vendor_name"] == "Cisco"
    assert cisco["metadata"]["product"] == "ASA"
    assert cisco["metadata"]["raw_event_id"] == events[_sha256(cisco_text)]["provenance.raw_event_id"]
    assert cisco["severity_id"] == 2  # ASA severity 6 (informational) -> Low
    assert cisco["time"] > 0

    # Failed / garbage line still produces a shaped OCSF record.
    garbage = ocsf[_sha256("this is not a log")]
    assert garbage["class_uid"] == 4001
    assert garbage["activity_id"] == 0
    assert garbage["disposition"] == "Unknown"
    assert garbage["severity_id"] == 0
    assert garbage["metadata"]["raw_data_hash"] == _sha256("this is not a log")

    # FortiGate -> Network Activity, denied traffic.
    fg_text = (
        "date=2026-09-27 time=10:31:00 devname=FG1 srcip=172.16.1.10 srcport=1234 "
        "dstip=8.8.8.8 dstport=53 proto=17 action=deny"
    )
    fortigate = ocsf[_sha256(fg_text)]
    assert fortigate["class_uid"] == 4001
    assert fortigate["disposition"] == "Blocked"
    assert fortigate["action"] == "deny"
    assert fortigate["connection_info"]["protocol_name"] == "udp"
    assert fortigate["metadata"]["vendor_name"] == "Fortinet"

    # Palo Alto (CEF) -> Network Activity, high severity.
    palo_text = (
        "CEF:0|Palo Alto Networks|PanOS|10.1|30514|THREAT|10|src=203.0.113.5 "
        "dst=198.51.100.1 spt=34567 dpt=443 proto=6 act=alert"
    )
    palo = ocsf[_sha256(palo_text)]
    assert palo["class_uid"] == 4001
    assert palo["metadata"]["vendor_name"] == "Palo Alto Networks"
    assert palo["severity_id"] == 5  # CEF severity 10 -> Critical

    # Suricata -> Security Finding / Detection, regardless of event.category.
    suricata_text = (
        '{"timestamp":"2026-09-27T10:33:00.123456Z","event_type":"alert",'
        '"src_ip":"10.0.0.2","src_port":54321,"dest_ip":"8.8.8.8","dest_port":53,'
        '"proto":"UDP","alert":{"action":"allowed","signature":"Allowed DNS Query","severity":2}}'
    )
    suricata = ocsf[_sha256(suricata_text)]
    assert events[_sha256(suricata_text)]["event.category"] == "network"
    assert suricata["class_uid"] == 2004
    assert suricata["class_name"] == "Security Finding"
    assert suricata["category_uid"] == 2
    assert suricata["activity_id"] == 1
    assert suricata["severity_id"] == 3  # suricata severity 2 -> Medium
    assert suricata["src_endpoint"] == {"ip": "10.0.0.2", "port": 54321}
    assert suricata["dst_endpoint"] == {"ip": "8.8.8.8", "port": 53}

    # sshd -> Authentication.
    sshd_text = "<38>Sep 27 10:34:00 host sshd[9999]: Failed password for alice from 10.0.0.3 port 22 ssh2"
    sshd = ocsf[_sha256(sshd_text)]
    assert sshd["class_uid"] == 3002
    assert sshd["class_name"] == "Authentication"
    assert sshd["category_uid"] == 3
    assert sshd["disposition"] == "Blocked"
    assert sshd["dst_endpoint"] == {"ip": "", "port": 22}

    # Check Point -> Network Activity, denied, via kv parser.
    checkpoint_text = "src=1.1.1.1 dst=2.2.2.2 action=Drop"
    checkpoint = ocsf[_sha256(checkpoint_text)]
    assert checkpoint["class_uid"] == 4001
    assert checkpoint["disposition"] == "Blocked"
    assert checkpoint["src_endpoint"] == {"ip": "1.1.1.1", "port": ""}
    assert checkpoint["dst_endpoint"] == {"ip": "2.2.2.2", "port": ""}
    assert checkpoint["metadata"]["vendor_name"] == "Check Point"


def test_to_ocsf_on_empty_event_has_fixed_shape() -> None:
    event = finalize_event(empty_event())
    record = to_ocsf(event)
    assert list(record.keys()) == list(OCSF_KEYS)
    assert record["class_uid"] == 4001
    assert record["activity_id"] == 0
    assert record["disposition"] == "Unknown"
    assert record["severity_id"] == 0
    assert record["src_endpoint"] == {"ip": "", "port": ""}
    assert record["metadata"]["raw_data_hash"] == ""
