from __future__ import annotations

import json
import socket
import time
from pathlib import Path

import pytest

from ulpf.ingest import IngestServer
from ulpf.pipeline import run

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"

CISCO_LINE = (
    "<166>Sep 27 10:30:12 fw1 : %ASA-6-302013: Built outbound TCP connection "
    "224811914 for outside:10.0.0.1/80 to inside:192.168.10.5/53421 user jdoe"
)
FORTIGATE_LINE = (
    "date=2026-09-27 time=10:31:00 devname=FG1 srcip=172.16.1.10 srcport=1234 "
    "dstip=8.8.8.8 dstport=53 proto=17 action=deny"
)


def _wait_until(predicate, timeout: float = 3.0, interval: float = 0.02):
    deadline = time.monotonic() + timeout
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if predicate():
                return
        except Exception as exc:  # noqa: BLE001 - report the last failure if we time out
            last_exc = exc
        time.sleep(interval)
    if last_exc:
        raise last_exc
    raise AssertionError("condition not met before timeout")


def _load_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _send_udp(host: str, port: int, text: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(text.encode("utf-8"), (host, port))


def _send_tcp(host: str, port: int, lines: list[str]) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        for line in lines:
            sock.sendall((line + "\n").encode("utf-8"))


def test_server_binds_to_127_0_0_1_by_default(tmp_path: Path) -> None:
    with IngestServer(tmp_path / "out", port=0) as server:
        assert server.host == "127.0.0.1"
        assert server.port != 0


def test_udp_message_flows_through_same_pipeline_path(tmp_path: Path) -> None:
    out = tmp_path / "out"
    with IngestServer(out, port=0) as server:
        _send_udp(server.host, server.port, CISCO_LINE)

        _wait_until(lambda: len(_load_jsonl(out / "events.jsonl")) == 1)

    events = _load_jsonl(out / "events.jsonl")
    raw = _load_jsonl(out / "raw.jsonl")
    assert len(events) == 1
    event = events[0]
    # Same parser registry, same result as file-based ingestion would give.
    assert event["observer.vendor"] == "Cisco"
    assert event["network.src_ip"] == "10.0.0.1"
    assert event["parse.status"] == "ok"
    # Source label is the sender's address, not a filename.
    assert raw[0]["source_file"].startswith("127.0.0.1:")


def test_tcp_multiple_messages_on_one_connection(tmp_path: Path) -> None:
    out = tmp_path / "out"
    with IngestServer(out, port=0) as server:
        _send_tcp(server.host, server.port, [CISCO_LINE, FORTIGATE_LINE])

        _wait_until(lambda: len(_load_jsonl(out / "events.jsonl")) == 2)

    events = _load_jsonl(out / "events.jsonl")
    vendors = {e["observer.vendor"] for e in events}
    assert vendors == {"Cisco", "Fortinet"}


def test_udp_and_tcp_share_the_same_output_files(tmp_path: Path) -> None:
    out = tmp_path / "out"
    with IngestServer(out, port=0) as server:
        _send_udp(server.host, server.port, CISCO_LINE)
        _send_tcp(server.host, server.port, [FORTIGATE_LINE])

        _wait_until(lambda: len(_load_jsonl(out / "events.jsonl")) == 2)

    raw = _load_jsonl(out / "raw.jsonl")
    events = _load_jsonl(out / "events.jsonl")
    ocsf = _load_jsonl(out / "ocsf.jsonl")
    assert len(raw) == len(events) == len(ocsf) == 2


def test_quality_json_updates_after_ingest(tmp_path: Path) -> None:
    out = tmp_path / "out"
    with IngestServer(out, port=0) as server:
        _send_udp(server.host, server.port, FORTIGATE_LINE)
        _wait_until(lambda: (out / "quality.json").is_file())
        _wait_until(
            lambda: json.loads((out / "quality.json").read_text(encoding="utf-8"))["overall"][
                "total_events"
            ]
            == 1
        )

    report = json.loads((out / "quality.json").read_text(encoding="utf-8"))
    assert report["sources"]["Fortinet"]["total_events"] == 1


def test_ingest_bootstraps_quality_from_existing_pipeline_output(tmp_path: Path) -> None:
    out = tmp_path / "out"
    run(SAMPLES, out)  # 23 existing records from the file-based pipeline
    before = json.loads((out / "quality.json").read_text(encoding="utf-8"))
    assert before["overall"]["total_events"] == 23

    with IngestServer(out, port=0) as server:
        _send_udp(server.host, server.port, CISCO_LINE)
        _wait_until(
            lambda: json.loads((out / "quality.json").read_text(encoding="utf-8"))["overall"][
                "total_events"
            ]
            == 24
        )

    after = json.loads((out / "quality.json").read_text(encoding="utf-8"))
    assert after["overall"]["total_events"] == 24
    events = _load_jsonl(out / "events.jsonl")
    assert len(events) == 24


def test_blank_and_whitespace_only_messages_are_ignored(tmp_path: Path) -> None:
    out = tmp_path / "out"
    with IngestServer(out, port=0) as server:
        _send_udp(server.host, server.port, "   ")
        _send_udp(server.host, server.port, CISCO_LINE)
        _wait_until(lambda: len(_load_jsonl(out / "events.jsonl")) == 1)
        # give the blank message a moment to have been (not) processed
        time.sleep(0.1)

    events = _load_jsonl(out / "events.jsonl")
    assert len(events) == 1


def test_non_utf8_udp_payload_is_handled_like_file_ingestion(tmp_path: Path) -> None:
    out = tmp_path / "out"
    with IngestServer(out, port=0) as server:
        payload = b"saddr=10.9.9.9 daddr=10.9.9.10 verdict=deny protocol=tcp note=bad\xffbyte"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(payload, (server.host, server.port))
        _wait_until(lambda: len(_load_jsonl(out / "raw.jsonl")) == 1)

    raw = _load_jsonl(out / "raw.jsonl")[0]
    events = _load_jsonl(out / "events.jsonl")[0]
    assert raw["raw_text_lossy"] is True
    assert "�" in raw["raw_text"]
    assert events["network.src_ip"] == "10.9.9.9"
