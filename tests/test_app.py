from __future__ import annotations

from pathlib import Path

from ulpf.app import busiest_source_ips, filter_events, load_events, page_data, summarize
from ulpf.pipeline import run

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
CISCO_OK = (
    "<166>Sep 27 10:30:12 fw1 : %ASA-6-302013: Built outbound TCP connection "
    "224811914 for outside:10.0.0.1/80 to inside:192.168.10.5/53421 user jdoe"
)


def _events(tmp_path: Path) -> list[dict]:
    out = tmp_path / "out"
    run(SAMPLES, out)
    return load_events(out / "events.jsonl")


def test_app_counts_and_filter(tmp_path: Path) -> None:
    events = _events(tmp_path)
    counts = summarize(events)
    assert counts["event_count"] == 8
    assert counts["failed_parses"] == 1
    assert counts["distinct_vendors"] == 4
    assert counts["authentication_failures"] == 1

    top = busiest_source_ips(events)
    assert top[0] == ("203.0.113.5", 2)
    assert len(top) == 5

    visible = filter_events(events, "203.0.113.5")
    assert len(visible) == 2
    assert {row["observer.vendor"] for row in visible} == {"Fortinet", "Palo Alto Networks"}

    data = page_data(events, "203.0.113.5")
    assert data["summary"] == counts
    assert {row["observer.vendor"] for row in data["rows"]} == {"Fortinet", "Palo Alto Networks"}

    cisco = next(row for row in events if row["observer.vendor"] == "Cisco")
    assert "user jdoe" in cisco["provenance.raw_text"]
    assert cisco["provenance.raw_text"] == CISCO_OK

    garbage = next(row for row in events if row["parse.status"] == "failed")
    assert garbage["provenance.raw_text"] == "this is not a log"
