from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from ulpf import verify
from ulpf.pipeline import run

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def _run_pipeline(tmp_path: Path) -> Path:
    out = tmp_path / "out"
    run(SAMPLES, out)
    return out


def _read_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def _write_lines(path: Path, lines: list[str]) -> None:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _find_line_index(lines: list[str], predicate) -> int:
    for i, line in enumerate(lines):
        record = json.loads(line)
        if predicate(record):
            return i
    raise AssertionError("no matching raw.jsonl line found")


def test_verify_passes_on_untampered_output(tmp_path: Path) -> None:
    out = _run_pipeline(tmp_path)
    report = verify.verify(out)
    assert report.ok is True
    assert report.mismatches == []
    assert report.raw_count == 23
    assert report.event_count == 23


def test_verify_catches_tampered_raw_text(tmp_path: Path) -> None:
    out = _run_pipeline(tmp_path)
    raw_path = out / "raw.jsonl"
    lines = _read_lines(raw_path)

    # Pick a non-lossy record so tampering raw_text alone (leaving raw_hash
    # untouched) is unambiguously a hash mismatch, not an artifact of the
    # lossy-decode base64 path.
    idx = _find_line_index(lines, lambda r: not r.get("raw_text_lossy"))
    record = json.loads(lines[idx])
    tampered_id = record["raw_event_id"]
    record["raw_text"] = record["raw_text"] + " TAMPERED"
    # raw_hash deliberately left as-is: simulates an attacker editing the
    # log line without recomputing the hash.
    lines[idx] = json.dumps(record, ensure_ascii=False)
    _write_lines(raw_path, lines)

    report = verify.verify(out)
    assert report.ok is False
    mismatches = [m for m in report.mismatches if m.raw_event_id == tampered_id]
    assert len(mismatches) == 1
    assert mismatches[0].kind == "raw_hash_mismatch"


def test_verify_catches_hash_recomputed_to_match_tampered_text(tmp_path: Path) -> None:
    # A more careful tamper: edit raw_text AND recompute raw_hash so it's
    # internally consistent (defeats the plain recompute-and-compare check).
    # It must still be caught by cross-checking events.jsonl, which recorded
    # the *original* hash at parse time.
    out = _run_pipeline(tmp_path)
    raw_path = out / "raw.jsonl"
    lines = _read_lines(raw_path)

    idx = _find_line_index(lines, lambda r: not r.get("raw_text_lossy"))
    record = json.loads(lines[idx])
    tampered_id = record["raw_event_id"]
    record["raw_text"] = record["raw_text"] + " TAMPERED"
    record["raw_hash"] = hashlib.sha256(record["raw_text"].encode("utf-8")).hexdigest()
    lines[idx] = json.dumps(record, ensure_ascii=False)
    _write_lines(raw_path, lines)

    report = verify.verify(out)
    assert report.ok is False
    # Check 1 (raw.jsonl self-consistency) passes now - the hash matches
    # the doctored text - but check 2 (events.jsonl cross-reference) must
    # still catch it.
    mismatches = [m for m in report.mismatches if m.raw_event_id == tampered_id]
    assert len(mismatches) == 1
    assert mismatches[0].kind == "event_hash_mismatch"


def test_verify_catches_missing_raw_id(tmp_path: Path) -> None:
    out = _run_pipeline(tmp_path)
    raw_path = out / "raw.jsonl"
    lines = _read_lines(raw_path)

    idx = _find_line_index(lines, lambda r: True)
    removed = json.loads(lines.pop(idx))
    _write_lines(raw_path, lines)

    report = verify.verify(out)
    assert report.ok is False
    mismatches = [m for m in report.mismatches if m.raw_event_id == removed["raw_event_id"]]
    assert len(mismatches) == 1
    assert mismatches[0].kind == "missing_raw_id"


def test_verify_report_to_dict_is_json_serializable(tmp_path: Path) -> None:
    out = _run_pipeline(tmp_path)
    report = verify.verify(out)
    serialized = json.dumps(report.to_dict())
    assert json.loads(serialized)["ok"] is True


def test_main_exits_nonzero_when_tampered(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = _run_pipeline(tmp_path)
    raw_path = out / "raw.jsonl"
    lines = _read_lines(raw_path)
    idx = _find_line_index(lines, lambda r: not r.get("raw_text_lossy"))
    record = json.loads(lines[idx])
    record["raw_text"] = record["raw_text"] + " TAMPERED"
    lines[idx] = json.dumps(record, ensure_ascii=False)
    _write_lines(raw_path, lines)

    with pytest.raises(SystemExit) as excinfo:
        verify.main([str(out)])
    assert excinfo.value.code == 1
    printed = json.loads(capsys.readouterr().out)
    assert printed["ok"] is False


def test_main_exits_zero_when_clean(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = _run_pipeline(tmp_path)
    with pytest.raises(SystemExit) as excinfo:
        verify.main([str(out)])
    assert excinfo.value.code == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["ok"] is True
