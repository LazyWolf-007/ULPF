from __future__ import annotations

import builtins
import json
from pathlib import Path

import pytest

from ulpf import export
from ulpf.pipeline import run

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def _sample_events() -> list[dict]:
    return [
        {
            "class_uid": 4001,
            "action": "deny",
            "time": 1790000000000,
            "metadata": {"raw_event_id": "abc-123", "raw_data_hash": "deadbeef"},
        },
        {
            "class_uid": 3002,
            "action": "failed password",
            "time": 0,
            "metadata": {"raw_event_id": "def-456", "raw_data_hash": "cafef00d"},
        },
    ]


def _run_pipeline(tmp_path: Path) -> Path:
    out = tmp_path / "out"
    run(SAMPLES, out)
    return out


# ---------------------------------------------------------------------------
# to_opensearch_bulk
# ---------------------------------------------------------------------------


def test_to_opensearch_bulk_produces_action_and_source_line_pairs() -> None:
    body = export.to_opensearch_bulk(_sample_events(), index="my-index")
    lines = body.splitlines()
    assert len(lines) == 4  # 2 events * (action + source)

    action1 = json.loads(lines[0])
    assert action1 == {"index": {"_index": "my-index", "_id": "abc-123"}}
    source1 = json.loads(lines[1])
    assert source1["action"] == "deny"

    action2 = json.loads(lines[2])
    assert action2["index"]["_id"] == "def-456"


def test_to_opensearch_bulk_falls_back_to_event_id_when_no_metadata() -> None:
    body = export.to_opensearch_bulk([{"event_id": "xyz", "action": "allow"}])
    lines = body.splitlines()
    action = json.loads(lines[0])
    assert action["index"]["_id"] == "xyz"


def test_to_opensearch_bulk_omits_id_when_none_available() -> None:
    body = export.to_opensearch_bulk([{"action": "allow"}])
    action = json.loads(body.splitlines()[0])
    assert "_id" not in action["index"]


def test_to_opensearch_bulk_empty_input() -> None:
    assert export.to_opensearch_bulk([]) == ""


# ---------------------------------------------------------------------------
# to_splunk_hec
# ---------------------------------------------------------------------------


def test_to_splunk_hec_wraps_event_and_converts_epoch_millis_to_seconds() -> None:
    body = export.to_splunk_hec(_sample_events(), source="ulpf-test", sourcetype="ulpf:test")
    lines = [json.loads(line) for line in body.splitlines()]
    assert len(lines) == 2
    assert lines[0]["source"] == "ulpf-test"
    assert lines[0]["sourcetype"] == "ulpf:test"
    assert lines[0]["event"]["action"] == "deny"
    assert lines[0]["time"] == pytest.approx(1790000000.0)


def test_to_splunk_hec_omits_time_when_zero_or_missing() -> None:
    body = export.to_splunk_hec(_sample_events())
    lines = [json.loads(line) for line in body.splitlines()]
    assert "time" not in lines[1]  # time: 0 in the fixture

    body2 = export.to_splunk_hec([{"action": "x"}])
    assert "time" not in json.loads(body2.splitlines()[0])


def test_to_splunk_hec_includes_index_only_when_given() -> None:
    body = export.to_splunk_hec([{"action": "x"}])
    assert "index" not in json.loads(body.splitlines()[0])

    body2 = export.to_splunk_hec([{"action": "x"}], index="security")
    assert json.loads(body2.splitlines()[0])["index"] == "security"


# ---------------------------------------------------------------------------
# to_parquet
# ---------------------------------------------------------------------------


def test_to_parquet_writes_a_readable_file(tmp_path: Path) -> None:
    pyarrow = pytest.importorskip("pyarrow.parquet")
    out_path = tmp_path / "events.parquet"
    export.to_parquet(_sample_events(), out_path)
    assert out_path.is_file()

    table = pyarrow.read_table(out_path)
    rows = table.to_pylist()
    assert len(rows) == 2
    assert rows[0]["action"] == "deny"
    assert rows[0]["metadata"]["raw_event_id"] == "abc-123"


def test_to_parquet_raises_helpful_error_without_pyarrow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "pyarrow" or name.startswith("pyarrow."):
            raise ImportError("simulated missing pyarrow")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(RuntimeError, match="pyarrow"):
        export.to_parquet(_sample_events(), tmp_path / "out.parquet")


# ---------------------------------------------------------------------------
# CLI + real pipeline output
# ---------------------------------------------------------------------------


def test_cli_opensearch_writes_to_output_file(tmp_path: Path) -> None:
    out = _run_pipeline(tmp_path)
    body_path = tmp_path / "bulk.ndjson"
    export.main(["opensearch", str(out), "--output", str(body_path)])

    lines = body_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 46  # 23 events * (action + source)
    for line in lines:
        json.loads(line)  # every line must be valid JSON on its own


def test_cli_splunk_writes_to_output_file(tmp_path: Path) -> None:
    out = _run_pipeline(tmp_path)
    body_path = tmp_path / "hec.ndjson"
    export.main(["splunk", str(out), "--output", str(body_path), "--index", "sec"])

    lines = [json.loads(line) for line in body_path.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 23
    assert all(line["index"] == "sec" for line in lines)
    assert all(line["sourcetype"] == "ulpf:ocsf" for line in lines)


def test_cli_parquet_defaults_to_export_parquet_in_out_dir(tmp_path: Path) -> None:
    pytest.importorskip("pyarrow.parquet")
    out = _run_pipeline(tmp_path)
    export.main(["parquet", str(out)])

    default_path = out / "export.parquet"
    assert default_path.is_file()

    import pyarrow.parquet as pq

    table = pq.read_table(default_path)
    assert table.num_rows == 23


def test_cli_reads_events_jsonl_when_requested(tmp_path: Path) -> None:
    out = _run_pipeline(tmp_path)
    body_path = tmp_path / "internal.ndjson"
    export.main(["splunk", str(out), "--source-file", "events.jsonl", "--output", str(body_path)])

    lines = [json.loads(line) for line in body_path.read_text(encoding="utf-8").splitlines()]
    assert len(lines) == 23
    # events.jsonl rows use the internal schema, not the OCSF one.
    assert "parse.status" in lines[0]["event"]
