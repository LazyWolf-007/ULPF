from __future__ import annotations

import json
from pathlib import Path

from ulpf import quality
from ulpf.pipeline import run

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def _run(tmp_path: Path) -> dict:
    out = tmp_path / "out"
    run(SAMPLES, out)
    return json.loads((out / "quality.json").read_text(encoding="utf-8"))


def test_quality_json_written_with_expected_shape(tmp_path: Path) -> None:
    report = _run(tmp_path)
    assert set(report.keys()) == {"generated_at", "overall", "sources"}
    assert report["overall"]["total_events"] == 23

    # Every group's total_events must sum back to the overall total - the
    # grouping (vendor-or-source-file) must partition every event exactly
    # once, never double-count or drop one.
    assert sum(group["total_events"] for group in report["sources"].values()) == 23

    for group in report["sources"].values():
        total = group["total_events"]
        assert total > 0
        # parsed/partial/failed percentages are of the same total and must
        # not exceed 100 individually; together they should reconstruct it
        # (within rounding) since every event is exactly one of the three.
        pct_sum = group["parsed_pct"] + group["partial_pct"] + group["failed_pct"]
        assert 99.9 <= pct_sum <= 100.1
        assert 0.0 <= group["ocsf_core_fields_populated_pct"] <= 100.0


def test_quality_groups_by_vendor_or_source_file_when_vendor_missing(tmp_path: Path) -> None:
    report = _run(tmp_path)
    sources = report["sources"]

    # Vendors that set observer.vendor group under the vendor name.
    assert sources["Fortinet"]["total_events"] == 2
    assert sources["Fortinet"]["parsed_pct"] == 100.0

    # The original garbage Cisco line has no vendor (failed to parse) and
    # groups under its source file instead.
    assert sources["cisco.log"]["total_events"] == 1
    assert sources["cisco.log"]["failed_pct"] == 100.0

    # messy.log's vendor-less generic/failed records all group there too.
    assert sources["messy.log"]["total_events"] == 11
    assert sources["messy.log"]["partial_pct"] > 0


def test_quality_top_unmapped_keys_surface_unmapped_cef_fields(tmp_path: Path) -> None:
    report = _run(tmp_path)
    zscaler = report["sources"]["Zscaler"]
    keys = {entry["key"] for entry in zscaler["top_unmapped_keys"]}
    # cef.yaml's field map only knows src/dst/spt/dpt/proto/act - "sip"/"dip"
    # (used by the messy Zscaler line instead of src/dst) must show up as
    # unmapped, which is exactly the signal this report exists to surface.
    assert {"sip", "dip"}.issubset(keys)


def test_build_report_handles_empty_input_without_division_errors() -> None:
    report = quality.build_report([])
    assert report["overall"]["total_events"] == 0
    assert report["overall"]["parsed_pct"] == 0.0
    assert report["overall"]["ocsf_core_fields_populated_pct"] == 0.0
    assert report["sources"] == {}


def test_build_report_core_field_check_is_defensive_to_missing_keys() -> None:
    # A malformed/partial ocsf_event (missing nested keys entirely) must not
    # raise - it just counts as "not populated" for whichever field is absent.
    report = quality.build_report([("Vendor", "file.log", "ok", {}, {})])
    group = report["sources"]["Vendor"]
    assert group["ocsf_core_fields_populated_pct"] == 0.0
