"""Per-source/vendor data-quality report (`out/quality.json`).

For each group — the vendor when `observer.vendor` is known, otherwise the
raw source file name (so failed/vendor-less generic parses still land in a
readable bucket) — reports how much of the group parsed cleanly, how much
of it survives into OCSF's core analytics fields, and which vendor-specific
fields most often end up in `unmapped` (a signal that a mapping is missing
a field). This module only aggregates data the pipeline already computed;
it does not re-parse or re-derive anything.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

# OCSF fields that matter most for cross-source analytics (joins, filters,
# dashboards) — deliberately excludes fields that are constant for every
# event regardless of parse quality (class_uid, category_uid, metadata.*).
CORE_FIELD_PATHS: tuple[tuple[str, ...], ...] = (
    ("time",),
    ("src_endpoint", "ip"),
    ("dst_endpoint", "ip"),
    ("connection_info", "protocol_name"),
    ("action",),
    ("disposition",),
)


def _core_field_populated(ocsf_event: dict[str, Any], path: tuple[str, ...]) -> bool:
    value: Any = ocsf_event
    for part in path:
        if not isinstance(value, dict) or part not in value:
            return False
        value = value[part]
    if path[-1] == "time":
        return isinstance(value, int) and value > 0
    if path[-1] == "disposition":
        return value not in ("", "Unknown", None)
    return bool(value)


def _percent(count: int, total: int) -> float:
    return round((count / total) * 100, 2) if total else 0.0


class _GroupAccumulator:
    def __init__(self) -> None:
        self.total = 0
        self.ok = 0
        self.partial = 0
        self.failed = 0
        self.core_populated = 0
        self.core_possible = 0
        self.unmapped_keys: Counter[str] = Counter()

    def add(self, status: str, ocsf_event: dict[str, Any], unmapped: dict[str, Any]) -> None:
        self.total += 1
        if status == "ok":
            self.ok += 1
        elif status == "partial":
            self.partial += 1
        elif status == "failed":
            self.failed += 1
        for path in CORE_FIELD_PATHS:
            self.core_possible += 1
            if _core_field_populated(ocsf_event, path):
                self.core_populated += 1
        # Counter.update(mapping) would add the *values* as counts (and our
        # unmapped values are arbitrary strings, not ints) - tally key names
        # by updating from an iterable of keys instead.
        self.unmapped_keys.update((unmapped or {}).keys())

    def to_dict(self, top_n: int) -> dict[str, Any]:
        return {
            "total_events": self.total,
            "parsed_pct": _percent(self.ok, self.total),
            "partial_pct": _percent(self.partial, self.total),
            "failed_pct": _percent(self.failed, self.total),
            "ocsf_core_fields_populated_pct": _percent(self.core_populated, self.core_possible),
            "top_unmapped_keys": [
                {"key": key, "count": count} for key, count in self.unmapped_keys.most_common(top_n)
            ],
        }


def _group_key(vendor: str, source_file: str) -> str:
    return vendor or source_file


def build_report(
    records: list[tuple[str, str, str, dict[str, Any], dict[str, Any]]],
    top_n: int = 5,
) -> dict[str, Any]:
    """Build the quality report from accumulated per-event data.

    `records` is a list of (vendor, source_file, parse_status, ocsf_event,
    unmapped) tuples, one per event, in pipeline processing order.
    """
    overall = _GroupAccumulator()
    groups: dict[str, _GroupAccumulator] = {}

    for vendor, source_file, status, ocsf_event, unmapped in records:
        overall.add(status, ocsf_event, unmapped)
        groups.setdefault(_group_key(vendor, source_file), _GroupAccumulator()).add(
            status, ocsf_event, unmapped
        )

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "overall": overall.to_dict(top_n),
        "sources": {key: group.to_dict(top_n) for key, group in sorted(groups.items())},
    }
