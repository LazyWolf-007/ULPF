"""Integrity verification for a pipeline output directory.

Two independent checks, so tampering can't hide by only fixing one file:

1. Every `raw.jsonl` row's stored `raw_hash` must match a hash recomputed
   from the exact original bytes (`raw_bytes_b64` for a row whose decode was
   lossy, `raw_text` re-encoded as UTF-8 otherwise — matching how
   `ulpf.pipeline` computed it in the first place).
2. Every `events.jsonl` row's `provenance.raw_event_id` must exist in
   `raw.jsonl`, and its `provenance.raw_hash` must match that raw row's
   `raw_hash` — catching a raw.jsonl edit that recomputes its own hash
   consistently (so check 1 passes) but no longer matches what the event
   recorded at parse time.
"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Mismatch:
    kind: str  # "raw_hash_mismatch" | "missing_raw_id" | "event_hash_mismatch"
    raw_event_id: str
    detail: str

    def to_dict(self) -> dict[str, str]:
        return {"kind": self.kind, "raw_event_id": self.raw_event_id, "detail": self.detail}


@dataclass
class VerifyReport:
    raw_count: int
    event_count: int
    mismatches: list[Mismatch] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.mismatches

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "raw_count": self.raw_count,
            "event_count": self.event_count,
            "mismatch_count": len(self.mismatches),
            "mismatches": [mismatch.to_dict() for mismatch in self.mismatches],
        }


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _recompute_raw_hash(record: dict[str, Any]) -> str:
    if record.get("raw_text_lossy"):
        original_bytes = base64.b64decode(record.get("raw_bytes_b64") or "")
    else:
        original_bytes = str(record.get("raw_text", "")).encode("utf-8")
    return hashlib.sha256(original_bytes).hexdigest()


def verify(output_dir: str | Path) -> VerifyReport:
    destination = Path(output_dir)
    raw_records = _load_jsonl(destination / "raw.jsonl")
    event_records = _load_jsonl(destination / "events.jsonl")

    mismatches: list[Mismatch] = []
    raw_by_id: dict[str, dict[str, Any]] = {}

    for record in raw_records:
        raw_id = str(record.get("raw_event_id", ""))
        raw_by_id[raw_id] = record
        recomputed = _recompute_raw_hash(record)
        stored = str(record.get("raw_hash", ""))
        if recomputed != stored:
            mismatches.append(
                Mismatch(
                    kind="raw_hash_mismatch",
                    raw_event_id=raw_id,
                    detail=f"stored raw_hash {stored!r} != recomputed {recomputed!r}",
                )
            )

    for event in event_records:
        raw_id = str(event.get("provenance.raw_event_id", ""))
        raw_record = raw_by_id.get(raw_id)
        if raw_record is None:
            mismatches.append(
                Mismatch(
                    kind="missing_raw_id",
                    raw_event_id=raw_id,
                    detail="event references a raw_event_id not present in raw.jsonl",
                )
            )
            continue
        event_hash = str(event.get("provenance.raw_hash", ""))
        raw_hash = str(raw_record.get("raw_hash", ""))
        if event_hash != raw_hash:
            mismatches.append(
                Mismatch(
                    kind="event_hash_mismatch",
                    raw_event_id=raw_id,
                    detail=f"event provenance.raw_hash {event_hash!r} != raw.jsonl raw_hash {raw_hash!r}",
                )
            )

    return VerifyReport(raw_count=len(raw_records), event_count=len(event_records), mismatches=mismatches)


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        sys.stderr.write("usage: python -m ulpf.verify <output_dir>\n")
        sys.exit(2)
    report = verify(args[0])
    print(json.dumps(report.to_dict(), indent=2))
    sys.exit(0 if report.ok else 1)


if __name__ == "__main__":
    main()
