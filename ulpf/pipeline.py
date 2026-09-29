from __future__ import annotations

import base64
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from ulpf import detect as detect_mod
from ulpf import quality as quality_mod
from ulpf.detect import detect_format, parsers_for
from ulpf.ocsf import to_ocsf
from ulpf.parsers import generic as generic_parser
from ulpf.parsers import register_all
from ulpf.schema import finalize_event, raw_hash_bytes

PACKAGE_DIR = Path(__file__).resolve().parent


def load_mappings() -> dict[str, dict[str, Any]]:
    """Register every parser module and load its YAML mapping.

    Public because both file-based ingestion (`run`, below) and live
    network ingestion (`ulpf.ingest`) need it to call `process_record`.
    """
    register_all(detect_mod)
    mappings: dict[str, dict[str, Any]] = {}
    mappings_dir = PACKAGE_DIR / "mappings"
    for mapping_path in mappings_dir.glob("*.yaml"):
        mappings[mapping_path.stem] = yaml.safe_load(mapping_path.read_text(encoding="utf-8")) or {}
    return mappings


def _mapping_for(parse: Callable[..., Any], mappings: dict[str, dict[str, Any]]) -> dict[str, Any]:
    stem = parse.__module__.rsplit(".", 1)[-1]
    return mappings.get(stem, {})


def _iter_input_files(input_dir: Path) -> Iterable[Path]:
    for path in sorted(input_dir.iterdir()):
        if path.is_file():
            yield path


def _iter_records(path: Path) -> Iterable[tuple[str, bytes, bool]]:
    """Yield (raw_text, raw_bytes, is_lossy) logical records for one file.

    A physical line starting with a space or tab is a continuation of the
    previous record (multiline records, e.g. a stack trace under a log
    line) and is joined onto it with "\\n". Bytes that are not valid UTF-8
    are decoded with errors="replace"; `is_lossy` flags that so the caller
    can keep the exact original bytes separately (raw_bytes_b64) since the
    decoded raw_text lost information.
    """
    data = path.read_bytes()
    groups: list[list[bytes]] = []
    for physical in data.split(b"\n"):
        if physical.endswith(b"\r"):
            physical = physical[:-1]
        if physical == b"":
            continue
        if physical[:1] in (b" ", b"\t") and groups:
            groups[-1].append(physical)
        else:
            groups.append([physical])

    for parts in groups:
        raw_bytes = b"\n".join(parts)
        try:
            text = raw_bytes.decode("utf-8")
            lossy = False
        except UnicodeDecodeError:
            text = raw_bytes.decode("utf-8", errors="replace")
            lossy = True
        yield text, raw_bytes, lossy


def _failed_event(raw_text: str, raw_event_id: str, digest: str, ingest_time: str) -> dict[str, Any]:
    event = finalize_event(
        {
            "event_id": raw_event_id,
            "parse.status": "failed",
            "parse.confidence": 0,
            "provenance.raw_event_id": raw_event_id,
            "provenance.raw_text": raw_text,
            "provenance.raw_hash": digest,
            "provenance.ingest_time": ingest_time,
        }
    )
    return event


def process_record(
    raw_text: str,
    raw_bytes: bytes,
    is_lossy: bool,
    source_label: str,
    mappings: dict[str, dict[str, Any]],
    ingest_time: str | None = None,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    """Run one logical record through detect -> parse -> finalize -> OCSF.

    Shared by both file-based ingestion (`run`, below - one record per input
    line) and live network ingestion (`ulpf.ingest` - one record per
    received syslog message), so both paths produce identically-shaped
    output through the same parser registry and generic fallback. Returns
    (raw_record, event, ocsf_event); the caller writes/appends them.
    `source_label` becomes `raw_record["source_file"]` - a filename for
    file-based ingestion, a `"host:port"` sender address for network ingestion.
    """
    raw_event_id = str(uuid.uuid4())
    digest = raw_hash_bytes(raw_bytes)
    ingest_time = ingest_time or datetime.now(timezone.utc).isoformat()
    raw_record = {
        "raw_event_id": raw_event_id,
        "raw_text": raw_text,
        "raw_hash": digest,
        "raw_text_lossy": is_lossy,
        "raw_bytes_b64": base64.b64encode(raw_bytes).decode("ascii") if is_lossy else "",
        "source_file": source_label,
        "ingest_time": ingest_time,
    }

    detection = detect_format(raw_text)
    parsed = None
    mapping_version = ""
    for parse in parsers_for(detection.format):
        mapping = _mapping_for(parse, mappings)
        parsed = parse(raw_text, mapping)
        if parsed is not None:
            mapping_version = str(mapping.get("mapping_version") or "")
            break

    if parsed is None:
        parsed = generic_parser.parse(raw_text, {"hints": detection.hints})
        if parsed is not None:
            mapping_version = "generic"

    if parsed is None:
        event = _failed_event(raw_text, raw_event_id, digest, ingest_time)
    else:
        parsed["event_id"] = raw_event_id
        parsed["provenance.raw_event_id"] = raw_event_id
        parsed["provenance.raw_text"] = raw_text
        parsed["provenance.raw_hash"] = digest
        parsed["provenance.mapping_version"] = mapping_version
        parsed["provenance.ingest_time"] = ingest_time
        event = finalize_event(parsed)

    ocsf_event = to_ocsf(event)
    return raw_record, event, ocsf_event


def run(input_dir: str | Path, output_dir: str | Path) -> None:
    source = Path(input_dir)
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    mappings = load_mappings()
    raw_path = destination / "raw.jsonl"
    events_path = destination / "events.jsonl"
    ocsf_path = destination / "ocsf.jsonl"
    quality_path = destination / "quality.json"
    quality_records: list[tuple[str, str, str, dict[str, Any], dict[str, Any]]] = []

    with raw_path.open("w", encoding="utf-8") as raw_out, events_path.open(
        "w", encoding="utf-8"
    ) as events_out, ocsf_path.open("w", encoding="utf-8") as ocsf_out:
        for source_file in _iter_input_files(source):
            for raw_text, raw_bytes, is_lossy in _iter_records(source_file):
                raw_record, event, ocsf_event = process_record(
                    raw_text, raw_bytes, is_lossy, source_file.name, mappings
                )
                raw_out.write(json.dumps(raw_record, ensure_ascii=False) + "\n")
                events_out.write(json.dumps(event, ensure_ascii=False) + "\n")
                ocsf_out.write(json.dumps(ocsf_event, ensure_ascii=False) + "\n")
                quality_records.append(
                    (
                        str(event.get("observer.vendor") or ""),
                        source_file.name,
                        str(event.get("parse.status") or ""),
                        ocsf_event,
                        event.get("unmapped") or {},
                    )
                )

    quality_report = quality_mod.build_report(quality_records)
    quality_path.write_text(json.dumps(quality_report, indent=2, ensure_ascii=False), encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        sys.stderr.write("usage: python -m ulpf.pipeline <input_dir> <output_dir>\n")
        sys.exit(2)
    run(args[0], args[1])


if __name__ == "__main__":
    main()
