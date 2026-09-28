from __future__ import annotations

import importlib
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from ulpf.detect import detect, parsers_for
from ulpf.schema import finalize_event, raw_hash

PACKAGE_DIR = Path(__file__).resolve().parent


def _load_mappings() -> dict[str, dict[str, Any]]:
    importlib.import_module("ulpf.parsers")
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


def run(input_dir: str | Path, output_dir: str | Path) -> None:
    source = Path(input_dir)
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    mappings = _load_mappings()
    raw_path = destination / "raw.jsonl"
    events_path = destination / "events.jsonl"

    with raw_path.open("w", encoding="utf-8") as raw_out, events_path.open(
        "w", encoding="utf-8"
    ) as events_out:
        for source_file in _iter_input_files(source):
            for line in source_file.read_text(encoding="utf-8").splitlines():
                raw_text = line
                if raw_text == "":
                    continue
                raw_event_id = str(uuid.uuid4())
                digest = raw_hash(raw_text)
                ingest_time = datetime.now(timezone.utc).isoformat()
                raw_record = {
                    "raw_event_id": raw_event_id,
                    "raw_text": raw_text,
                    "raw_hash": digest,
                    "source_file": source_file.name,
                    "ingest_time": ingest_time,
                }
                raw_out.write(json.dumps(raw_record, ensure_ascii=False) + "\n")

                parsed = None
                mapping_version = ""
                for parse in parsers_for(detect(raw_text)):
                    mapping = _mapping_for(parse, mappings)
                    parsed = parse(raw_text, mapping)
                    if parsed is not None:
                        mapping_version = str(mapping.get("mapping_version") or "")
                        break

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

                events_out.write(json.dumps(event, ensure_ascii=False) + "\n")


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        sys.stderr.write("usage: python -m ulpf.pipeline <input_dir> <output_dir>\n")
        sys.exit(2)
    run(args[0], args[1])


if __name__ == "__main__":
    main()
