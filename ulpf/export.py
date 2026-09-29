"""Export pipeline output to external analytics/SIEM formats.

Reads `out/ocsf.jsonl` by default (the OCSF-aligned, analytics-ready shape
that `ulpf.ocsf` produces - see SPEC.md) and reshapes it for a specific
downstream sink. Each `to_*` function is a pure transform (list of event
dicts in, sink-shaped text/file out) so it can be tested and reused without
a network call - nothing here makes one; writing the exported body to
OpenSearch/Splunk/wherever is left to the operator, per ULPF's air-gap rule.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


def _doc_id(event: dict[str, Any]) -> str | None:
    metadata = event.get("metadata")
    if isinstance(metadata, dict) and metadata.get("raw_event_id"):
        return str(metadata["raw_event_id"])
    if event.get("event_id"):
        return str(event["event_id"])
    return None


def to_opensearch_bulk(events: list[dict[str, Any]], index: str = "ulpf-events") -> str:
    """NDJSON body for OpenSearch/Elasticsearch's `_bulk` API.

    One action line + one source line per event, per the bulk format. Uses
    `metadata.raw_event_id` (OCSF events) or `event_id` (internal events)
    as the document `_id` when present, so re-indexing the same export is
    idempotent instead of creating duplicates.
    """
    lines: list[str] = []
    for event in events:
        action: dict[str, Any] = {"index": {"_index": index}}
        doc_id = _doc_id(event)
        if doc_id:
            action["index"]["_id"] = doc_id
        lines.append(json.dumps(action, ensure_ascii=False))
        lines.append(json.dumps(event, ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")


def to_splunk_hec(
    events: list[dict[str, Any]],
    source: str = "ulpf",
    sourcetype: str = "ulpf:ocsf",
    index: str | None = None,
) -> str:
    """NDJSON body for Splunk's HTTP Event Collector (`/services/collector`).

    Each line wraps one event as `{"event": ..., "time": ..., "source":
    ..., "sourcetype": ...}`. `time` (epoch seconds, as HEC expects) is
    taken from the OCSF `time` field (epoch milliseconds) when it's
    present and positive; otherwise it's omitted and Splunk assigns
    current time on ingest.
    """
    lines: list[str] = []
    for event in events:
        wrapper: dict[str, Any] = {"event": event, "source": source, "sourcetype": sourcetype}
        if index:
            wrapper["index"] = index
        time_ms = event.get("time")
        if isinstance(time_ms, int) and time_ms > 0:
            wrapper["time"] = time_ms / 1000
        lines.append(json.dumps(wrapper, ensure_ascii=False))
    return "\n".join(lines) + ("\n" if lines else "")


def _null_out_empty_strings(value: Any) -> Any:
    """Recursively turn "" into None.

    Both `ulpf.schema` and `ulpf.ocsf` use "" as the universal "unset"
    sentinel, including on fields that are otherwise numeric (e.g. an OCSF
    endpoint's `port` is an int when known, "" when not - see ocsf.py's
    `_endpoint`). Arrow/Parquet is a typed columnar format and can't infer
    one column type spanning both int and str, so without this, exporting
    real pipeline output raises `ArrowInvalid`. "" already *means* "no
    value" in this schema, so mapping it to a true null is a faithful
    transformation, not a workaround.
    """
    if isinstance(value, dict):
        return {key: _null_out_empty_strings(v) for key, v in value.items()}
    if isinstance(value, list):
        return [_null_out_empty_strings(v) for v in value]
    if value == "":
        return None
    return value


def to_parquet(events: list[dict[str, Any]], path: str | Path) -> None:
    """Write events to a Parquet file.

    Requires the optional `pyarrow` dependency (deliberately not in
    requirements.txt - ULPF keeps its core dependency list minimal, and
    most deployments won't need Parquet export). Install it with
    `pip install pyarrow` to use this.
    """
    try:
        import pyarrow as pa
        import pyarrow.parquet as pq
    except ImportError as exc:
        raise RuntimeError(
            "to_parquet requires the optional 'pyarrow' package; install it with "
            "`pip install pyarrow`."
        ) from exc

    normalized = [_null_out_empty_strings(event) for event in events]
    table = pa.Table.from_pylist(normalized)
    pq.write_table(table, str(path))


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _write_output(body: str, output_path: str | None) -> None:
    if output_path is None:
        sys.stdout.write(body)
    else:
        Path(output_path).write_text(body, encoding="utf-8")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="ulpf.export")
    parser.add_argument("format", choices=["opensearch", "splunk", "parquet"])
    parser.add_argument("out_dir", help="pipeline output directory (contains ocsf.jsonl)")
    parser.add_argument(
        "--source-file",
        default="ocsf.jsonl",
        help="which .jsonl file under out_dir to export (default: ocsf.jsonl)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="write to this path instead of stdout (parquet always writes to a file: "
        "out_dir/export.parquet if --output is omitted)",
    )
    parser.add_argument("--index", default="ulpf-events", help="OpenSearch/Splunk index name")
    parser.add_argument("--splunk-source", default="ulpf")
    parser.add_argument("--splunk-sourcetype", default="ulpf:ocsf")
    args = parser.parse_args(argv)

    events_path = Path(args.out_dir) / args.source_file
    events = _load_jsonl(events_path)

    if args.format == "opensearch":
        _write_output(to_opensearch_bulk(events, index=args.index), args.output)
    elif args.format == "splunk":
        body = to_splunk_hec(
            events, source=args.splunk_source, sourcetype=args.splunk_sourcetype, index=args.index
        )
        _write_output(body, args.output)
    elif args.format == "parquet":
        output_path = Path(args.output) if args.output else Path(args.out_dir) / "export.parquet"
        to_parquet(events, output_path)
        print(f"wrote {len(events)} events to {output_path}")


if __name__ == "__main__":
    main()
