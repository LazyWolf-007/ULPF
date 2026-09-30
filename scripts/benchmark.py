#!/usr/bin/env python
"""Benchmark ulpf.pipeline throughput.

Runs the pipeline on demo_data/bulk.log repeated out to ~100k lines in a
temp dir, and prints events/sec for a single worker. With --workers N (N>1)
it also *attempts* an N-process run and prints a comparison row - but only
if that can be done without changing what the pipeline produces (see
"Multi-worker strategy" below). If that attempt fails for any reason, it's
caught, reported plainly, and the script still prints the single-worker
result rather than failing outright.

Multi-worker strategy (does not modify ulpf/pipeline.py at all):
`ulpf.pipeline.process_record` is a pure per-line function - no state is
shared across lines within one `run()` call - so splitting the repeated
input into N contiguous chunks and running N independent
`ulpf.pipeline.run()` calls (one per process, each against its own chunk +
its own temp output dir) produces the same per-event field values a single
sequential run would (modulo the randomly-generated `event_id`/
`raw_event_id` UUIDs and wall-clock `provenance.ingest_time`, which already
differ between *any* two pipeline runs, single- or multi-worker). The N
workers' raw.jsonl/events.jsonl/ocsf.jsonl are concatenated in chunk order
afterward (preserving the original line order), and quality.json is
recomputed once on the merged data via the same public
`ulpf.quality.build_report` function `pipeline.run` itself calls - not
re-derived some other way - so the merged output is the same *shape* and
computed the same way a single run's would be.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
if str(ROOT) not in sys.path:
    # Runnable directly (`python scripts/benchmark.py`) regardless of CWD -
    # a plain script run doesn't put the project root on sys.path the way
    # `python -m ulpf.xxx` does.
    sys.path.insert(0, str(ROOT))

from ulpf.pipeline import run as pipeline_run  # noqa: E402
from ulpf.quality import build_report  # noqa: E402

DEFAULT_BULK_LOG = ROOT / "demo_data" / "bulk.log"
DEFAULT_TARGET_LINES = 100_000


def _repeat_to_target(source_lines: list[str], target: int) -> list[str]:
    if not source_lines:
        raise ValueError("source file has no lines to repeat")
    repeats = -(-target // len(source_lines))  # ceil division
    return (source_lines * repeats)[:target]


def _count_events(output_dir: Path) -> int:
    events_path = output_dir / "events.jsonl"
    if not events_path.is_file():
        return 0
    return sum(1 for _ in events_path.open("r", encoding="utf-8"))


def _run_single(input_dir: Path, output_dir: Path) -> tuple[float, int]:
    start = time.perf_counter()
    pipeline_run(input_dir, output_dir)
    elapsed = time.perf_counter() - start
    return elapsed, _count_events(output_dir)


def _split_into_chunks(lines: list[str], n: int) -> list[list[str]]:
    chunk_size = -(-len(lines) // n)  # ceil division
    chunks = [lines[i : i + chunk_size] for i in range(0, len(lines), chunk_size)]
    return chunks


def _worker_entrypoint(input_dir: str, output_dir: str) -> None:
    """Top-level (picklable) target for a worker process: run the pipeline
    on one chunk. No return value crosses the process boundary - the
    parent reads the chunk's output files back from disk after `join()`,
    same as it would read any other pipeline output."""
    pipeline_run(input_dir, output_dir)


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _merge_worker_outputs(worker_output_dirs: list[Path], merged_dir: Path) -> int:
    merged_dir.mkdir(parents=True, exist_ok=True)
    quality_records: list[tuple[str, str, str, dict[str, Any], dict[str, Any]]] = []
    total = 0

    with (merged_dir / "raw.jsonl").open("w", encoding="utf-8") as raw_out, (
        merged_dir / "events.jsonl"
    ).open("w", encoding="utf-8") as events_out, (merged_dir / "ocsf.jsonl").open(
        "w", encoding="utf-8"
    ) as ocsf_out:
        for worker_dir in worker_output_dirs:
            raw_rows = _load_jsonl(worker_dir / "raw.jsonl")
            event_rows = _load_jsonl(worker_dir / "events.jsonl")
            ocsf_rows = _load_jsonl(worker_dir / "ocsf.jsonl")
            if not (len(raw_rows) == len(event_rows) == len(ocsf_rows)):
                raise RuntimeError(f"worker output row-count mismatch under {worker_dir}")
            for raw_row, event_row, ocsf_row in zip(raw_rows, event_rows, ocsf_rows):
                raw_out.write(json.dumps(raw_row, ensure_ascii=False) + "\n")
                events_out.write(json.dumps(event_row, ensure_ascii=False) + "\n")
                ocsf_out.write(json.dumps(ocsf_row, ensure_ascii=False) + "\n")
                total += 1
                quality_records.append(
                    (
                        str(event_row.get("observer.vendor") or ""),
                        str(raw_row.get("source_file") or ""),
                        str(event_row.get("parse.status") or ""),
                        ocsf_row,
                        event_row.get("unmapped") or {},
                    )
                )

    report = build_report(quality_records)
    (merged_dir / "quality.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return total


def _run_multi(lines: list[str], workers: int, tmp_root: Path) -> tuple[float, int]:
    chunks = _split_into_chunks(lines, workers)
    worker_args: list[tuple[str, str]] = []
    worker_output_dirs: list[Path] = []
    for i, chunk in enumerate(chunks):
        input_dir = tmp_root / f"worker_{i}_in"
        output_dir = tmp_root / f"worker_{i}_out"
        input_dir.mkdir(parents=True, exist_ok=True)
        (input_dir / "chunk.log").write_text("\n".join(chunk) + "\n", encoding="utf-8")
        worker_args.append((str(input_dir), str(output_dir)))
        worker_output_dirs.append(output_dir)

    start = time.perf_counter()
    ctx = multiprocessing.get_context("spawn")
    with ctx.Pool(processes=len(chunks)) as pool:
        pool.starmap(_worker_entrypoint, worker_args)
    elapsed = time.perf_counter() - start

    merged_dir = tmp_root / "merged_out"
    total = _merge_worker_outputs(worker_output_dirs, merged_dir)
    return elapsed, total


def _print_table(rows: list[dict[str, Any]]) -> None:
    headers = ["workers", "events", "seconds", "events/sec", "speedup"]
    widths = [max(len(h), 10) for h in headers]
    print(" | ".join(h.ljust(w) for h, w in zip(headers, widths)))
    print("-+-".join("-" * w for w in widths))
    for row in rows:
        cells = [
            str(row["workers"]),
            str(row["events"]),
            f"{row['seconds']:.3f}",
            f"{row['events_per_sec']:,.0f}",
            row.get("speedup", "-"),
        ]
        print(" | ".join(c.ljust(w) for c, w in zip(cells, widths)))


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="scripts/benchmark.py")
    parser.add_argument("--bulk-log", default=str(DEFAULT_BULK_LOG))
    parser.add_argument("--target-lines", type=int, default=DEFAULT_TARGET_LINES)
    parser.add_argument("--workers", type=int, default=None, help="also attempt an N-process run")
    parser.add_argument("--tmp-dir", default=None, help="default: a fresh temp dir under the system tmp")
    args = parser.parse_args(argv)

    bulk_log_path = Path(args.bulk_log)
    if not bulk_log_path.is_file():
        parser.error(f"{bulk_log_path} not found - run scripts/gen_demo_data.py first")

    source_lines = [line for line in bulk_log_path.read_text(encoding="utf-8").splitlines() if line]
    lines = _repeat_to_target(source_lines, args.target_lines)
    print(f"benchmark input: {len(lines)} lines (repeated from {len(source_lines)}-line {bulk_log_path})")

    tmp_root = Path(args.tmp_dir) if args.tmp_dir else Path(tempfile.mkdtemp(prefix="ulpf_benchmark_"))
    tmp_root.mkdir(parents=True, exist_ok=True)

    single_input_dir = tmp_root / "single_in"
    single_output_dir = tmp_root / "single_out"
    single_input_dir.mkdir(parents=True, exist_ok=True)
    (single_input_dir / "bulk.log").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print("running single-worker pass...")
    single_seconds, single_events = _run_single(single_input_dir, single_output_dir)
    single_rate = single_events / single_seconds if single_seconds > 0 else 0.0
    rows = [
        {
            "workers": 1,
            "events": single_events,
            "seconds": single_seconds,
            "events_per_sec": single_rate,
            "speedup": "1.00x",
        }
    ]

    if args.workers and args.workers > 1:
        print(f"attempting {args.workers}-worker pass...")
        try:
            multi_seconds, multi_events = _run_multi(lines, args.workers, tmp_root / "multi")
            if multi_events != single_events:
                raise RuntimeError(
                    f"multi-worker produced {multi_events} events, single-worker produced "
                    f"{single_events} - output would not match, refusing to report it"
                )
            multi_rate = multi_events / multi_seconds if multi_seconds > 0 else 0.0
            speedup = f"{multi_rate / single_rate:.2f}x" if single_rate else "-"
            rows.append(
                {
                    "workers": args.workers,
                    "events": multi_events,
                    "seconds": multi_seconds,
                    "events_per_sec": multi_rate,
                    "speedup": speedup,
                }
            )
        except Exception as exc:  # noqa: BLE001 - deliberately broad: any failure here
            # must fall back to reporting single-worker only, never crash the
            # whole benchmark over the optional multi-worker path.
            print(
                f"\nmulti-worker benchmark not usable ({exc!r}); "
                "reporting single-worker results only.\n"
            )

    print()
    _print_table(rows)


if __name__ == "__main__":
    main()
