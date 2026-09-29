# ULPF architecture

ULPF is a local log pre-processor. It reads plain-text log files from a folder, keeps every input line unchanged, and writes two JSON Lines outputs: a raw vault and a shared event record per line. Nothing in the core path calls external services; parsing and mapping run entirely on the machine where you invoke the pipeline.

## Ingest

The pipeline walks every file in an input directory (for example `samples/`). Each non-empty line becomes one logical event. It assigns a unique event id, computes a SHA-256 hash of the exact line bytes, stamps ingest time, and appends one row to `raw.jsonl`. The original text is never altered in that vault row.

## Detect

Before parsing, each line is classified by format using simple rules in `detect.py`: CEF prefix, JSON object, syslog priority prefix, key=value pairs, or unknown. Detection does not name vendors; it only chooses which registered parsers may run. First matching format wins for routing.

## Parse and map

Parser modules live under `ulpf/parsers/`. Each module exposes `parse(line, mapping)` and `register(registry)` so the pipeline can discover handlers without importing vendors by name. YAML files under `ulpf/mappings/` supply defaults, field renames, protocol tables, and action-to-outcome rules. A parser returns a partial event dict or `None` if the line is not its dialect. The pipeline tries registered parsers for the detected format until one succeeds.

## Raw vault

`raw.jsonl` stores provenance-oriented rows: raw event id, raw text, raw hash, source file name, and ingest time. Analysts and auditors can reconcile shared events back to the exact source line using this file.

## Shared record

`events.jsonl` stores one normalized record per input line using a fixed key set (observer, network, user, event, parse, provenance, unmapped). Successful parses fill vendor-specific fields; failed parses still emit a row with `parse.status` failed and empty network fields where appropriate. Outcomes are limited to success, failure, or unknown. `finalize_event` in `schema.py` ensures every row has the same shape.

## Local page

`ulpf/app.py` serves a read-only HTML view over an existing `events.jsonl` using the standard library HTTP server on `127.0.0.1` and a free port. It loads the file, computes summary counts and busiest source IPs in Python, and renders a filterable table. Row clicks show `provenance.raw_text` and `provenance.raw_hash`. Optional `--rebuild` re-runs the pipeline before serving; otherwise the page does not re-parse.

## What this prototype does not run

This repository does not run Kafka, Flink, OpenSearch, or a cluster. Those are how the same ingest → detect → parse → map flow would be hosted at scale later (streaming ingest, stateful enrichment, search, and horizontal workers). The parser interface—register a handler, ship a YAML mapping, drop samples, re-run the pipeline—would stay the same; only deployment and storage backends would change.

## Traceability

Every event carries a stable `event_id` for the processing run, a SHA-256 `provenance.raw_hash` of the original line, and the full `provenance.raw_text` copied verbatim. Failed lines are never dropped: they appear in both `raw.jsonl` and `events.jsonl` with `parse.status` failed so reviewers can see garbage, typos, and unsupported formats alongside successful parses.
