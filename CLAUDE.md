# CLAUDE.md

Guidance for any agent (Claude Code or otherwise) working in this repo.

## What this is

ULPF (Universal Log Pre-processing Framework) — SIH26156 (NTRO). Turns perimeter
network logs (firewalls, IDS sensors, Linux hosts) into lossless, OCSF-aligned,
analytics-ready JSON events. See `README.md` for usage and `ARCHITECTURE.md` for
the ingest → detect → parse → map → serve flow.

## Hard rules

- **Never break existing pipeline behaviour or tests.** Run `python -m pytest tests/ -v`
  after every change, before considering a task done.
- **Air-gapped.** No outbound network calls, no cloud APIs. The only listener is the
  local viewer (`ulpf/app.py`), bound to `127.0.0.1`.
- **No vendor names in `ulpf/pipeline.py`.** Vendor/device discovery goes only through
  the parser registry (`register(registry)` in each `ulpf/parsers/*.py`) and the YAML
  mappings in `ulpf/mappings/`. `pipeline.py` stays vendor-agnostic.
- **Raw text is sacred.** Never modify `raw_text`. Every normalized event in
  `events.jsonl` links back to `raw_id` and `raw_hash` in `raw.jsonl`.
- **Failed parses still produce a record.** A line that doesn't parse gets a row with
  `parse.status = "failed"` and provenance filled in — never silently dropped.
- **Keep code simple, typed, and commented.** Minimal dependencies — anything new goes
  in `requirements.txt` (currently just PyYAML and pytest).

## Repo layout

- `ulpf/pipeline.py` — orchestrates ingest → detect → parse → map, vendor-agnostic.
- `ulpf/detect.py` — classifies each line's format (CEF, JSON, syslog, kv, unknown);
  never names vendors, only picks which registered parsers may run.
- `ulpf/parsers/<name>.py` — one module per device/dialect. Exposes `parse(line, mapping)`
  (returns a partial event dict or `None`) and `register(registry)`.
- `ulpf/mappings/<name>.yaml` — defaults, field renames, protocol tables, action→outcome
  rules for a parser.
- `ulpf/schema.py` — `finalize_event` guarantees every output row has the same shape
  (observer, network, user, event, parse, provenance, unmapped).
- `ulpf/app.py` — read-only local HTML viewer over `events.jsonl`, stdlib HTTP server
  on `127.0.0.1`, optional `--rebuild` to re-run the pipeline first.
- `samples/` — one sample log file per device type, used by tests and manual checks.
- `tests/test_pipeline.py`, `tests/test_app.py` — the test suite; run before/after changes.

## Adding a new device/parser

1. `ulpf/parsers/<name>.py` with `parse(line, mapping)` + `register(registry)`.
2. `ulpf/mappings/<name>.yaml` with defaults/field maps/action rules.
3. Sample file under `samples/`, re-run `python -m ulpf.pipeline samples out`.
4. Add/extend tests in `tests/`.

## Commands

```bash
python -m ulpf.pipeline samples out   # writes out/raw.jsonl and out/events.jsonl
python -m ulpf.app out                # local viewer at http://127.0.0.1:<port>/
python -m ulpf.app out --rebuild      # re-parse samples, then serve
python -m pytest tests/ -v            # run tests — do this after every change
```

## After each task

Summarize changed files, tests added/run, and how to verify manually (which commands
to run and what output/field to check).
