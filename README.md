# ULPF

Firewalls, IDS sensors, and Linux hosts each emit logs in their own dialect—syslog prefixes, CEF, JSON blobs, or `key=value` lines. Comparing or searching across them is awkward when every tool expects a different shape.

ULPF is a local pre-processor. It reads those files line by line, stores the original text in a raw vault, and writes one shared JSON record per line with common fields (source and destination IP, action, outcome, vendor, parse status, and provenance). Lines that do not parse still get a record so nothing is silently dropped.

## Setup and run

PyYAML is required for mappings. Use a virtual environment so dependencies stay isolated:

```bash
python -m venv .venv
```

Activate it (Windows PowerShell: `.venv\Scripts\Activate.ps1`; macOS/Linux: `source .venv/bin/activate`), then install and run:

```bash
pip install -r requirements.txt
python -m ulpf.pipeline samples out
python -m ulpf.app out
```

The pipeline writes `out/raw.jsonl`, `out/events.jsonl`, `out/ocsf.jsonl`, and `out/quality.json`. The app prints a URL such as `http://127.0.0.1:<port>/`; open it in a browser to browse and filter events. To re-parse before serving, use `python -m ulpf.app out --rebuild` (defaults to input folder `samples`).

Run tests:

```bash
python -m pytest tests/ -v
```

Verify a run's integrity (recomputes hashes and cross-checks `events.jsonl` against `raw.jsonl`; exits non-zero if anything doesn't match):

```bash
python -m ulpf.verify out
```

Capture live syslog instead of (or in addition to) files — UDP and TCP listeners on `127.0.0.1:5514` feeding the same pipeline, appending to the same `out/` (see "Live ingest" below):

```bash
python -m ulpf.ingest out --port 5514
```

Export `out/ocsf.jsonl` for an external sink (see "Export" below):

```bash
python -m ulpf.export opensearch out --output out/bulk.ndjson
python -m ulpf.export splunk out --index security
python -m ulpf.export parquet out   # requires `pip install pyarrow`
```

## Output files

**`raw.jsonl`** — One JSON object per logical record: raw event id, exact `raw_text`, SHA-256 `raw_hash`, source file name, ingest timestamp, `raw_text_lossy`, and `raw_bytes_b64`. Use this when you need the untouched line or to verify hashing. A "logical record" merges an indented continuation line (leading space/tab) onto the line above it, so a multiline entry (e.g. a stack trace under a log line) becomes one record, not several broken ones. `raw_hash` is always computed over the exact original bytes, not the decoded text. If a line isn't valid UTF-8, it's decoded with `errors="replace"` for `raw_text`, `raw_text_lossy` is set to `true`, and the exact original bytes are kept losslessly in base64 in `raw_bytes_b64` (empty otherwise).

**`events.jsonl`** — One shared record per line with normalized fields (`network.*`, `observer.*`, `event.*`, `parse.*`, `provenance.*`, `unmapped`). Failed parses appear here with `parse.status` set to `failed` and provenance filled from the raw line. A line that doesn't match any vendor parser but still yields partial signal (an IP, a port, an action word, a timestamp) via the generic fallback parser gets `parse.status = "partial"`, `parse.parser = "generic"`, and a `parse.confidence` between 0 and 1 — see "Unknown vendors" below.

**`ocsf.jsonl`** — One OCSF-aligned record per line, projected from `events.jsonl` (`ulpf/ocsf.py`, `to_ocsf`). Class is chosen per event: Security Finding (`2004`) for IDS alerts (Suricata), Authentication (`3002`) for `event.category == "authentication"`, otherwise Network Activity (`4001`) — including failed parses. See `SPEC.md` for the full field mapping and severity normalization tables.

**`quality.json`** — A data-quality report (`ulpf/quality.py`), grouped by `observer.vendor` (falling back to the source file name for vendor-less/failed lines). Per group: `total_events`, `parsed_pct`/`partial_pct`/`failed_pct` (by `parse.status`), `ocsf_core_fields_populated_pct` (fraction of `time`, `src_endpoint.ip`, `dst_endpoint.ip`, `connection_info.protocol_name`, `action`, `disposition` that carry real signal in `ocsf.jsonl`), and `top_unmapped_keys` (the most common field names left in `unmapped` — a signal that a mapping is missing a field). An `"overall"` entry aggregates across every group.

## Verifying integrity

`ulpf/verify.py` recomputes the SHA-256 of every `raw.jsonl` row from its exact original bytes and compares it to the stored `raw_hash`, then cross-checks every `events.jsonl` row's `provenance.raw_event_id` exists in `raw.jsonl` and its `provenance.raw_hash` matches. Two independent checks so a single doctored file can't hide: editing `raw_text` without updating `raw_hash` fails the first check; editing `raw_text` *and* recomputing a self-consistent `raw_hash` still fails the second, since `events.jsonl` recorded the original hash at parse time. Run it with `python -m ulpf.verify <out_dir>` (prints a JSON report, exit code `1` if anything doesn't match) or call `ulpf.verify.verify(out_dir)` directly for a `VerifyReport`.

## Adding a device

1. Add `ulpf/parsers/<name>.py` with `parse(line, mapping)` and `register(registry)` that registers for the correct format (`syslog`, `cef`, `json`, `kv`, etc.).
2. Add `ulpf/mappings/<name>.yaml` with defaults, field maps, and action rules.
3. Drop a sample file under `samples/` and re-run `python -m ulpf.pipeline samples out`.

Do not add vendor or product names to `pipeline.py`; discovery goes through the parser registry and YAML only.

## Unknown vendors

`ulpf/detect.py`'s `detect_format(line)` classifies a line (`json`, `cef`, `leef`, `kv`, `syslog`, `unknown`) and also returns best-effort vendor fingerprint hints (e.g. `"%ASA-"` → `cisco_asa`, `devname=` → `fortigate`, a CEF/LEEF header's vendor field, `"PA-"` → `paloalto`, a JSON `event_type`/`alert` key → `suricata`). The pipeline always uses `.format` to pick registered parsers automatically — there's no manual per-file or per-vendor flag.

When no registered parser recognizes a line, `ulpf/parsers/generic.py` runs as the last-resort fallback (not through per-format registry dispatch — it's invoked explicitly, with the detected hints, once every real parser has declined). It tries structural parsing in order — JSON, then CEF/LEEF, then `key=value`, then a syslog `<PRI>` prefix — then heuristically scans the raw text for timestamps, IPv4/IPv6 addresses, ports, a protocol name, and an action word (`allow`/`deny`/`drop`/`block`/`accept`), filling in whatever the structural pass missed. Results get `parse.status = "partial"` and a `parse.confidence` (0–1) reflecting how much signal was actually found; a line with no recognizable signal at all still gets `parse.status = "failed"`, same as before. See `samples/messy.log` and `tests/test_generic.py` for 15 worked examples (non-UTF-8 bytes, a multiline record, mixed timezones, IPv6, LEEF, unrecognized key names, and genuinely unparseable text).

## Live ingest

`ulpf/ingest.py`'s `IngestServer` binds a UDP listener and a TCP listener to the same host:port (default `127.0.0.1:5514` — configurable, but defaulting local like every other listener here). Every received message — one per UDP datagram, newline-delimited per TCP connection — runs through `ulpf.pipeline.process_record`, the exact same detect → parse → finalize → OCSF path `ulpf.pipeline.run` uses for files, so a line captured live is indistinguishable in shape from one read from a file. There's no source *file* for a live message, so `raw_record["source_file"]` (and the `quality.json` grouping key, when vendor is unknown) holds the sender's `"host:port"` address instead of a filename. Records append to the same `raw.jsonl`/`events.jsonl`/`ocsf.jsonl` in `output_dir`, and `quality.json` is rebuilt after each one — including bootstrapping from whatever's already on disk (e.g. a prior `ulpf.pipeline` run), so it never regresses to reflecting only the live session.

## Export

`ulpf/export.py` reshapes `out/ocsf.jsonl` (or any `.jsonl` file under `out/`, via `--source-file`) for a specific downstream sink — each `to_*` function is a pure transform with no network calls of its own (writing the result to a real OpenSearch/Splunk endpoint is left to the operator, per the air-gap rule below):

- **`to_opensearch_bulk(events, index=...)`** — NDJSON for the OpenSearch/Elasticsearch `_bulk` API: one `{"index": {...}}` action line + one source line per event, using `metadata.raw_event_id` (or `event_id`) as the document `_id` so re-indexing the same export is idempotent.
- **`to_splunk_hec(events, source=..., sourcetype=..., index=...)`** — NDJSON for Splunk's HTTP Event Collector: `{"event": ..., "time": ..., "source": ..., "sourcetype": ...}` per line, converting OCSF's epoch-millisecond `time` to the epoch-seconds HEC expects.
- **`to_parquet(events, path)`** — writes a Parquet file. Needs the optional `pyarrow` dependency (`pip install pyarrow`; deliberately not in `requirements.txt`, per "minimal dependencies") — raises a clear `RuntimeError` if it's missing.

## Air-gap

ULPF does not open outbound network connections. The listeners are the optional local viewer in `ulpf/app.py` and the optional syslog listener in `ulpf/ingest.py`, both bound to `127.0.0.1` on your machine by default. `ulpf/export.py` only writes local files/stdout — it never calls out to OpenSearch, Splunk, or anywhere else itself. No API keys or cloud credentials are used.

## Sample files (what to check)

| File | Field to verify |
|------|-----------------|
| `samples/cisco.log` | `user.name` (`jdoe` on the ASA line); `parse.status` (`failed` on the garbage line) |
| `samples/fortigate.log` | `network.transport` (`udp` / `tcp` from `proto`) |
| `samples/paloalto.log` | `observer.vendor` (`Palo Alto Networks`) |
| `samples/suricata.log` | `event.description` (`Allowed DNS Query`; timestamp from JSON, not ingest time) |
| `samples/sshd.log` | `event.category` (`authentication`) |
| `samples/checkpoint.log` | `observer.vendor` (`Check Point`) |
| `samples/messy.log` | 15 nasty/edge-case lines exercising the generic fallback parser, multiline merging, non-UTF-8 bytes, and mixed timezones — see `tests/test_generic.py` |

## Docker

If all tests pass in your tree, you can run the same pipeline and viewer in a single-container image (Python 3.12 only; no Kafka or other services):

```bash
docker build -t ulpf .
docker run --rm ulpf
```

The build step runs `python -m ulpf.pipeline samples out` inside the image. The container starts one process: `python -m ulpf.app out`, which prints a `http://127.0.0.1:<port>/` URL. On Linux, `docker run --rm --network host ulpf` lets you open that URL from the host.
