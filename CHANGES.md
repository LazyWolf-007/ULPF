# Change report — `day-build` since it diverged from `main`

**Important factual note before anything else:** `git log --stat main..HEAD`
and `git diff main..HEAD --stat` both return **empty**. `git branch -vv`
shows:

```
* day-build 9ae028e docs: readme, architecture, submission notes
  main      9ae028e [origin/main] docs: readme, architecture, submission notes
```

`day-build` and `main` point at the identical commit — there is no commit
divergence between them. Everything below is **uncommitted work in the
working tree** (`git status` shows it all as modified/untracked against
that shared commit `9ae028e`). This report is therefore built from
`git diff --stat` (working tree vs. `HEAD`) and `git status --short`, not
from `main..HEAD`, since the latter has nothing to show. If a commit was
expected to exist by now, it doesn't — nothing has been committed this
session.

```
git diff --stat
 README.md              |  55 ++++++-
 SPEC.md                | 391 +++++++++++++++++++++++++++++++++++++++++++++++++
 tests/test_app.py      |   9 +-
 tests/test_pipeline.py |   7 +-
 ulpf/detect.py         |  86 ++++++++++-
 ulpf/pipeline.py       | 168 ++++++++++++++++-----
 ulpf/schema.py         |   5 +
 7 files changed, 671 insertions(+), 50 deletions(-)
```

plus 14 new (untracked) files listed in the table below.

---

## 1. FILES

| File | Status | What it does |
|---|---|---|
| `README.md` | Modified | User-facing docs: output files, "Unknown vendors", "Live ingest", "Export", "Verifying integrity", air-gap section, sample-file table — updated for every feature below. |
| `SPEC.md` | Modified (was empty) | Technical spec: OCSF field-mapping tables, generic-parser design, quality-report field definitions, verify.py's two-check design, ingest.py/export.py design notes, a manual-verification checklist. |
| `tests/test_app.py` | Modified | One test's hardcoded counts (`event_count`, `failed_parses`, `distinct_vendors`) updated from 8/1/4 to 23/2/6 to reflect `samples/messy.log` joining `samples/`. |
| `tests/test_pipeline.py` | Modified | Same reason: `len(events1)` and the raw-line count updated from 8 to 23; added an `ocsf.jsonl` existence assertion. |
| `ulpf/detect.py` | Modified | Added `Detection` dataclass and `detect_format(line) -> Detection` (format + vendor fingerprint hints); added `"leef"` format. `detect()` kept as a backward-compatible wrapper around the same classifier. |
| `ulpf/pipeline.py` | Modified | Refactored to extract `process_record(...)` (detect → parse → finalize → OCSF for one record) and public `load_mappings()`, so `ulpf.ingest` can reuse the identical path. Added multiline-record merging + non-UTF-8 handling in `_iter_records`. Wired in the generic fallback parser and `quality.json` writing. |
| `ulpf/schema.py` | Modified | Added `raw_hash_bytes(data: bytes)` — hashes exact source bytes, independent of decode lossiness. Original `raw_hash(text)` untouched. |
| `CLAUDE.md` | New | Per-session agent guidance: hard rules, repo layout, commands (mirrors the ULPF rules given in this conversation's system context). |
| `samples/messy.log` | New | 15 hand-crafted "nasty" logical records (17 physical lines — one record spans 3) exercising the generic fallback parser, multiline merge, a non-UTF-8 byte, mixed timezones, LEEF, IPv6, and a genuinely unparseable line. |
| `ulpf/ocsf.py` | New | `to_ocsf(event) -> dict`: projects a finalized internal event to an OCSF-aligned record. Class selection, severity normalization, timestamp parsing (see §2). |
| `ulpf/parsers/generic.py` | New | Fallback parser used only when no vendor parser matches: JSON → CEF/LEEF → kv → syslog-prefix structurally, then regex heuristics for timestamp/IP/port/protocol/action. `parse.status = "partial"` + `parse.confidence` (0–1), or `None` if nothing at all was found. |
| `ulpf/quality.py` | New | `build_report(records) -> dict`: per-vendor-or-source-file aggregation (total events, parsed/partial/failed %, OCSF-core-field-populated %, top unmapped keys) written to `out/quality.json`. |
| `ulpf/verify.py` | New | `verify(output_dir) -> VerifyReport`: recomputes `raw.jsonl` hashes from original bytes, cross-checks every `events.jsonl` row's `provenance.raw_event_id`/`raw_hash` against `raw.jsonl`. CLI exits 1 on any mismatch. |
| `ulpf/ingest.py` | New | `IngestServer`: UDP + TCP listeners on `127.0.0.1:<port>`, both feeding `ulpf.pipeline.process_record`; source label = sender `"host:port"`. Appends to `raw/events/ocsf.jsonl`, rebuilds `quality.json` per message. |
| `ulpf/export.py` | New | `to_opensearch_bulk`, `to_splunk_hec`, `to_parquet` (optional `pyarrow`) + CLI `python -m ulpf.export <format> out`. |
| `tests/test_ocsf.py` | New | 3 tests for `to_ocsf` (class selection, all 6 vendor samples, empty-event fixed shape). |
| `tests/test_generic.py` | New | 20 tests: `detect_format`/hints, `generic.parse` unit behavior, every `messy.log` record end-to-end. |
| `tests/test_quality.py` | New | 5 tests: report shape, vendor-vs-file grouping, unmapped-key surfacing, empty input, defensive core-field check. |
| `tests/test_verify.py` | New | 7 tests: clean pass, tampered-hash catch, hash-recomputed-to-match catch (the task-3 requirement), missing-raw-id catch, CLI exit codes. |
| `tests/test_ingest.py` | New | 8 tests over real UDP/TCP sockets on ephemeral ports: same-pipeline-path proof, multi-message TCP, shared output files, quality.json updates, bootstrap from existing output, blank-message filtering, non-UTF-8 payload. |
| `tests/test_export.py` | New | 13 tests: all three exporters' output shape, CLI wiring, an optional-dependency-missing simulation for `to_parquet`. |

---

## 2. FEATURES DONE (Phase 1)

| Feature | Status | File + function |
|---|---|---|
| OCSF layer (`to_ocsf`, `out/ocsf.jsonl`, classes 4001/3002/2004) | **DONE** | `ulpf/ocsf.py:219 to_ocsf`; class selection in `_class_info` (line 108) — `parse.parser == "suricata"` → 2004 Security Finding, `event.category == "authentication"` → 3002 Authentication, else 4001 Network Activity. Written every run in `ulpf/pipeline.py:158 run` (one `ocsf_event` per record, line ~178). |
| Format auto-detection (`detect.py`) | **DONE** | `ulpf/detect.py:112 detect_format` returns format (`json`/`cef`/`leef`/`kv`/`syslog`/`unknown`) + vendor hints; `ulpf/pipeline.py:158 run` uses `.format` to select registered parsers with no manual flag (asserted directly by `tests/test_generic.py::test_pipeline_auto_selects_parser_with_no_manual_flag`). |
| Generic fallback parser (`generic.py`, partial status + confidence) | **DONE** | `ulpf/parsers/generic.py:268 parse` — returns `parse.status="partial"`, `parse.parser="generic"`, `parse.confidence` (0–1, weighted sum of found signals) or `None` when nothing at all is found (still yields `parse.status="failed"` upstream). Wired into `ulpf/pipeline.py:158 run` after the vendor-parser loop. |
| Multiline, non-UTF-8, mixed-timezone handling | **DONE** | Multiline + non-UTF-8: `ulpf/pipeline.py:49 _iter_records` (continuation-line merge, `errors="replace"` + `raw_text_lossy`/`raw_bytes_b64`). Mixed timezone: `ulpf/ocsf.py:164 _normalize_offset` + `179 _parse_timestamp` (handles `Z`, `+05:30`, `+0530`/`-0700`). All three exercised in `samples/messy.log` + `tests/test_generic.py`. |
| Quality report (`quality.json`) | **DONE, with a scoping note** | `ulpf/quality.py:92 build_report`, written in `ulpf/pipeline.py:158 run` (and kept live by `ulpf/ingest.py`'s `_Writer`). The task asked for grouping "per source/vendor"; this implementation uses **one merged key** — `observer.vendor` when known, else the source file/sender address (`ulpf/quality.py:88 _group_key`) — not an independent two-dimensional source × vendor breakdown. Per group: total events, parsed/partial/failed %, `ocsf_core_fields_populated_pct`, top 5 unmapped keys. |
| Integrity verifier (`verify.py` + tamper test) | **DONE** | `ulpf/verify.py:71 verify` — two checks: raw self-consistency (`_recompute_raw_hash`, line 63) and events→raw cross-reference. Tamper tests: `tests/test_verify.py::test_verify_catches_tampered_raw_text` (edit text, leave hash) and `::test_verify_catches_hash_recomputed_to_match_tampered_text` (edit text *and* recompute a self-consistent hash — caught by the second check instead). |
| Syslog UDP/TCP listener (`ingest.py`) | **DONE** | `ulpf/ingest.py:155 IngestServer` — `_UDPServer`/`_TCPServer` (lines 138/146) both bound to `127.0.0.1` (default port `5514`, configurable), both routing to `ulpf.pipeline.process_record` (added to `pipeline.py` specifically for this). Source label = sender `"host:port"` in `_UDPHandler`/`_TCPHandler` (lines 117/126). |
| Exporters: OpenSearch, Splunk HEC, Parquet | **DONE** | `ulpf/export.py:29 to_opensearch_bulk`, `:48 to_splunk_hec`, `:95 to_parquet` (optional `pyarrow`, not in `requirements.txt`). CLI at `:130 main` — `python -m ulpf.export <format> out`. |

---

## 3. TESTS

Ran: `python -m pytest tests/ -v` (Python 3.14.0, pytest 9.0.2)

**Result: 60 passed, 0 failed, 0 errors, 0 skipped, in 11.05s.**

Breakdown by file (counted directly from the `-v` output, matches pytest's
own "collected 60 items" line): `test_app.py` 1, `test_export.py` 13,
`test_generic.py` 20, `test_ingest.py` 8, `test_ocsf.py` 3,
`test_pipeline.py` 3, `test_quality.py` 5, `test_verify.py` 7 = **60**. No
failures to report. Re-ran the full suite twice in this session
(socket-based `test_ingest.py` tests are the one place flakiness could
plausibly show up); both runs passed with an identical count.

---

## 4. PIPELINE

Ran: `python -m ulpf.pipeline samples <tmp_out>` — exit code 0. Wrote
`raw.jsonl`, `events.jsonl`, `ocsf.jsonl`, `quality.json`. Per-source-file
breakdown (computed by joining `raw.jsonl`'s `source_file` with
`events.jsonl`'s `parse.status`, same line order in both files):

| source_file | total | ok | partial | failed |
|---|---:|---:|---:|---:|
| checkpoint.log | 1 | 1 | 0 | 0 |
| cisco.log | 2 | 1 | 0 | 1 |
| fortigate.log | 2 | 2 | 0 | 0 |
| messy.log | 15 | 3 | 11 | 1 |
| paloalto.log | 1 | 1 | 0 | 0 |
| sshd.log | 1 | 1 | 0 | 0 |
| suricata.log | 1 | 1 | 0 | 0 |
| **TOTAL** | **23** | **10** | **11** | **2** |

`cisco.log`'s 1 failed line is the deliberate garbage sample
(`"this is not a log"`). `messy.log`'s 1 failed line is its deliberately
unparseable noise line; its 11 partial lines are the generic-fallback
records; its 3 ok lines are vendor-parsed (Check Point multiline, CEF,
Suricata edge case — see `SPEC.md`).

Also ran `python -m ulpf.verify <tmp_out>` against this same fresh output:
`{"ok": true, "raw_count": 23, "event_count": 23, "mismatch_count": 0}`,
exit code 0.

---

## 5. HOW TO RUN each new feature

```bash
# Base pipeline (writes raw/events/ocsf.jsonl + quality.json)
python -m ulpf.pipeline samples out

# Local viewer
python -m ulpf.app out

# Integrity check (exit 1 on any mismatch)
python -m ulpf.verify out

# Live syslog capture (UDP + TCP on 127.0.0.1:5514), appends into out/
python -m ulpf.ingest out --port 5514

# Export out/ocsf.jsonl for an external sink (no network call is made here)
python -m ulpf.export opensearch out --output out/bulk.ndjson
python -m ulpf.export splunk out --index security --output out/hec.ndjson
python -m ulpf.export parquet out                # needs: pip install pyarrow

# Tests
python -m pytest tests/ -v
```

---

## 6. RISKS

- **Nothing is committed.** All of the above is uncommitted working-tree
  state on `day-build`, identical in git history to `main`. If this
  machine/checkout were lost, all of this work would be lost with it.
- **Quality report grouping is one merged key, not a source×vendor
  matrix** (see §2) — a literal "per source AND per vendor" cross-tab was
  not built.
- **`pyarrow` is an optional dependency not declared anywhere**, not even
  as an "extras" marker — it's only mentioned in prose (README/SPEC) and
  handled with a `try/except ImportError` in `ulpf/export.py:95
  to_parquet`. A machine without it gets a clear `RuntimeError`, not a
  crash, but there's no `requirements-optional.txt` or `extras_require`.
- **`ulpf.ingest`'s CLI entrypoint (`main`, line 208) has no automated
  test** — only `IngestServer` (the class it constructs) is exercised by
  `tests/test_ingest.py`. The argparse wiring itself was checked once by
  hand during development, not under pytest.
- **`ulpf.ingest`'s `quality.json` rewrite is O(n) per received message**
  (it re-serializes the whole in-memory record list on every message,
  documented in `SPEC.md`) — fine at the local/demo volumes this listener
  targets, would not scale to a high-throughput deployment.
- **Syslog listener is deliberately minimal transport**: newline-delimited
  TCP framing only (no RFC 6587 octet-counting, no RFC 5425 TLS framing),
  no authentication, no rate limiting. Acceptable for an air-gapped local
  tool; would not be acceptable for a real network-facing syslog collector.
- **No test against a real external syslog sender** (a router, `rsyslog`,
  `logger` over the network, etc.) — all `test_ingest.py` coverage is
  local Python `socket` calls in-process. Interop with real-world syslog
  senders is **unverified**.
- **Docker image not rebuilt or run this session** — the `Dockerfile`
  still only runs `ulpf.pipeline` + `ulpf.app`; it was not updated to
  expose `ulpf.ingest`'s port or run `ulpf.export`, and none of this
  session's new modules have been validated inside the container.
  **Unverified.**
- **Air-gap / CLAUDE.md compliance — checked directly, clean:**
  `grep` for vendor/product names in `ulpf/pipeline.py` — no matches.
  `grep` for outbound-network patterns (`requests.`, `urllib.request`,
  `http.client`, `socket.connect(`, `smtplib`, `ftplib`) across
  `ulpf/*.py` and `ulpf/parsers/*.py` — no matches (the only sockets in
  the codebase are `ulpf.ingest`'s inbound listeners and `ulpf.app`'s
  inbound HTTP server, both bound to `127.0.0.1`).
  `grep` for any reassignment of `raw_text`/the decoded `text` variable
  after its initial `.decode(...)` — none found; the only two hits
  (`ulpf/app.py:79`, `ulpf/ingest.py:87`) are read-outs/parameter passing,
  not mutation.
- **`process_record`'s `ingest_time` is now generated inside the shared
  function** rather than by each caller as before the refactor — behavior
  is unchanged (still one fresh UTC timestamp per record) but this is a
  structural change to `ulpf/pipeline.py` worth knowing about if something
  downstream ever depended on the old call order.

---

## 7. NOT DONE

Nothing from the four feature requests in this session was skipped
outright — every explicitly named deliverable (OCSF classes, detect_format
+ hints, generic parser + confidence, multiline/non-UTF-8/timezone
handling, `messy.log` + tests, quality.json, verify.py + tamper tests,
ingest.py UDP+TCP, all three exporters + CLI) exists and is covered by a
passing test. The gaps are the scoping/robustness notes already listed
under RISKS above (source×vendor as one merged key rather than a 2D
matrix; no automated test of `ingest.py`'s CLI entrypoint itself; no
real-external-sender or Docker validation this session) — reported there
rather than duplicated here since none of them represents a requested
deliverable that was left undone.
