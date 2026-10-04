# SPEC

## OCSF export (`ulpf/ocsf.py`)

`ulpf/pipeline.py` writes `out/ocsf.jsonl` alongside `out/raw.jsonl` and
`out/events.jsonl`. It is one line per input line, in the same order as
`events.jsonl` (one OCSF record per internal event, including failed
parses). Nothing about the internal schema (`ulpf/schema.py`, `EVENT_KEYS`)
changes — `to_ocsf(event)` is a pure, read-only projection of an already
finalized internal event dict, called once per event from `pipeline.run`.
It does not touch parsers or mappings.

This export is **field-shape aligned** with the public OCSF class catalog
(class/category ids and names, the `_id` + caption enum pattern, endpoint
and metadata objects). It is not validated against the official OCSF JSON
schema — treat `OCSF_VERSION` ("1.1.0") as "the OCSF release this shape
targets", not a compliance guarantee.

### Class selection

`to_ocsf` picks one of three OCSF classes per event. Selection is driven by
fields already on the internal event (`parse.parser`, `event.category`) —
no new signal is added upstream:

| Rule | OCSF class | `class_uid` | `category_uid` |
|---|---|---|---|
| `parse.parser == "suricata"` | Security Finding | 2004 | 2 (Findings) |
| else `event.category == "authentication"` | Authentication | 3002 | 3 (IAM) |
| else (default, includes `event.category == "network"` and failed parses) | Network Activity | 4001 | 4 (Network Activity) |

Suricata is the only IDS/IDPS source in this sample set. Every line it
emits is a detection-engine alert (that's what the `alert` object in
Suricata EVE JSON *is*), so it is always exported as a Security Finding —
even though its internal `event.category` stays `"network"` (that field
describes the traffic the alert is about, and existing tests pin it to
`"network"`; it is deliberately left alone). A future IDS parser should
follow the same pattern: key the OCSF class off something stable already on
the event (parser name, or a dedicated `event.category` value), not off
vendor name.

Lines that fail to parse (`parse.status != "ok"`) still get a full,
fixed-shape OCSF record (default Network Activity class, `activity_id: 0`
"Unknown", `disposition: "Unknown"`, `severity_id: 0`) so the export stays
lossless: `metadata.raw_data_hash` / `metadata.raw_event_id` always trace
back to the exact raw line.

### Field mapping

| OCSF field | Source | Notes |
|---|---|---|
| `class_uid`, `class_name`, `category_uid`, `category_name` | derived, see above | |
| `activity_id`, `activity_name` | derived from class + `event.outcome` / `parse.status` | see table below |
| `severity_id`, `severity` | `event.severity`, normalized per `parse.parser` | see severity table |
| `time` | `event.timestamp`, else `provenance.ingest_time` | epoch milliseconds; `0` if neither parses |
| `action` | `event.action` | passed through verbatim |
| `disposition_id`, `disposition` | `event.outcome` | `success`→Allowed(1), `failure`→Blocked(2), else Unknown(0) |
| `src_endpoint.ip` / `.port` | `network.src_ip` / `network.src_port` | `""` when unknown, matching `schema.py` convention |
| `dst_endpoint.ip` / `.port` | `network.dst_ip` / `network.dst_port` | same |
| `connection_info.protocol_name` | `network.transport` | |
| `metadata.product` | `observer.product` (or `"unknown"`) | |
| `metadata.vendor_name` | `observer.vendor` (or `"unknown"`) | |
| `metadata.version` | constant `OCSF_VERSION` | schema version of this export, not device firmware version |
| `metadata.raw_data_hash` | `provenance.raw_hash` | ties every OCSF record back to `raw.jsonl` |
| `metadata.raw_event_id` | `provenance.raw_event_id` | |
| `unmapped` | `event["unmapped"]` | passed through as-is |

### `activity_id` by class

| Class | Condition | `activity_id` | `activity_name` |
|---|---|---|---|
| any | `parse.status != "ok"` | 0 | Unknown |
| Security Finding | parsed ok | 1 | Create (a new finding/alert record) |
| Authentication | parsed ok | 1 | Logon (sample sshd data only carries logon attempts) |
| Network Activity | `event.outcome == "success"` | 1 | Open |
| Network Activity | `event.outcome == "failure"` | 4 | Fail |
| Network Activity | `event.outcome == "unknown"` | 6 | Traffic |

### `severity_id` normalization

`event.severity` uses a different native scale per source, so it's
normalized per `parse.parser` before mapping to the OCSF 0–6 severity
enum (0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical,
6 Fatal):

| Parser | Native scale | Mapping |
|---|---|---|
| `cisco_asa` | syslog severity 0–7, **0 = most severe** | `{0:6, 1:6, 2:5, 3:5, 4:4, 5:3, 6:2, 7:1}` |
| `suricata` | alert severity 1–3, **1 = most severe** | `{1:4, 2:3, 3:2}` |
| `cef` (Palo Alto / other CEF sources) | 0–10, **10 = most severe** | bucketed: 0→0, 1–2→1, 3–4→2, 5–6→3, 7–8→4, 9–10→5 |
| everything else (`checkpoint`, `fortigate`, `sshd`) | no `event.severity` emitted | always `0` (Unknown) |

### `time` parsing

Three timestamp shapes appear in the sample data; `_parse_timestamp` tries
each in order and falls back to `provenance.ingest_time` (always present)
if none match:

1. ISO 8601, optional trailing `Z` (Suricata `timestamp`, `provenance.ingest_time`).
2. Classic syslog `"Mon DD HH:MM:SS"` with no year (`cisco_asa`, `sshd`) —
   the current UTC year is assumed since the source line doesn't carry one.
3. `"YYYY-MM-DD HH:MM:SS"` (`fortigate`).

CEF (Palo Alto sample) and Check Point's kv format don't populate
`event.timestamp` at all, so those records fall back to `provenance.ingest_time`.

Mixed timezone notations are normalized before the ISO 8601 branch runs:
a trailing `Z`, a colon-separated offset (`+05:30`), and an offset with no
colon (`+0530`, `-0700`) all parse to the same correct instant (`_normalize_offset`
in `ulpf/ocsf.py`). Different offsets are never conflated: two lines at the
same wall-clock time in different zones produce different epoch millis.

## Unknown-vendor handling (`ulpf/detect.py`, `ulpf/parsers/generic.py`)

Two pieces work together so a line from a device with no dedicated parser
still produces a useful record instead of `parse.status = "failed"`:

**`detect_format(line)`** (`ulpf/detect.py`) classifies a line into one of
`json`, `cef`, `leef`, `kv`, `syslog`, `unknown` — the same classification
`detect()` always returned (kept as a thin wrapper for backward
compatibility) — and additionally returns `hints`: cheap substring/structural
fingerprints (`"%ASA-"` → `cisco_asa`, `"devname="` → `fortigate`, a
CEF/LEEF header's vendor field → `cef_vendor:<name>`/`leef_vendor:<name>`
(and `paloalto`/`checkpoint` when that name matches), `"PA-"` → `paloalto`,
a JSON `event_type`/`alert` key → `suricata`). Hints are computed
independently of the format classification — a mangled line that fails
structural detection can still carry a recognizable fingerprint — and never
change which parser the registry dispatches to; they are only consulted by
the fallback parser below, to make a vendor guess when nothing else set one.

**`ulpf/parsers/generic.py`** is the fallback, used only once every
registered parser for the detected format has declined (returned `None`).
It is *not* selected through the normal per-format registry dispatch used
by vendor parsers — `pipeline.run` calls `generic.parse(raw_text, {"hints":
...})` directly as the explicit last resort, threading the hints in. (Its
`register()` still exists, for the same module-shape convention every
parser follows, but wires to a sentinel format string no real line ever
classifies as, so it never double-dispatches.) It tries, in order:

1. JSON (flattening one level of nesting, then the same key-alias table as step 3).
2. CEF or LEEF (`CEF:`/`LEEF:` header, pipe-delimited fields, alias table over the extension).
3. `key=value` pairs, matched against alias sets for src/dst IP, src/dst port,
   protocol, action, and timestamp (e.g. `saddr`/`daddr`/`source_ip`/`sip` all
   alias to src IP). Deliberately **excludes** bare `source`/`destination`/`dest`
   — those key names are ambiguous in real logs (Windows Event Log's `Source`
   is a product name, not an IP) and produced a false-positive IP in testing
   (`samples/messy.log` record 15); the regex fallback below is the safety net
   for lines using those names.
4. A syslog `<PRI>` prefix (structure only, no field extraction — the body still
   goes through step 5).

Whatever structural fields are still missing after that, a heuristic regex
pass over the raw text fills in: an ISO-8601 or classic-syslog timestamp,
the first and second distinct IPv4/IPv6 address, a `port=`/`sport=`/`dport=`-style
number, a standalone `tcp`/`udp`/`icmp`/`sctp` token, and an
`allow(ed)`/`accept(ed)`/`deny/denied`/`drop(ped)`/`block(ed)` action word
(also setting `event.outcome`: allow/accept → `success`, deny/drop/block →
`failure`). The IPv6 matcher is deliberately loose — it grabs any run of hex
digits and colons then requires at least two colons — so it handles `::`
compression correctly, unlike a fixed-group-count pattern.

A line producing **no** structural match and **no** heuristic field at all
returns `None` (so the pipeline still marks it `parse.status = "failed"`,
identical to today). Otherwise it returns a record with `parse.status =
"partial"`, `parse.parser = "generic"`, `parse.format` set to whichever
structure was recognized (or `"unknown"`), and `parse.confidence` — a 0–1
score, the sum of fixed weights for each signal actually found (structure
recognized: 0.25; timestamp: 0.15; src IP: 0.15; dst IP: 0.15; a port: 0.10;
protocol: 0.10; action word: 0.10 — these sum to 1.0 when everything is found).

`ocsf.py`'s `_activity`/`_disposition` treat `parse.status in {"ok", "partial"}`
the same (only `"failed"` collapses to Unknown/0) so a `"partial"` record's
`event.outcome` still drives a real OCSF `disposition`/`activity_id` instead
of always reading Unknown — this was a real bug caught by testing `samples/messy.log`
records against the OCSF layer, fixed alongside adding the generic parser.

### Multiline records and non-UTF-8 bytes (`ulpf/pipeline.py`)

`_iter_records` reads each input file as bytes and groups physical lines
into logical records: a physical line starting with a space or tab is a
continuation of the previous record (e.g. a stack trace line under a log
entry) and is joined onto it with `"\n"`. `raw_hash` is computed over the
exact joined bytes, before any decoding, so it's a true fingerprint of the
source data regardless of decode issues. Each group is decoded as UTF-8;
if that fails, it's redecoded with `errors="replace"` and `raw_text_lossy`
is set — the exact original bytes are still recoverable losslessly from
`raw_bytes_b64` (base64), since the substituted `raw_text` lost information.

## Data-quality report (`ulpf/quality.py`, `out/quality.json`)

`pipeline.run` accumulates one `(vendor, source_file, parse_status, ocsf_event,
unmapped)` tuple per event while it processes records (no re-parsing, no
re-reading the output files) and passes the list to `quality.build_report`
once at the end, writing the result to `out/quality.json`.

**Grouping.** Each event lands in one group: `observer.vendor` when set,
otherwise the raw source file name. This means every failed parse and every
vendor-less generic-fallback partial still lands somewhere readable (e.g.
`"cisco.log"`, `"messy.log"`) instead of collapsing into a meaningless empty
key. An `"overall"` group aggregates across all of them.

**Per group:**

- `total_events` — count.
- `parsed_pct` / `partial_pct` / `failed_pct` — percentage of `total_events`
  with `parse.status` `"ok"` / `"partial"` / `"failed"` respectively (these
  three always sum to ~100%, since every event is exactly one of them).
- `ocsf_core_fields_populated_pct` — of six OCSF fields considered "core"
  for cross-source analytics (`time`, `src_endpoint.ip`, `dst_endpoint.ip`,
  `connection_info.protocol_name`, `action`, `disposition`), the percentage
  that actually carry signal, averaged across every event in the group.
  "Populated" means: `time > 0`; `disposition not in ("", "Unknown")`; every
  other field just needs to be truthy. Constant-per-event OCSF fields
  (`class_uid`, `category_uid`, `metadata.*`) are deliberately excluded —
  they don't vary with parse quality, so including them would inflate the
  score without saying anything useful.
- `top_unmapped_keys` — the 5 most common key names left in that group's
  `unmapped` dicts, as `{"key": ..., "count": ...}`, most-common first. A
  key that consistently shows up here across many events of one vendor is a
  signal that vendor's YAML mapping is missing a field it should map.

## Integrity verification (`ulpf/verify.py`)

`verify(output_dir)` re-derives trust in a pipeline output directory from
first principles — it never trusts a stored hash without recomputing it —
via two independent checks, run as a CLI (`python -m ulpf.verify <out_dir>`,
exit `1` on any mismatch) or as a library call returning a `VerifyReport`:

1. **`raw.jsonl` self-consistency.** For every row, recompute SHA-256 over
   the exact original bytes — `raw_bytes_b64` base64-decoded when
   `raw_text_lossy` is true, otherwise `raw_text` re-encoded as UTF-8 (this
   mirrors exactly how `pipeline.run` computed `raw_hash` in the first
   place: from bytes, before any lossy decode) — and compare to the stored
   `raw_hash`. A mismatch here means `raw.jsonl` was edited without
   recomputing its own hash: `kind: "raw_hash_mismatch"`.
2. **`events.jsonl` cross-reference.** For every row, confirm
   `provenance.raw_event_id` exists in `raw.jsonl` (`kind:
   "missing_raw_id"` if not — e.g. a raw row was deleted), then confirm
   `provenance.raw_hash` matches that raw row's `raw_hash` (`kind:
   "event_hash_mismatch"` if not).

Check 2 exists because check 1 alone can be defeated: an attacker who edits
`raw_text` *and* recomputes a self-consistent `raw_hash` passes check 1
outright. But `events.jsonl` was written by `pipeline.run` at parse time and
still carries the *original* hash, so it no longer matches the tampered
`raw.jsonl` row — check 2 catches it. `tests/test_verify.py` exercises both
tamper shapes directly (`test_verify_catches_tampered_raw_text` for check 1,
`test_verify_catches_hash_recomputed_to_match_tampered_text` for check 2),
plus a deleted-row case (`test_verify_catches_missing_raw_id`) and a clean
run staying `ok: true`.

## Live ingest (`ulpf/ingest.py`)

`ulpf.pipeline.run` was refactored to split out `process_record(raw_text,
raw_bytes, is_lossy, source_label, mappings, ingest_time=None) -> (raw_record,
event, ocsf_event)` — the detect → parse (registry, then generic fallback) →
finalize → OCSF steps, with no file/network I/O in it. `run` calls it once
per logical line from a file; `ulpf.ingest` calls the identical function
once per received syslog message, so live and file-based ingestion are
provably the same pipeline, not two implementations that happen to agree.
`load_mappings` (renamed from `_load_mappings`, made public for the same
reason) is called once when an `IngestServer` starts.

**Transport.** `IngestServer(output_dir, host="127.0.0.1", port=5514)`
binds a `socketserver.ThreadingUDPServer` and a `socketserver.ThreadingTCPServer`
to the same host:port — UDP is bound first, and TCP is then bound to
whatever port UDP actually resolved to, so `port=0` (let the OS pick a free
port, used in tests) still gives both protocols the *same* port; binding
each independently would give two different ephemeral ports. Each UDP
datagram is one message; a TCP connection is read line-by-line (LF- or
CRLF-delimited, RFC 6587-style plain framing) and can carry many messages.
A message that is empty or whitespace-only after stripping trailing CR/LF
is silently dropped (mirrors skipping blank lines in file ingestion).
Non-UTF-8 payloads are decoded with `errors="replace"` and flagged lossy,
identically to `pipeline._iter_records`' file handling.

**Source label.** There's no source *file* for a live message, so
`process_record`'s `source_label` is the sender's `"<ip>:<port>"` address.
This flows into `raw_record["source_file"]` and therefore into
`quality.json`'s grouping key whenever `observer.vendor` is unknown (e.g.
`"127.0.0.1:54821"` instead of `"messy.log"`).

**quality.json.** `_Writer` keeps its own in-memory list of quality tuples
(same shape `ulpf.quality.build_report` expects) and rewrites `quality.json`
after every message — simple and correct at the message volumes this local
listener is meant for; a high-throughput deployment would batch this. On
startup, if `raw.jsonl`/`events.jsonl`/`ocsf.jsonl` already exist in
`output_dir` (e.g. from a prior `ulpf.pipeline` run), `_Writer` reads them
back and bootstraps the in-memory list from them first, so `quality.json`
never regresses to reflecting only the current session.

## Export (`ulpf/export.py`)

Three pure transforms, `list[dict] -> text` (or, for Parquet, `-> file`),
reading `out/ocsf.jsonl` by default via the CLI (`--source-file` picks a
different `.jsonl`). None of them make a network call — sending the result
to a real OpenSearch/Splunk endpoint is the operator's job, consistent with
ULPF's air-gap rule.

- **`to_opensearch_bulk`** — the OpenSearch/Elasticsearch bulk-API NDJSON
  shape: an `{"index": {"_index": ..., "_id": ...}}` line followed by the
  event itself, per event. `_id` comes from `metadata.raw_event_id` (OCSF
  events) or `event_id` (internal `events.jsonl` events) when present, so
  re-running the same export twice overwrites the same documents instead of
  duplicating them; omitted when neither is present.
- **`to_splunk_hec`** — Splunk HEC's NDJSON shape: `{"event": ...,
  "source": ..., "sourcetype": ..., ["time": ..., "index": ...]}` per line.
  `time` is derived from the OCSF `time` field (epoch milliseconds) divided
  by 1000 (HEC wants epoch seconds), and omitted when `time` is missing or
  `0` — same "let the receiver decide" rule Splunk itself uses.
- **`to_parquet`** — the only one of the three with an optional dependency
  (`pyarrow`, not in `requirements.txt`). Before conversion, every `""`
  leaf value is recursively turned into `None`
  (`_null_out_empty_strings`). This isn't cosmetic: `ocsf.py`'s endpoint
  fields (e.g. `src_endpoint.port`) are `int` when known and `""` when not
  — the same "" convention `schema.py` uses everywhere as "unset" — and
  Arrow/Parquet is a typed columnar format that cannot infer one column
  type spanning both `int` and `str`. Passing real `ocsf.jsonl` output
  through `pa.Table.from_pylist` unmodified raises `ArrowInvalid`; since ""
  already *means* "no value" in this schema, mapping it to a true null is
  the correct fix, not a workaround. `pyarrow` missing raises `RuntimeError`
  with an install hint rather than a raw `ImportError` traceback.

## Offline LLM parser generator (`ulpf/llm/`, `ulpf/parsers/dynamic.py`)

Five files under `ulpf/llm/`, one under `ulpf/parsers/`:

- `structure.py` - deterministic detection and tokenization (quoted key=value, JSON, CEF/LEEF, syslog prefix split from the body). The model never writes this extractor.
- `client.py` - transport only (Ollama native or OpenAI-compatible), loopback-enforced, urllib-only.
- `generator.py` - builds the short prompt, runs the generate -> validate -> retry loop.
- `validator.py` - schema, regex safety (regex mode only), match rate, required-field coverage, report.
- `generate.py` - the CLI (`python -m ulpf.llm.generate`): read samples, generate, show, approve, save.
- `ulpf/parsers/dynamic.py` - loads approved configs from `ulpf/mappings/*.yaml` at registration time and tokenizes with `structure.py`.

None of this executes model-authored code. Structured modes have no regex
at all. Regex mode (unstructured text only) compiles `line_regex` with
`re.compile` and uses it only for `.match()` / `.groupdict()` - in the
validator and in `dynamic.py`, nowhere else - and rejects more than 6
capture groups. There is no `eval`/`exec` in any of these files.

### Client (`ulpf/llm/client.py`)

`OllamaClient.generate(prompt)` POSTs to `http://<host>:<port>/api/generate`
with `stream: false`, `format: "json"`, `options.temperature: 0` (deterministic
output) and returns the `response` field's text. `OpenAICompatClient` does
the same against `<base_url>/chat/completions` (`response_format:
{"type": "json_object"}`), for `--backend openai` (e.g. llama.cpp's server,
LM Studio). Both constructors call `require_loopback(host)` - checked
against a fixed allow-list (`127.0.0.1`, `localhost`, `::1`), not a DNS
resolve-and-check - **before any socket is opened**, raising
`NonLoopbackHostError` immediately for anything else. A connection failure
(Ollama not running) raises `LLMConnectionError` with a message pointing at
`--replay` as the fallback, rather than a raw `URLError` traceback.

Model defaults to `qwen2.5-coder:3b`; resolution order is `--model` flag >
`ULPF_LLM_MODEL` env var > the built-in default (in that order - `--model`
was initially given an argparse `default=`, which meant the env var could
never actually take effect since the flag always looked "explicitly set";
fixed by defaulting `--model` to `None` and resolving the three-way
precedence by hand after parsing).

### Structure (`ulpf/llm/structure.py`)

`tokenize(line)` splits an optional syslog prefix first (RFC 5424, RFC 3164
with or without `<PRI>`, or a bare `<PRI>`), then classifies the body:

- a JSON object, flattened one level (`event.action` for a nested key);
- a CEF or LEEF header plus its extension (header fields are `cef_*` /
  `leef_*`; extension pairs are ordinary keys; both are mode `cef`);
- key=value, where a value may be double-quoted and may contain spaces and
  backslash escapes (`\"`, `\\`, `\n`, `\t`, `\r`).

Mode is `syslog_kv` when a syslog header is followed by at least one
key=value pair, `kv` when there is no header and at least two pairs (one
stray `token=value` in a sentence is not a kv log), and `regex` otherwise.
`example_values` keeps at most two distinct values per key. `route_for`
is the `detect.py` format (a `<PRI>` line routes as `syslog` even when the
body's mode is `cef`). `attach_route` stamps that onto `format_hint`; the
model does not choose it.

### Prompt (`ulpf/llm/generator.py`, `build_prompt`)

For a structured mode the prompt lists source keys and up to two example
values. It does not include the raw lines, a few-shot YAML mapping, or a
request for a regex. It asks for `field_map` (internal field -> source
key) plus the short shell of vendor, product, mode, action rules,
timestamp, and category. The first prompt stays under ~800 tokens
(`PROMPT_TOKEN_BUDGET`, counted as 4 characters per token). Model size
does not change the prompt: the old second few-shot file (`cisco_asa.yaml`
for 7b+) is gone, because those hand-written `fields:` sections map
raw-key -> internal-field, the opposite direction from `field_map`, and a
3b model copied that direction.

Regex mode is only when `detect_mode` is `regex`. That prompt shows the
lines (there are no keys) and asks for `line_regex` with at most 6 named
groups.

Retries (default up to 2, so 3 attempts total) feed the previous attempt's
JSON, `ValidationReport.error_summary()`, and an explicit
`Unmapped required fields:` line back into the next prompt.

### Config schema (`ulpf/llm/validator.py`)

```json
{
  "vendor": "string",
  "product": "string",
  "mode": "kv | json | cef | syslog_kv | regex",
  "field_map": {"<internal field>": "<source key, or regex group name in regex mode>"},
  "action_rules": [{"match_value": "<raw captured action>", "action": "<canonical action>"}],
  "timestamp": {"keys": ["<source key>", "..."], "format": "free-text description"},
  "category": "network | authentication"
}
```

`kv` / `json` / `cef` / `syslog_kv` must not contain `line_regex`. Regex
mode is the only one that does, and only when the samples themselves are
unstructured; pointing regex mode at structured samples is a schema error
and the pattern is not compiled. `line_regex` may have at most 6 capture
groups (`structure.MAX_CAPTURE_GROUPS`).

`field_map` keys are restricted to `validator.ALLOWED_FIELD_MAP_TARGETS`,
a subset of `schema.EVENT_KEYS` that excludes identity/provenance/parse
fields the pipeline owns. An unknown internal field is a schema error.
An unknown *source* key (or, in regex mode, a group name that is not in
the pattern) is also a schema error and names the keys that do exist, so
the retry can fix a hallucinated key instead of dropping data. `format_hint`
is not model output; `structure.attach_route` sets it to the detect.py
format before the config is saved.

### Validation (`ulpf/llm/validator.validate`)

1. **Schema.** Required keys present with the right types; `mode` in the
   allowed set; no `line_regex` on a structured mode; every `field_map`
   key in the allow-list above; every `action_rules` entry has
   `match_value`/`action`; `timestamp.keys` is a list of strings and
   `timestamp.format` is a string; every string value anywhere in the
   config (recursively) is scanned for code-like markers (`"import "`,
   `"def "`, `"eval("`, `"__import__"`, ...) and rejected if found.
2. **Regex safety (regex mode only).** `re.compile` must succeed, the
   pattern must have <= 6 capture groups, then a catastrophic-backtracking
   guard runs it against 2 short adversarial strings (`"a"*30 + "!"`,
   `"0"*30 + "x"`) with a 1-second-per-string timeout. **This guard uses
   a subprocess, not a thread, and that's not incidental** - verified
   directly during development: CPython's `re` engine does not release
   the GIL during a match, so a thread-based timeout left the *entire
   interpreter* unresponsive for 30+ seconds on `^(a+)+$` against the
   exact stress string used here. A `multiprocessing` child can be
   `.terminate()`d regardless. If spawning the probe fails (`OSError`),
   the regex is treated as unsafe. Structured modes never compile a
   model regex, including one smuggled in next to `mode: kv`.
3. **Match rate.** A line is mapped when `structure.tokenize` returns the
   config's mode and a non-empty field dict (regex mode: `.match`
   succeeds). At least 80% of the sample lines must map. Same tokenizer
   `dynamic.py` uses at runtime.
4. **Required-field coverage.** For each *mapped* line, the same oracle
   regexes `ulpf/parsers/generic.py` uses (`IPV4_RE` / `IPV6_RE` /
   `ISO_TS_RE` / `SYSLOG_TS_RE` / `ACTION_RE`) decide whether that line
   plainly contains a src/dst IP, a timestamp, or an action word.
   `required_field_rate` is the fraction of those that `field_map` plus
   `timestamp.keys` actually captured. Below 80%, `unmapped_required`
   lists the internal field names and the retry prompt repeats them.
5. **Report.** `ValidationReport(ok, score, schema_errors, regex_error,
   catastrophic_backtracking, match_rate, required_field_rate,
   unmapped_required, per_line)`. `ok` requires match_rate >= 0.8 and
   required_field_rate >= 0.8, and no schema/regex/backtracking errors.
   `score = 0.6 * match_rate + 0.4 * required_field_rate`.
   `check_backtracking=False` skips the ReDoS guard - used by the
   generator-loop tests. `validate_schema_only(config)` runs steps 1-2
   with no sample lines, for `--replay` without `--samples`.

### Dynamic parser loading (`ulpf/parsers/dynamic.py`)

"No new Python file per vendor": one module handles every LLM-onboarded
vendor. `register(registry)` scans `ulpf/mappings/*.yaml` for configs
carrying `generator: "ulpf.llm"` (written by `generate.py` on approval;
absent from every hand-written mapping, so `dynamic._load_dynamic_configs`
never picks those up) and builds one closure per vendor via `_make_parser`,
registered under that vendor's `format_hint` (the detect.py route).

Structured modes call `structure.tokenize` and apply `field_map`. The
closure returns `None` unless the line's mode matches and at least one
mapped source key is present, so a kv config does not claim every kv line.
Timestamp keys are joined in listed order when `field_map` did not already
set `timestamp`. A config that still has `line_regex` and no `mode` (the
previous generator's shape) still loads, without the 6-group cap; new
regex-mode configs are capped.

**Existing parsers keep priority.** `ulpf/parsers/__init__.py`'s module
discovery sorts `dynamic` to load *last*, regardless of alphabetical
position (`paths.sort(key=lambda p: (p.stem == "dynamic", p.stem))`) - not
an accident of filename ordering. Since the registry tries parsers for a
given format in registration order and stops at the first non-`None`
result, every hand-written vendor parser always gets first refusal on a
line before any dynamic one is tried, for every format. Verified directly:
a deliberately over-broad dynamic "kv" config that *would* match a
FortiGate-shaped line never actually claims one, because `fortigate.py`
(registered first) already returns a result for it
(`test_existing_hand_written_parser_still_wins_over_a_dynamic_one`).

**Registration is idempotent per file, not just per process.**
`register()` runs once per `ulpf.pipeline.load_mappings()` call - i.e.
every `ulpf.pipeline.run()` and every `ulpf.ingest.IngestServer` start -
and `ulpf/detect.py`'s `register()` dedupes repeat registrations by
function *identity*. A closure built fresh from the same YAML file on every
call would never be `is` any previous closure, so the registry would grow
without bound across repeated runs in one process. `dynamic._PARSER_CACHE`
(keyed by mapping file path) avoids this by reusing the same closure object
for a given path across calls - the same reason hand-written parsers don't
have this problem (their `parse` function is a single module-level def,
never recreated). Trade-off: editing a dynamic mapping's YAML in place
without restarting the process won't be picked up mid-session - the same
limitation every hand-written parser's *code* already has (only its
mapping's *content* hot-reloads per line, never its code), so this isn't a
new inconsistency.

A malformed/hand-edited dynamic config (bad regex, missing keys) is skipped
silently at registration time rather than raised - a broken one-vendor
config must never take down the whole pipeline at startup.

### CLI (`ulpf/llm/generate.py`)

`python -m ulpf.llm.generate --samples <file> [--vendor NAME] [--auto-approve]
[--model NAME] [--backend ollama|openai] [--host H] [--port P] [--base-url URL]
[--out-dir DIR] [--replay saved_config.json]`

Flow: generate (or replay) -> print config + validation report -> `y/n`
prompt (skipped by `--auto-approve`) -> on approval, write
`ulpf/mappings/<slugified-vendor>.yaml` (with `generator: ulpf.llm` added)
and append a `{vendor, seconds, validator_score, approved_at}` record to
`<out-dir>/onboarding.json` (a JSON array - one record per approved
onboarding over time, not overwritten, so it doubles as a history/audit
log).

`--auto-approve` refuses to approve a config that failed validation
(`report.ok is False`) - exits `5` instead, printing why. A human
approving interactively can still override and save it anyway (the prompt
prints an explicit warning first) - `--auto-approve` exists for unattended/
demo automation, where silently saving a known-bad config would be the
wrong default; a human in the loop can make that call, an unattended flag
should not.

`--replay <path>` loads a previously saved JSON config with **no model
call at all** - the demo-safety fallback for when Ollama isn't reachable.
With `--samples` also given, the replayed config is validated normally
against them; without `--samples`, `validate_schema_only` still checks it's
well-formed rather than trusting a replay file blindly.

## Manual verification

```bash
python -m ulpf.pipeline samples out
python -m pytest tests/ -v
```

Then check `out/ocsf.jsonl`:

- Every line has the same fixed key set as `ulpf.ocsf.OCSF_KEYS`.
- The Suricata line has `class_uid: 2004` ("Security Finding") even though
  its `events.jsonl` counterpart has `event.category: "network"`.
- The sshd line has `class_uid: 3002` ("Authentication").
- All other lines (including the garbage Cisco line) have `class_uid: 4001`
  ("Network Activity").
- `metadata.raw_data_hash` on any `ocsf.jsonl` row matches `raw_hash` for
  the same line in `raw.jsonl`.

And `samples/messy.log` in particular (see `tests/test_generic.py` for the
full set of 15):

- `out/raw.jsonl` has one row with `raw_text_lossy: true` and a non-empty
  `raw_bytes_b64` — base64-decoding it contains a `0xFF` byte that doesn't
  decode as UTF-8.
- One row's `raw_text` contains two embedded `\n` characters (the
  multiline stack-trace record) and still parsed with `observer.vendor:
  "Check Point"`.
- Several rows have `parse.status: "partial"` and `parse.parser:
  "generic"` with `parse.confidence` between 0 and 1.
- The line starting `zzz qqq xkcd` has `parse.status: "failed"` — pure
  noise with no recoverable signal still fails cleanly.

Then check `out/quality.json`:

- `overall.total_events` is `23`, and the `total_events` across every entry
  in `sources` sums back to `23`.
- The `"cisco.log"` group (the original garbage line's vendor-less bucket)
  has `failed_pct: 100.0`.
- The `"Zscaler"` group's `top_unmapped_keys` includes `"sip"` and `"dip"`
  (the messy CEF line's nonstandard extension keys that `cef.yaml` doesn't map).

And integrity verification:

```bash
python -m ulpf.verify out
```

should print `"ok": true` and exit `0` on a freshly generated `out/`. Hand-edit
one `raw_text` in `out/raw.jsonl` (leave `raw_hash` alone) and rerun it — it
should print a `raw_hash_mismatch` entry for that `raw_event_id` and exit `1`.

And live ingest / export:

```bash
python -m ulpf.ingest out --port 5514 &
printf '<134>Sep 28 09:00:00 host app[1]: action=deny src=10.1.1.1 dst=10.1.1.2\n' \
  | nc -u 127.0.0.1 5514
python -m ulpf.export opensearch out --output out/bulk.ndjson
python -m ulpf.export parquet out
```

- `out/events.jsonl` gains one more row with `network.src_ip: "10.1.1.1"`
  and `raw.jsonl`'s matching row has `source_file` starting with
  `"127.0.0.1:"` (the sender's port, not a filename).
- `out/quality.json`'s `overall.total_events` grows by exactly 1.
- `out/bulk.ndjson` has `2 * out/ocsf.jsonl line count` lines, alternating
  `{"index": {...}}` and the event itself.
- `out/export.parquet` exists and (with `pyarrow` installed) reads back the
  same row count as `out/ocsf.jsonl` has lines.

And the LLM parser generator, with no model running (demo-safe, no Ollama needed):

```bash
echo 'src=10.9.9.1 dst=10.9.9.2 act=deny' > /tmp/samples.txt
echo 'src=10.9.9.3 dst=10.9.9.4 act=allow' >> /tmp/samples.txt
echo 'src=10.9.9.5 dst=10.9.9.6 act=deny' >> /tmp/samples.txt
cat > /tmp/config.json <<'EOF'
{"vendor": "DemoVendor", "product": "DemoBox", "mode": "kv",
 "field_map": {"network.src_ip": "src", "network.dst_ip": "dst", "event.action": "act"},
 "action_rules": [{"match_value": "deny", "action": "deny"}],
 "timestamp": {"keys": [], "format": ""}, "category": "network"}
EOF
python -m ulpf.llm.generate --replay /tmp/config.json --samples /tmp/samples.txt --auto-approve
python -m ulpf.pipeline samples out   # (with a matching line dropped into samples/)
```

- The validation report prints `ok: True`, `match_rate: 100%`.
- `ulpf/mappings/demovendor.yaml` is created, with `generator: ulpf.llm` in it.
- `out/onboarding.json` gains a record with `"vendor": "DemoVendor"`.
- A fresh `python -m ulpf.pipeline` run (new process) against a line shaped
  like the samples now reports `parse.status: "ok"`,
  `parse.parser: "llm:DemoVendor"` - proving the mapping is live without
  any code change, not just validated in isolation.
- Passing a non-loopback `--host` (e.g. `--host 8.8.8.8`) exits immediately
  with a `NonLoopbackHostError` message, before any network attempt.
