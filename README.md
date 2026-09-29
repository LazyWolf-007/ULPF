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

The pipeline writes `out/raw.jsonl` and `out/events.jsonl`. The app prints a URL such as `http://127.0.0.1:<port>/`; open it in a browser to browse and filter events. To re-parse before serving, use `python -m ulpf.app out --rebuild` (defaults to input folder `samples`).

Run tests:

```bash
python -m pytest tests/ -v
```

## Output files

**`raw.jsonl`** — One JSON object per input line: raw event id, exact `raw_text`, SHA-256 `raw_hash`, source file name, and ingest timestamp. Use this when you need the untouched line or to verify hashing.

**`events.jsonl`** — One shared record per line with normalized fields (`network.*`, `observer.*`, `event.*`, `parse.*`, `provenance.*`, `unmapped`). Failed parses appear here with `parse.status` set to `failed` and provenance filled from the raw line.

## Adding a device

1. Add `ulpf/parsers/<name>.py` with `parse(line, mapping)` and `register(registry)` that registers for the correct format (`syslog`, `cef`, `json`, `kv`, etc.).
2. Add `ulpf/mappings/<name>.yaml` with defaults, field maps, and action rules.
3. Drop a sample file under `samples/` and re-run `python -m ulpf.pipeline samples out`.

Do not add vendor or product names to `pipeline.py`; discovery goes through the parser registry and YAML only.

## Air-gap

ULPF does not open outbound network connections. The only listener is the optional local viewer in `ulpf/app.py`, bound to `127.0.0.1` on your machine. No API keys or cloud credentials are used.

## Sample files (what to check)

| File | Field to verify |
|------|-----------------|
| `samples/cisco.log` | `user.name` (`jdoe` on the ASA line); `parse.status` (`failed` on the garbage line) |
| `samples/fortigate.log` | `network.transport` (`udp` / `tcp` from `proto`) |
| `samples/paloalto.log` | `observer.vendor` (`Palo Alto Networks`) |
| `samples/suricata.log` | `event.description` (`Allowed DNS Query`; timestamp from JSON, not ingest time) |
| `samples/sshd.log` | `event.category` (`authentication`) |
| `samples/checkpoint.log` | `observer.vendor` (`Check Point`) |

## Docker

If all tests pass in your tree, you can run the same pipeline and viewer in a single-container image (Python 3.12 only; no Kafka or other services):

```bash
docker build -t ulpf .
docker run --rm ulpf
```

The build step runs `python -m ulpf.pipeline samples out` inside the image. The container starts one process: `python -m ulpf.app out`, which prints a `http://127.0.0.1:<port>/` URL. On Linux, `docker run --rm --network host ulpf` lets you open that URL from the host.
