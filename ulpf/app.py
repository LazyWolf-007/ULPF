from __future__ import annotations

import argparse
import html
import json
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse



def load_events(events_path: str | Path) -> list[dict[str, Any]]:
    path = Path(events_path)
    if not path.is_file():
        return []
    events: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line:
            events.append(json.loads(line))
    return events


def summarize(events: list[dict[str, Any]]) -> dict[str, int]:
    vendors = {str(event.get("observer.vendor") or "") for event in events}
    vendors.discard("")
    return {
        "event_count": len(events),
        "failed_parses": sum(1 for event in events if event.get("parse.status") == "failed"),
        "distinct_vendors": len(vendors),
        "authentication_failures": sum(
            1
            for event in events
            if event.get("event.category") == "authentication"
            and event.get("event.outcome") == "failure"
        ),
    }


def busiest_source_ips(events: list[dict[str, Any]], limit: int = 5) -> list[tuple[str, int]]:
    counts: Counter[str] = Counter()
    for event in events:
        ip = str(event.get("network.src_ip") or "")
        if ip:
            counts[ip] += 1
    return counts.most_common(limit)


def filter_events(events: list[dict[str, Any]], query: str) -> list[dict[str, Any]]:
    text = (query or "").strip().lower()
    if not text:
        return list(events)
    visible: list[dict[str, Any]] = []
    for event in events:
        src = str(event.get("network.src_ip") or "").lower()
        dst = str(event.get("network.dst_ip") or "").lower()
        if text in src or text in dst:
            visible.append(event)
    return visible


def page_data(events: list[dict[str, Any]], query: str = "") -> dict[str, Any]:
    return {
        "summary": summarize(events),
        "top_sources": busiest_source_ips(events),
        "rows": filter_events(events, query),
    }


def render_html(events: list[dict[str, Any]], query: str = "") -> str:
    data = page_data(events, query)
    summary = data["summary"]
    top_items = "".join(
        f"<li><code>{html.escape(ip)}</code> — {count}</li>" for ip, count in data["top_sources"]
    )
    rows = []
    for event in data["rows"]:
        raw_text = str(event.get("provenance.raw_text") or "")
        raw_hash = str(event.get("provenance.raw_hash") or "")
        src = str(event.get("network.src_ip") or "")
        dst = str(event.get("network.dst_ip") or "")
        rows.append(
            "<tr"
            f' data-src="{html.escape(src, quote=True)}"'
            f' data-dst="{html.escape(dst, quote=True)}"'
            f' data-raw="{html.escape(raw_text, quote=True)}"'
            f' data-hash="{html.escape(raw_hash, quote=True)}"'
            ">"
            f"<td>{html.escape(str(event.get('timestamp') or ''))}</td>"
            f"<td>{html.escape(str(event.get('observer.vendor') or ''))}</td>"
            f"<td>{html.escape(str(event.get('observer.product') or ''))}</td>"
            f"<td>{html.escape(src)}</td>"
            f"<td>{html.escape(dst)}</td>"
            f"<td>{html.escape(str(event.get('event.action') or ''))}</td>"
            f"<td>{html.escape(str(event.get('event.outcome') or ''))}</td>"
            f"<td>{html.escape(str(event.get('parse.status') or ''))}</td>"
            "</tr>"
        )
    table_body = "\n".join(rows) if rows else '<tr class="empty"><td colspan="8">No matching events</td></tr>'
    q = html.escape(query, quote=True)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ULPF events</title>
  <style>
    :root {{ color-scheme: dark; }}
    body {{ font-family: Segoe UI, sans-serif; margin: 1.5rem; background: #111; color: #eee; }}
    h1 {{ font-size: 1.2rem; }}
    .summary, .sources, .filter, table, #detail {{ margin-bottom: 1rem; }}
    .summary span {{ margin-right: 1.25rem; }}
    input {{ width: 22rem; max-width: 100%; padding: 0.4rem; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #444; padding: 0.4rem 0.5rem; text-align: left; }}
    tbody tr {{ cursor: pointer; }}
    tbody tr:hover, tbody tr.selected {{ background: #2a2a2a; }}
    #detail {{ white-space: pre-wrap; background: #1a1a1a; padding: 0.75rem; min-height: 3rem; }}
    a.button {{ color: #9cf; }}
  </style>
</head>
<body>
  <h1>ULPF</h1>
  <p class="summary">
    <span>Events: {summary["event_count"]}</span>
    <span>Failed parses: {summary["failed_parses"]}</span>
    <span>Distinct vendors: {summary["distinct_vendors"]}</span>
    <span>Authentication failures: {summary["authentication_failures"]}</span>
  </p>
  <div class="sources">
    <strong>Busiest source IPs</strong>
    <ol>{top_items}</ol>
  </div>
  <p class="filter">
    <label>Filter by src_ip or dst_ip
      <input id="ip-filter" type="text" value="{q}" autocomplete="off">
    </label>
    <a class="button" href="/events.jsonl" download="events.jsonl">Download events.jsonl</a>
  </p>
  <table>
    <thead>
      <tr>
        <th>time</th><th>vendor</th><th>product</th><th>src_ip</th>
        <th>dst_ip</th><th>action</th><th>outcome</th><th>parse status</th>
      </tr>
    </thead>
    <tbody id="event-rows">{table_body}</tbody>
  </table>
  <div id="detail">Click a row to show provenance.</div>
  <script>
    const box = document.getElementById("ip-filter");
    const rows = Array.from(document.querySelectorAll("#event-rows tr[data-src]"));
    const detail = document.getElementById("detail");
    function applyFilter() {{
      const q = box.value.toLowerCase();
      rows.forEach((row) => {{
        const src = (row.dataset.src || "").toLowerCase();
        const dst = (row.dataset.dst || "").toLowerCase();
        row.hidden = Boolean(q) && !src.includes(q) && !dst.includes(q);
      }});
    }}
    box.addEventListener("input", applyFilter);
    rows.forEach((row) => {{
      row.addEventListener("click", () => {{
        rows.forEach((other) => other.classList.remove("selected"));
        row.classList.add("selected");
        detail.textContent = "raw_text: " + (row.dataset.raw || "") + "\\nraw_hash: " + (row.dataset.hash || "");
      }});
    }});
    applyFilter();
  </script>
</body>
</html>
"""


class EventHandler(BaseHTTPRequestHandler):
    out_dir: Path

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        events_path = self.out_dir / "events.jsonl"
        if parsed.path in {"/events.jsonl", "/download/events.jsonl"}:
            body = events_path.read_bytes() if events_path.is_file() else b""
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="events.jsonl"')
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        query = parse_qs(parsed.query).get("q", [""])[0]
        page = render_html(load_events(events_path), query).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(page)))
        self.end_headers()
        self.wfile.write(page)


def bind_local_server(out_dir: str | Path, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    EventHandler.out_dir = Path(out_dir)
    return ThreadingHTTPServer((host, 0), EventHandler)


def serve(out_dir: str | Path, host: str = "127.0.0.1") -> None:
    httpd = bind_local_server(out_dir, host)
    host_ip, port = httpd.server_address
    print(f"http://{host_ip}:{port}/", flush=True)
    httpd.serve_forever()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="ulpf.app")
    parser.add_argument("out_dir")
    parser.add_argument(
        "--rebuild",
        nargs="?",
        const="samples",
        default=None,
        metavar="INPUT_DIR",
        help="re-parse INPUT_DIR into out_dir before serving (default INPUT_DIR: samples)",
    )
    args = parser.parse_args(argv)
    out_dir = Path(args.out_dir)
    if args.rebuild is not None:
        from ulpf.pipeline import run

        run(args.rebuild, out_dir)
    serve(out_dir)


if __name__ == "__main__":
    main()
