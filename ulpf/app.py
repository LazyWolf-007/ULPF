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


def _device_names(events: list[dict[str, Any]]) -> str:
    """Distinct vendors, first-seen. Products stay in the table."""
    seen: list[str] = []
    for event in events:
        vendor = str(event.get("observer.vendor") or "").strip()
        if vendor and vendor not in seen:
            seen.append(vendor)
    return ", ".join(seen)


def _dash(value: object) -> str:
    """Visible placeholder for an empty Time, Device, or Product cell."""
    text = str(value or "").strip()
    return html.escape(text) if text else "—"


def render_html(events: list[dict[str, Any]], query: str = "") -> str:
    data = page_data(events, query)
    summary = data["summary"]
    devices = html.escape(_device_names(events))
    top_items = "".join(
        "<li><button type=\"button\" data-ip=\"{ip}\">{ip}</button> {count}</li>".format(
            ip=html.escape(ip, quote=True),
            count=count,
        )
        for ip, count in data["top_sources"]
    )
    rows = []
    for event in data["rows"]:
        raw_text = str(event.get("provenance.raw_text") or "")
        raw_hash = str(event.get("provenance.raw_hash") or "")
        src = str(event.get("network.src_ip") or "")
        dst = str(event.get("network.dst_ip") or "")
        vendor = str(event.get("observer.vendor") or "")
        action = str(event.get("event.action") or "")
        outcome = str(event.get("event.outcome") or "")
        status = str(event.get("parse.status") or "")
        failed = " failed" if status == "failed" else ""
        rows.append(
            f'<tr class="{failed.strip()}"'
            f' data-src="{html.escape(src, quote=True)}"'
            f' data-dst="{html.escape(dst, quote=True)}"'
            f' data-vendor="{html.escape(vendor, quote=True)}"'
            f' data-action="{html.escape(action, quote=True)}"'
            f' data-outcome="{html.escape(outcome, quote=True)}"'
            f' data-raw="{html.escape(raw_text, quote=True)}"'
            f' data-hash="{html.escape(raw_hash, quote=True)}"'
            ">"
            f"<td>{_dash(event.get('timestamp'))}</td>"
            f"<td>{_dash(vendor)}</td>"
            f"<td>{_dash(event.get('observer.product'))}</td>"
            f"<td>{html.escape(src)}</td>"
            f"<td>{html.escape(dst)}</td>"
            f"<td>{html.escape(action)}</td>"
            f"<td>{html.escape(outcome)}</td>"
            f"<td>{html.escape(status)}</td>"
            "</tr>"
        )
    table_body = "\n".join(rows) if rows else '<tr class="empty"><td colspan="8">No matching events</td></tr>'
    q = html.escape(query, quote=True)
    fail_class = " bad" if summary["failed_parses"] else ""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ULPF events</title>
  <style>
    html {{ font-size: 20px; }}
    body {{
      margin: 0.35rem 0.7rem 1.2rem;
      background: #fff;
      color: #111;
      font-family: "Segoe UI", Arial, sans-serif;
      line-height: 1.2;
    }}
    h1 {{ font-size: 1.35rem; line-height: 1.1; margin: 0; }}
    h2 {{ font-size: 1rem; margin: 0; }}
    .who {{ margin: 0.05rem 0 0.3rem; }}
    .summary {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.15rem 1.4rem;
      margin: 0 0 0.3rem;
    }}
    .summary b {{ display: block; font-size: 1.45rem; line-height: 1; }}
    .summary .bad b {{ color: #9b0f24; }}
    .sources {{
      display: flex;
      flex-wrap: wrap;
      align-items: center;
      gap: 0.2rem 0.7rem;
      margin: 0 0 0.25rem;
    }}
    .sources ol {{
      display: flex;
      flex-wrap: wrap;
      gap: 0.15rem 0.75rem;
      list-style: none;
      margin: 0;
      padding: 0;
    }}
    button[data-ip] {{
      font: inherit;
      font-weight: 700;
      color: #fff;
      background: #111;
      border: 2px solid #111;
      padding: 0.05rem 0.4rem;
      cursor: pointer;
    }}
    .filter {{ display: flex; flex-wrap: wrap; align-items: center; gap: 0.4rem 0.7rem; margin: 0; }}
    label {{ font-weight: 700; }}
    input {{
      font: inherit;
      width: 16rem;
      max-width: 100%;
      padding: 0.08rem 0.4rem;
      border: 2px solid #111;
      background: #fff;
      color: #111;
    }}
    a.download {{
      color: #111;
      background: #fff;
      border: 2px solid #111;
      padding: 0.08rem 0.45rem;
      font-weight: 700;
      text-decoration: none;
    }}
    #match-note {{ margin: 0; font-weight: 800; }}
    #match-note:not(:empty) {{ margin: 0.15rem 0; }}
    .columns {{ margin: 0.2rem 0 0.1rem; font-weight: 700; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 2px solid #111; padding: 0.12rem 0.4rem; text-align: left; vertical-align: top; }}
    th {{ background: #111; color: #fff; }}
    tbody tr {{ cursor: pointer; }}
    tbody tr.failed {{ background: #9b0f24; color: #fff; font-weight: 700; }}
    tbody tr.selected {{ background: #ffe566; color: #111; }}
    tbody tr.selected td:first-child {{ box-shadow: inset 10px 0 0 #111; }}
    tbody tr.failed.selected {{ background: #9b0f24; color: #fff; }}
    tbody tr.failed.selected td:first-child {{ box-shadow: inset 10px 0 0 #ffe566; }}
    #detail {{ border-top: 4px solid #111; margin-top: 0.6rem; }}
    #detail h2 {{ margin-top: 0.45rem; }}
    #raw-line, #raw-hash {{
      font-family: Consolas, "Courier New", monospace;
      font-size: 0.95rem;
      white-space: pre-wrap;
      word-break: break-word;
      margin: 0 0 0.2rem;
    }}
    .caption {{ margin: 0 0 0.15rem; }}
    #same-source table {{ margin-top: 0.3rem; }}
    @media (max-width: 800px) {{
      html {{ font-size: 18px; }}
    }}
  </style>
</head>
<body>
  <h1>Many device dialects. One table.</h1>
  <p class="who">{devices}</p>
  <p class="summary">
    <span><b>{summary["event_count"]}</b> Events</span>
    <span class="{fail_class.strip()}"><b>{summary["failed_parses"]}</b> Failed parses</span>
    <span><b>{summary["distinct_vendors"]}</b> Distinct vendors</span>
    <span><b>{summary["authentication_failures"]}</b> Authentication failures</span>
  </p>
  <div class="sources">
    <h2>Busiest source IPs</h2>
    <ol>{top_items}</ol>
  </div>
  <div class="filter">
    <label for="ip-filter">Source or destination</label>
    <input id="ip-filter" type="text" value="{q}" autocomplete="off">
    <a class="download" href="/events.jsonl" download="events.jsonl">Download events.jsonl</a>
  </div>
  <p id="match-note"></p>
  <p class="columns">One set of columns for every device.</p>
  <table>
    <thead>
      <tr>
        <th>Time</th><th>Device</th><th>Product</th><th>Source</th>
        <th>Destination</th><th>Action</th><th>Result</th><th>Parse</th>
      </tr>
    </thead>
    <tbody id="event-rows">{table_body}</tbody>
  </table>
  <section id="detail">
    <h2>Original line</h2>
    <p class="caption">Kept as it arrived.</p>
    <p id="raw-line">Click a row.</p>
    <h2>Hash</h2>
    <p id="raw-hash"></p>
    <h2>Same source</h2>
    <div id="same-source"></div>
  </section>
  <script>
    const box = document.getElementById("ip-filter");
    const rows = Array.from(document.querySelectorAll("#event-rows tr[data-src]"));
    const rawLine = document.getElementById("raw-line");
    const rawHash = document.getElementById("raw-hash");
    const same = document.getElementById("same-source");
    const note = document.getElementById("match-note");
    let selected = null;

    function clearDetail() {{
      rawLine.textContent = "Click a row.";
      rawHash.textContent = "";
      same.textContent = "";
    }}

    function showSameSource(row) {{
      same.replaceChildren();
      const src = row.dataset.src || "";
      if (!src) {{
        same.textContent = "This row has no source address.";
        return;
      }}
      const others = rows.filter((other) => other !== row && (other.dataset.src || "") === src);
      if (!others.length) {{
        same.textContent = "No other row has this source.";
        return;
      }}
      const table = document.createElement("table");
      const head = document.createElement("tr");
      ["Device", "Action", "Result"].forEach((label) => {{
        const cell = document.createElement("th");
        cell.textContent = label;
        head.appendChild(cell);
      }});
      const headRow = document.createElement("thead");
      headRow.appendChild(head);
      table.appendChild(headRow);
      const body = document.createElement("tbody");
      others.forEach((other) => {{
        const line = document.createElement("tr");
        [other.dataset.vendor || "", other.dataset.action || "", other.dataset.outcome || ""].forEach((value) => {{
          const cell = document.createElement("td");
          cell.textContent = value;
          line.appendChild(cell);
        }});
        body.appendChild(line);
      }});
      table.appendChild(body);
      same.appendChild(table);
    }}

    function applyFilter() {{
      const q = box.value.toLowerCase();
      rows.forEach((row) => {{
        const src = (row.dataset.src || "").toLowerCase();
        const dst = (row.dataset.dst || "").toLowerCase();
        row.hidden = Boolean(q) && !src.includes(q) && !dst.includes(q);
      }});
      if (selected && selected.hidden) {{
        selected.classList.remove("selected");
        selected = null;
        clearDetail();
      }}
      const shown = rows.filter((row) => !row.hidden);
      const devices = [];
      shown.forEach((row) => {{
        const name = row.dataset.vendor || "";
        if (name && !devices.includes(name)) devices.push(name);
      }});
      if (q && devices.length >= 2) {{
        note.textContent = box.value.trim() + " is the same address on " + devices.join(", ") + ".";
      }} else if (q) {{
        note.textContent = String(shown.length) + (shown.length === 1 ? " row." : " rows.");
      }} else {{
        note.textContent = "";
      }}
    }}

    box.addEventListener("input", applyFilter);
    document.querySelectorAll("button[data-ip]").forEach((button) => {{
      button.addEventListener("click", () => {{
        box.value = button.dataset.ip || "";
        applyFilter();
      }});
    }});
    rows.forEach((row) => {{
      row.addEventListener("click", () => {{
        if (row.hidden) return;
        rows.forEach((other) => other.classList.remove("selected"));
        row.classList.add("selected");
        selected = row;
        rawLine.textContent = row.dataset.raw || "";
        rawHash.textContent = row.dataset.hash || "";
        showSameSource(row);
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
