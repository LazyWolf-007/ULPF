"""Live syslog ingest: UDP + TCP listeners bound to 127.0.0.1.

Every received message runs through the exact same detect -> parse ->
finalize -> OCSF path as `ulpf.pipeline.run` (both call
`ulpf.pipeline.process_record`), so a line captured live and a line read
from a file produce identically-shaped output. Records are appended to
`raw.jsonl`/`events.jsonl`/`ocsf.jsonl` in `output_dir`, and `quality.json`
is rebuilt after each one.

There is no source *file* for a live message, so `raw_record["source_file"]`
(and therefore the `quality.json` grouping key, when `observer.vendor` is
unknown) holds the sender's `"host:port"` address instead.
"""

from __future__ import annotations

import argparse
import json
import socketserver
import threading
from pathlib import Path
from typing import Any

from ulpf.pipeline import load_mappings, process_record
from ulpf.quality import build_report

DEFAULT_PORT = 5514  # non-privileged; the standard syslog port 514 needs root


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _decode(raw_bytes: bytes) -> tuple[str, bool]:
    try:
        return raw_bytes.decode("utf-8"), False
    except UnicodeDecodeError:
        return raw_bytes.decode("utf-8", errors="replace"), True


class _Writer:
    """Appends one record's raw/event/ocsf rows and keeps quality.json
    current. Shared (with a lock) between the UDP and TCP listener threads.
    """

    def __init__(self, output_dir: str | Path) -> None:
        self.destination = Path(output_dir)
        self.destination.mkdir(parents=True, exist_ok=True)
        self.mappings = load_mappings()
        self._lock = threading.Lock()
        self._raw_path = self.destination / "raw.jsonl"
        self._events_path = self.destination / "events.jsonl"
        self._ocsf_path = self.destination / "ocsf.jsonl"
        self._quality_path = self.destination / "quality.json"
        # Bootstrap from whatever's already on disk (e.g. a prior
        # `ulpf.pipeline` run over samples/) so quality.json stays
        # representative of the whole directory, not just this session.
        self._quality_records = self._bootstrap_quality_records()

    def _bootstrap_quality_records(self) -> list[tuple[str, str, str, dict[str, Any], dict[str, Any]]]:
        raw_rows = _load_jsonl(self._raw_path)
        event_rows = _load_jsonl(self._events_path)
        ocsf_rows = _load_jsonl(self._ocsf_path)
        records: list[tuple[str, str, str, dict[str, Any], dict[str, Any]]] = []
        for raw, event, ocsf_event in zip(raw_rows, event_rows, ocsf_rows):
            records.append(
                (
                    str(event.get("observer.vendor") or ""),
                    str(raw.get("source_file") or ""),
                    str(event.get("parse.status") or ""),
                    ocsf_event,
                    event.get("unmapped") or {},
                )
            )
        return records

    def handle_message(self, raw_bytes: bytes, source_label: str) -> dict[str, Any] | None:
        raw_bytes = raw_bytes.rstrip(b"\r\n")
        if raw_bytes.strip() == b"":
            return None
        text, is_lossy = _decode(raw_bytes)

        with self._lock:
            raw_record, event, ocsf_event = process_record(
                raw_text=text,
                raw_bytes=raw_bytes,
                is_lossy=is_lossy,
                source_label=source_label,
                mappings=self.mappings,
            )
            with self._raw_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(raw_record, ensure_ascii=False) + "\n")
            with self._events_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
            with self._ocsf_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(ocsf_event, ensure_ascii=False) + "\n")

            self._quality_records.append(
                (
                    str(event.get("observer.vendor") or ""),
                    source_label,
                    str(event.get("parse.status") or ""),
                    ocsf_event,
                    event.get("unmapped") or {},
                )
            )
            report = build_report(self._quality_records)
            self._quality_path.write_text(
                json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
            )

        return event


class _UDPHandler(socketserver.BaseRequestHandler):
    server: "_UDPServer"

    def handle(self) -> None:
        data: bytes = self.request[0]
        source_label = f"{self.client_address[0]}:{self.client_address[1]}"
        self.server.writer.handle_message(data, source_label)


class _TCPHandler(socketserver.StreamRequestHandler):
    server: "_TCPServer"

    def handle(self) -> None:
        # RFC 6587-style plain TCP framing: one newline-delimited message
        # per line; a connection can carry many messages.
        source_label = f"{self.client_address[0]}:{self.client_address[1]}"
        for raw_line in self.rfile:
            if raw_line.strip():
                self.server.writer.handle_message(raw_line, source_label)


class _UDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], writer: _Writer) -> None:
        self.writer = writer
        super().__init__(address, _UDPHandler)


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], writer: _Writer) -> None:
        self.writer = writer
        super().__init__(address, _TCPHandler)


class IngestServer:
    """Binds a UDP and a TCP syslog listener to the same host:port.

    Both feed every received message through `ulpf.pipeline.process_record`
    - the identical path `ulpf.pipeline.run` uses for files - appending
    into `output_dir`. Defaults to 127.0.0.1, matching the rest of ULPF's
    local-only listeners (see `ulpf.app`); `host`/`port` are still
    parameters, same convention as `ulpf.app.bind_local_server`.
    """

    def __init__(
        self, output_dir: str | Path, host: str = "127.0.0.1", port: int = DEFAULT_PORT
    ) -> None:
        self.writer = _Writer(output_dir)
        self.udp_server = _UDPServer((host, port), self.writer)
        # Bind TCP to the port UDP actually resolved to, so `port=0` (an
        # OS-assigned free port, used in tests) still gives both protocols
        # the *same* port - independent binds would each get their own.
        resolved_port = self.udp_server.server_address[1]
        self.tcp_server = _TCPServer((host, resolved_port), self.writer)
        self._threads: list[threading.Thread] = []

    @property
    def host(self) -> str:
        return self.udp_server.server_address[0]

    @property
    def port(self) -> int:
        return self.udp_server.server_address[1]

    def start(self) -> None:
        for server in (self.udp_server, self.tcp_server):
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        self.udp_server.shutdown()
        self.tcp_server.shutdown()
        self.udp_server.server_close()
        self.tcp_server.server_close()
        for thread in self._threads:
            thread.join(timeout=5)
        self._threads.clear()

    def __enter__(self) -> "IngestServer":
        self.start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.stop()


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="ulpf.ingest")
    parser.add_argument("out_dir")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args(argv)

    server = IngestServer(args.out_dir, host=args.host, port=args.port)
    server.start()
    print(f"listening udp+tcp on {args.host}:{args.port}, writing to {args.out_dir}", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


if __name__ == "__main__":
    main()
