"""CLI: python -m ulpf.llm.generate --samples <file> [options]

Generates a parser config for an unrecognized log source from a handful of
sample lines, validates it, shows it (and the validation report) to a
human, and on approval writes `ulpf/mappings/<vendor>.yaml` - live in the
registry the next time anything calls `ulpf.pipeline.load_mappings()`
(every `ulpf.pipeline.run`, `ulpf.ingest.IngestServer` start, etc.).

Approval also appends a record to `out/onboarding.json`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from ulpf.llm import client as client_mod
from ulpf.llm import generator, structure, validator

PACKAGE_DIR = Path(__file__).resolve().parent.parent  # .../ulpf
MAPPINGS_DIR = PACKAGE_DIR / "mappings"

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _slugify(vendor: str) -> str:
    slug = _SLUG_RE.sub("_", vendor.strip().lower()).strip("_")
    return slug or "unknown_vendor"


def _read_samples(path: str | Path) -> list[str]:
    lines = [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines()]
    return [line for line in lines if line]


def _load_replay_config(path: str | Path) -> Any:
    """Load a config saved by `_save_mapping` (YAML) or the JSON replay form.

    `--replay` does not call a model. YAML is what approval writes; JSON is
    the form the manual examples use. Both are data, never code.
    """
    file = Path(path)
    text = file.read_text(encoding="utf-8")
    if file.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(text)
    return json.loads(text)


def _print_config_and_report(config: dict[str, Any] | None, report: validator.ValidationReport) -> None:
    print("\n--- Generated config ---")
    print(json.dumps(config, indent=2, ensure_ascii=False) if config else "(no config produced)")
    print("\n--- Validation report ---")
    print(f"ok: {report.ok}   score: {report.score}   match_rate: {report.match_rate:.0%}   "
          f"required_field_rate: {report.required_field_rate:.0%}")
    if not report.ok:
        print(f"errors: {report.error_summary()}")
    print("\nper-line:")
    for i, line_result in enumerate(report.per_line, start=1):
        status = "matched" if line_result.matched else "NO MATCH"
        missing = f" (missing: {', '.join(line_result.missing_required)})" if line_result.missing_required else ""
        print(f"  {i}. [{status}]{missing} {line_result.line[:80]}")


def _ask_approval(auto_approve: bool) -> bool:
    if auto_approve:
        print("\n--auto-approve set: approving without prompting.")
        return True
    try:
        answer = input("\nApprove and save this mapping? [y/N]: ").strip().lower()
    except EOFError:
        answer = ""
    return answer in ("y", "yes")


def _save_mapping(vendor: str, config: dict[str, Any]) -> Path:
    MAPPINGS_DIR.mkdir(parents=True, exist_ok=True)
    slug = _slugify(vendor)
    path = MAPPINGS_DIR / f"{slug}.yaml"
    to_write = dict(config)
    to_write["generator"] = "ulpf.llm"  # marks this for ulpf/parsers/dynamic.py to pick up
    path.write_text(yaml.safe_dump(to_write, sort_keys=False), encoding="utf-8")
    return path


def _record_onboarding(out_dir: Path, vendor: str, seconds: float, score: float) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "onboarding.json"
    records: list[dict[str, Any]] = []
    if path.is_file():
        try:
            records = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(records, list):
                records = []
        except json.JSONDecodeError:
            records = []
    records.append(
        {
            "vendor": vendor,
            "seconds": seconds,
            "validator_score": score,
            "approved_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
    )
    path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="ulpf.llm.generate")
    parser.add_argument("--samples", help="file with 3-10 sample log lines, one per line")
    parser.add_argument("--vendor", default=None, help="hint the vendor/product name to the model")
    parser.add_argument("--auto-approve", action="store_true", help="skip the y/n prompt")
    parser.add_argument(
        "--model",
        default=None,
        help=f"model name (default: {client_mod.DEFAULT_MODEL}, overridable via env ULPF_LLM_MODEL)",
    )
    parser.add_argument("--backend", choices=["ollama", "openai"], default="ollama")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=client_mod.DEFAULT_OLLAMA_PORT)
    parser.add_argument("--base-url", default=None, help="override for --backend openai")
    parser.add_argument("--out-dir", default="out", help="where to write onboarding.json (default: out)")
    parser.add_argument(
        "--replay",
        default=None,
        help="load a previously saved JSON or YAML config instead of calling the model (demo-safe fallback)",
    )
    args = parser.parse_args(argv)

    model = args.model or os.environ.get("ULPF_LLM_MODEL", client_mod.DEFAULT_MODEL)

    start = time.monotonic()
    if args.replay:
        config = _load_replay_config(args.replay)
        samples = _read_samples(args.samples) if args.samples else []
        if isinstance(config, dict):
            # format_hint is the detect.py route, not a model output.
            structure.attach_route(config, samples)
        if samples:
            report = validator.validate(config, samples)
        else:
            print("(no --samples given; checking schema/regex only, not match rate)")
            report = validator.validate_schema_only(config)
        seconds = round(time.monotonic() - start, 3)
        print(f"(replayed from {args.replay}, no model call made)")
    else:
        if not args.samples:
            parser.error("--samples is required unless --replay is given")
        samples = _read_samples(args.samples)
        if not (3 <= len(samples) <= 10):
            print(
                f"warning: {len(samples)} sample line(s) given; 3-10 is the sweet spot for this tool",
                file=sys.stderr,
            )
        try:
            llm_client = client_mod.make_client(
                backend=args.backend, host=args.host, port=args.port, base_url=args.base_url, model=model
            )
        except client_mod.NonLoopbackHostError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(2)

        try:
            result = generator.generate_config(llm_client, samples, vendor_hint=args.vendor)
        except client_mod.LLMConnectionError as exc:
            print(f"error: {exc}", file=sys.stderr)
            sys.exit(3)
        config, report, seconds = result.config, result.report, result.seconds

    _print_config_and_report(config, report)

    if config is None:
        print("\nNo usable config was produced; nothing to approve.", file=sys.stderr)
        sys.exit(4)

    if not report.ok:
        print(
            f"\nwarning: this config did NOT pass automated validation ({report.error_summary()}). "
            "Approving anyway is a human override, not a validator pass."
        )
        if args.auto_approve:
            print("--auto-approve set, but refusing to auto-approve a failed validation; "
                  "approve interactively or fix the config.", file=sys.stderr)
            sys.exit(5)

    if not _ask_approval(args.auto_approve):
        print("Not approved; nothing was saved.")
        sys.exit(0)

    vendor = str(config.get("vendor") or args.vendor or "unknown_vendor")
    mapping_path = _save_mapping(vendor, config)
    onboarding_path = _record_onboarding(Path(args.out_dir), vendor, seconds, report.score)
    print(f"\nSaved {mapping_path}")
    print(f"Recorded onboarding in {onboarding_path}")
    print("This mapping is live the next time the pipeline/ingest server starts.")


if __name__ == "__main__":
    main()
