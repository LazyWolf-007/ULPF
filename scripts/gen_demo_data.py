#!/usr/bin/env python
"""Generate demo_data/bulk.log: a mixed-vendor demo dataset.

4000 lines mixing the 6 existing vendor log formats (Cisco ASA, FortiGate,
Palo Alto/CEF, Suricata, sshd, Check Point), built from the exact line
shapes in samples/*.log so every generated line matches its parser's regex
(ulpf/parsers/cisco_asa.py, fortigate.py, cef.py, suricata.py, sshd.py,
checkpoint.py) - only the IPs/ports/users/timestamps/action values vary.

Composition of the 4000 lines:
  - ~1% (40) deliberately malformed lines (truncated/garbled/broken-JSON),
    for testing that failures are handled gracefully, not silently dropped.
  - 300 FortiGate "action=deny" lines from 3 fixed source IPs, timestamps
    confined to one random 2-minute window - the anomaly-detection spike.
  - the remaining ~3660 lines split evenly across the 6 vendors.

Timestamps span a 60-minute window for the four formats that actually carry
an embedded timestamp in their real line syntax (Cisco ASA, FortiGate,
Suricata, sshd). Palo Alto/CEF and Check Point's sample lines carry no
timestamp field at all (matching samples/paloalto.log and
samples/checkpoint.log exactly), so - to keep faithfully reusing "their
line templates exactly as they appear in samples/" - this script doesn't
invent one for them either; those events only get a timestamp from the
pipeline's own `provenance.ingest_time` at parse time, same as the real
samples already behave (see SPEC.md's OCSF `time` section).

Deterministic for a given --seed (uses a private random.Random instance,
never the global `random` module). Does not import or modify anything
under ulpf/ - it only has to match what the existing parsers already
expect; it never calls them.
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
DEFAULT_OUTPUT = ROOT / "demo_data" / "bulk.log"

TOTAL_LINES = 4000
SPIKE_COUNT = 300
SPIKE_SOURCE_COUNT = 3
SPIKE_WINDOW_SECONDS = 120
MALFORMED_FRACTION = 0.01
SPAN_SECONDS = 60 * 60
BASE_TIME = datetime(2026, 9, 27, 10, 0, 0, tzinfo=timezone.utc)

USERS = ["alice", "bob", "carol", "dave", "admin", "root", "jdoe", "svc-backup", "test", "guest"]
ASA_HOSTS = ["fw1", "fw2", "fw3", "edge-gw", "core-gw"]
FORTIGATE_DEVICES = ["FG1", "FG2", "FG-EDGE"]
SIGNATURES = [
    "Allowed DNS Query",
    "Blocked Port Scan",
    "ET INFO Suspicious User Agent",
    "Possible SQL Injection Attempt",
    "Outbound SSH to Uncommon Port",
]


def _rand_ip(rng: random.Random) -> str:
    """A mix of private/reserved ranges matching the style already used in
    samples/*.log (10.x, 172.16.x, 203.0.113.x, 198.51.100.x)."""
    choice = rng.random()
    if choice < 0.45:
        return f"10.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    if choice < 0.65:
        return f"172.16.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    if choice < 0.85:
        return f"203.0.113.{rng.randint(1, 254)}"
    return f"198.51.100.{rng.randint(1, 254)}"


def _rand_port(rng: random.Random, well_known: bool = False) -> int:
    if well_known:
        return rng.choice([22, 53, 80, 443, 3389, 8080])
    return rng.randint(1024, 65535)


def _fmt_syslog_ts(dt: datetime) -> str:
    # No year, matching samples/cisco.log and samples/sshd.log exactly
    # ("Sep 27 10:30:12") - the parsers' own regexes don't capture one.
    return dt.strftime("%b %d %H:%M:%S")


def _random_offset(rng: random.Random) -> datetime:
    return BASE_TIME + timedelta(seconds=rng.randint(0, SPAN_SECONDS - 1))


# --- per-vendor line builders, matching ulpf/parsers/*.py exactly -----------


def gen_cisco_line(rng: random.Random, dt: datetime | None = None) -> str:
    dt = dt or _random_offset(rng)
    verb = rng.choices(["Built", "Teardown", "Denied", "Deny"], weights=[45, 25, 20, 10])[0]
    direction = rng.choice(["inbound", "outbound"])
    transport = rng.choice(["TCP", "UDP", "ICMP"])
    conn_id = rng.randint(100000, 999999999)
    severity = rng.randint(0, 7)
    msgid = rng.choice([302013, 302014, 302015, 106023])
    host = rng.choice(ASA_HOSTS)
    src_ip, dst_ip = _rand_ip(rng), _rand_ip(rng)
    src_port, dst_port = _rand_port(rng), _rand_port(rng, well_known=True)
    user = rng.choice(USERS)
    pri = rng.choice([164, 165, 166])
    return (
        f"<{pri}>{_fmt_syslog_ts(dt)} {host} : %ASA-{severity}-{msgid}: "
        f"{verb} {direction} {transport} connection {conn_id} for "
        f"outside:{src_ip}/{src_port} to inside:{dst_ip}/{dst_port} user {user}"
    )


def gen_fortigate_line(
    rng: random.Random,
    dt: datetime | None = None,
    action: str | None = None,
    src_ip: str | None = None,
) -> str:
    dt = dt or _random_offset(rng)
    devname = rng.choice(FORTIGATE_DEVICES)
    src_ip = src_ip or _rand_ip(rng)
    dst_ip = _rand_ip(rng)
    src_port, dst_port = _rand_port(rng), _rand_port(rng, well_known=True)
    proto = rng.choice(["6", "17"])
    action = action or rng.choices(["deny", "accept"], weights=[30, 70])[0]
    return (
        f"date={dt.date().isoformat()} time={dt.strftime('%H:%M:%S')} devname={devname} "
        f"srcip={src_ip} srcport={src_port} dstip={dst_ip} dstport={dst_port} "
        f"proto={proto} action={action}"
    )


def gen_paloalto_line(rng: random.Random) -> str:
    src_ip, dst_ip = _rand_ip(rng), _rand_ip(rng)
    spt, dpt = _rand_port(rng), _rand_port(rng, well_known=True)
    proto = rng.choice(["6", "17"])
    severity = rng.randint(1, 10)
    sig_id = rng.randint(10000, 40000)
    name = rng.choice(["THREAT", "TRAFFIC", "URL-FILTERING"])
    act = rng.choice(["alert", "allow", "deny", "drop"])
    return (
        f"CEF:0|Palo Alto Networks|PanOS|10.1|{sig_id}|{name}|{severity}|"
        f"src={src_ip} dst={dst_ip} spt={spt} dpt={dpt} proto={proto} act={act}"
    )


def gen_suricata_line(rng: random.Random, dt: datetime | None = None) -> str:
    dt = dt or _random_offset(rng)
    src_ip, dst_ip = _rand_ip(rng), _rand_ip(rng)
    src_port, dst_port = _rand_port(rng), _rand_port(rng, well_known=True)
    proto = rng.choice(["UDP", "TCP", "ICMP"])
    action = rng.choices(["allowed", "blocked"], weights=[60, 40])[0]
    signature = rng.choice(SIGNATURES)
    severity = rng.randint(1, 3)
    ts = dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{rng.randint(0, 999999):06d}Z"
    return (
        '{"timestamp":"' + ts + '","event_type":"alert","src_ip":"' + src_ip + '",'
        '"src_port":' + str(src_port) + ',"dest_ip":"' + dst_ip + '",'
        '"dest_port":' + str(dst_port) + ',"proto":"' + proto + '",'
        '"alert":{"action":"' + action + '","signature":"' + signature + '",'
        '"severity":' + str(severity) + "}}"
    )


def gen_sshd_line(rng: random.Random, dt: datetime | None = None) -> str:
    dt = dt or _random_offset(rng)
    host = rng.choice(ASA_HOSTS + ["host"])
    pid = rng.randint(1000, 99999)
    user = rng.choice(USERS)
    src_ip = _rand_ip(rng)
    pri = rng.choice([36, 37, 38])
    return (
        f"<{pri}>{_fmt_syslog_ts(dt)} {host} sshd[{pid}]: Failed password for "
        f"{user} from {src_ip} port 22 ssh2"
    )


def gen_checkpoint_line(rng: random.Random) -> str:
    src_ip, dst_ip = _rand_ip(rng), _rand_ip(rng)
    action = rng.choices(["Drop", "Accept"], weights=[40, 60])[0]
    return f"src={src_ip} dst={dst_ip} action={action}"


VENDOR_BUILDERS = [
    gen_cisco_line,
    gen_fortigate_line,
    gen_paloalto_line,
    gen_suricata_line,
    gen_sshd_line,
    gen_checkpoint_line,
]


def gen_malformed_line(rng: random.Random) -> str:
    """A handful of distinct corruption strategies - deliberately broken,
    not merely "unusual" (see samples/messy.log / generic.py for that kind
    of edge case instead)."""
    strategy = rng.choice(["truncate", "broken_json", "no_cef_prefix", "control_chars", "pure_noise"])
    if strategy == "truncate":
        full = rng.choice([gen_cisco_line(rng), gen_fortigate_line(rng), gen_paloalto_line(rng)])
        cut = rng.randint(5, max(6, len(full) - 5))
        return full[:cut]
    if strategy == "broken_json":
        return '{"timestamp":"broken, "event_type": alert src_ip:10.0.0.' + str(rng.randint(1, 254))
    if strategy == "no_cef_prefix":
        # A CEF-shaped body with the literal "CEF:" marker stripped, so
        # cef.py's regex (which requires that exact prefix) cannot match it.
        return gen_paloalto_line(rng).replace("CEF:0|", "", 1)
    if strategy == "control_chars":
        junk = "".join(chr(rng.randint(1, 8)) for _ in range(rng.randint(3, 10)))
        return f"???{junk}??? unreadable frame {rng.randint(0, 999)}"
    return rng.choice(
        [
            "###GARBLED### " + "".join(rng.choice("xzqjv0123") for _ in range(rng.randint(10, 40))),
            "incomplete transmission - buffer overrun at offset " + str(rng.randint(0, 9999)),
        ]
    )


def generate(seed: int, total: int = TOTAL_LINES) -> list[str]:
    rng = random.Random(seed)

    malformed_count = max(1, round(total * MALFORMED_FRACTION))
    spike_count = min(SPIKE_COUNT, max(0, total - malformed_count))
    normal_count = total - malformed_count - spike_count
    if normal_count < 0:
        raise ValueError(f"--total {total} is too small to fit the {SPIKE_COUNT}-line spike + malformed lines")

    lines: list[str] = [VENDOR_BUILDERS[i % len(VENDOR_BUILDERS)](rng) for i in range(normal_count)]

    # The anomaly spike: fixed source IPs, one random 2-minute window.
    spike_start = BASE_TIME + timedelta(seconds=rng.randint(0, max(0, SPAN_SECONDS - SPIKE_WINDOW_SECONDS)))
    spike_ips = [_rand_ip(rng) for _ in range(SPIKE_SOURCE_COUNT)]
    lines.extend(
        gen_fortigate_line(
            rng,
            dt=spike_start + timedelta(seconds=rng.randint(0, SPIKE_WINDOW_SECONDS - 1)),
            action="deny",
            src_ip=rng.choice(spike_ips),
        )
        for _ in range(spike_count)
    )

    lines.extend(gen_malformed_line(rng) for _ in range(malformed_count))

    rng.shuffle(lines)  # interleave, like a real merged multi-source stream
    return lines


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="scripts/gen_demo_data.py")
    parser.add_argument("--seed", type=int, default=42, help="RNG seed (default: 42)")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help=f"default: {DEFAULT_OUTPUT}")
    parser.add_argument("--total", type=int, default=TOTAL_LINES, help=f"default: {TOTAL_LINES}")
    args = parser.parse_args(argv)

    lines = generate(seed=args.seed, total=args.total)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {len(lines)} lines to {output_path} (seed={args.seed})")


if __name__ == "__main__":
    main()
