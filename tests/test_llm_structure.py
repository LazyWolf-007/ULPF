"""Tokenizer coverage for the formats the model is no longer asked to regex."""

from __future__ import annotations

from ulpf.llm import structure


def test_quoted_kv_keeps_spaces_and_escapes() -> None:
    line = (
        r'device_name="SFW" msg="hello \"world\" extra" src_ip="10.1.1.1" '
        r'dst_ip="10.2.2.2" path="C:\\temp\\a"'
    )
    tokenized = structure.tokenize(line)
    assert tokenized.mode == "kv"
    assert tokenized.fields["msg"] == 'hello "world" extra'
    assert tokenized.fields["src_ip"] == "10.1.1.1"
    assert tokenized.fields["path"] == "C:\\temp\\a"
    assert structure.route_for([line]) == "kv"


def test_equals_inside_a_quoted_value_stays_in_the_value() -> None:
    line = 'msg="a=b c" src_ip="10.0.0.1" dst_ip="10.0.0.2"'
    tokenized = structure.tokenize(line)
    assert tokenized.mode == "kv"
    assert tokenized.fields["msg"] == "a=b c"
    assert tokenized.fields["src_ip"] == "10.0.0.1"


def test_one_kv_pair_is_not_enough_to_call_it_kv() -> None:
    tokenized = structure.tokenize("connection dropped foo=bar today")
    assert tokenized.mode == "regex"


def test_json_object_flattens_one_level_of_nesting() -> None:
    line = '{"src_ip": "10.1.1.1", "dst_port": 443, "event": {"action": "deny"}}'
    tokenized = structure.tokenize(line)
    assert tokenized.mode == "json"
    assert tokenized.fields["src_ip"] == "10.1.1.1"
    assert tokenized.fields["dst_port"] == "443"
    assert tokenized.fields["event.action"] == "deny"
    assert structure.route_for([line]) == "json"


def test_cef_header_and_quoted_extension() -> None:
    line = (
        "CEF:0|ZZ|Widget|1.0|100|Blocked traffic|5|"
        'src=10.1.1.1 dst=10.2.2.2 act=deny msg="hello world"'
    )
    tokenized = structure.tokenize(line)
    assert tokenized.mode == "cef"
    assert tokenized.fields["cef_vendor"] == "ZZ"
    assert tokenized.fields["cef_name"] == "Blocked traffic"
    assert tokenized.fields["src"] == "10.1.1.1"
    assert tokenized.fields["msg"] == "hello world"
    assert structure.route_for([line]) == "cef"


def test_leef_is_cef_mode_and_routes_as_leef() -> None:
    line = "LEEF:1.0|Acme|Box|1.0|42|src=10.0.0.1 dst=10.0.0.2 act=deny"
    tokenized = structure.tokenize(line)
    assert tokenized.mode == "cef"
    assert tokenized.fields["leef_vendor"] == "Acme"
    assert tokenized.fields["leef_event_id"] == "42"
    assert tokenized.fields["src"] == "10.0.0.1"
    assert structure.route_for([line]) == "leef"


def test_rfc3164_with_pri_is_syslog_kv() -> None:
    line = (
        '<14>Oct  4 12:00:01 srx1 RT_FLOW: RT_FLOW_SESSION_DENY: '
        'source-address="10.1.1.1" destination-address="10.2.2.2" action="deny"'
    )
    tokenized = structure.tokenize(line)
    assert tokenized.mode == "syslog_kv"
    assert tokenized.fields["syslog_pri"] == "14"
    assert tokenized.fields["syslog_host"] == "srx1"
    assert tokenized.fields["syslog_app"] == "RT_FLOW"
    assert tokenized.fields["syslog_timestamp"] == "Oct  4 12:00:01"
    assert tokenized.fields["source-address"] == "10.1.1.1"
    assert structure.route_for([line]) == "syslog"


def test_rfc3164_without_pri_is_still_syslog_kv() -> None:
    line = (
        'Oct  4 12:00:01 srx1 RT_FLOW: source-address="10.1.1.1" '
        'destination-address="10.2.2.2"'
    )
    tokenized = structure.tokenize(line)
    assert tokenized.mode == "syslog_kv"
    assert tokenized.fields["syslog_host"] == "srx1"
    assert "syslog_pri" not in tokenized.fields
    assert tokenized.fields["source-address"] == "10.1.1.1"
    # No <PRI>, so detect.py classifies the line as kv. The route follows detect.
    assert structure.route_for([line]) == "kv"


def test_rfc5424_structured_data_kv() -> None:
    line = (
        "<134>1 2026-10-04T12:00:01.123Z fw1 RT_FLOW 1234 RT_FLOW_SESSION_DENY "
        '[junos@2636.1.1.1.2.36 source-address="10.1.1.1" destination-address="10.2.2.2" action="deny"]'
    )
    tokenized = structure.tokenize(line)
    assert tokenized.mode == "syslog_kv"
    assert tokenized.fields["syslog_version"] == "1"
    assert tokenized.fields["syslog_host"] == "fw1"
    assert tokenized.fields["syslog_msgid"] == "RT_FLOW_SESSION_DENY"
    assert tokenized.fields["source-address"] == "10.1.1.1"
    assert tokenized.fields["action"] == "deny"
    assert structure.route_for([line]) == "syslog"


def test_pri_wrapped_cef_keeps_cef_mode() -> None:
    line = "<14>CEF:0|ZZ|Widget|1|100|Deny|5|src=10.1.1.1 dst=10.2.2.2 act=deny"
    tokenized = structure.tokenize(line)
    assert tokenized.mode == "cef"
    assert tokenized.fields["syslog_pri"] == "14"
    assert tokenized.fields["cef_vendor"] == "ZZ"
    assert tokenized.fields["src"] == "10.1.1.1"
    assert structure.route_for([line]) == "syslog"


def test_example_values_stops_at_two_distinct_values() -> None:
    lines = [
        "src=10.0.0.1 dst=10.0.0.2 act=deny",
        "src=10.0.0.3 dst=10.0.0.4 act=allow",
        "src=10.0.0.5 dst=10.0.0.6 act=deny",
    ]
    examples = structure.example_values(lines, limit=2)
    assert examples["src"] == ["10.0.0.1", "10.0.0.3"]
    assert examples["act"] == ["deny", "allow"]
    assert "10.0.0.5" not in examples["src"]


def test_unstructured_prose_is_regex_mode() -> None:
    line = "connection denied from alpha to beta"
    tokenized = structure.tokenize(line)
    assert tokenized.mode == "regex"
    assert tokenized.fields == {}
    assert structure.detect_mode([line, line]) == "regex"
    assert structure.route_for([line]) == "unknown"


_RT_CANONICAL = {
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "host",
    "timestamp",
    "event",
    "protocol",
    "pri",
}


def test_positional_rt_flow_create_keeps_padded_day() -> None:
    line = (
        "<14>Sep  3 09:01:02 edge-test RT_FLOW: RT_FLOW_SESSION_CREATE: "
        "session created 10.7.7.7/1000->10.8.8.8/80 0x0 junos-http "
        "10.7.7.7/1000->10.8.8.8/80 0x0 N/A N/A 6 trust-to-untrust trust untrust 42"
    )
    tokenized = structure.tokenize(line)
    assert tokenized.mode == "rt_flow"
    assert set(tokenized.fields) <= _RT_CANONICAL
    assert tokenized.fields["timestamp"] == "Sep  3 09:01:02"
    assert tokenized.fields["host"] == "edge-test"
    assert tokenized.fields["event"] == "RT_FLOW_SESSION_CREATE"
    assert tokenized.fields["src_ip"] == "10.7.7.7"
    assert tokenized.fields["src_port"] == "1000"
    assert tokenized.fields["dst_ip"] == "10.8.8.8"
    assert tokenized.fields["dst_port"] == "80"
    assert tokenized.fields["protocol"] == "6"
    assert tokenized.fields["pri"] == "14"
    assert structure.detect_mode([line]) == "rt_flow"
    assert structure.route_for([line]) == "syslog"


def test_positional_rt_flow_deny_and_close_and_icmp() -> None:
    deny = (
        "<14>Sep 30 09:01:03 edge-test RT_FLOW: RT_FLOW_SESSION_DENY: "
        "session denied 10.9.9.1/2000->10.8.8.2/22 junos-ssh 6(0) "
        "untrust-to-trust untrust trust NO_POLICY 6"
    )
    close = (
        "<14>Sep 30 09:01:04 edge-test RT_FLOW: RT_FLOW_SESSION_CLOSE: "
        "session closed idle Timeout: 10.7.7.7/1000->10.8.8.8/53 junos-dns-udp "
        "10.7.7.7/1000->10.8.8.8/53 None None 17 trust-to-untrust trust untrust 42 1 2 3 4 5"
    )
    icmp = (
        "<14>Sep 30 09:01:05 edge-test RT_FLOW: RT_FLOW_SESSION_CREATE: "
        "session created 10.7.7.7/0->10.8.8.8/0 0x0 junos-icmp-ping "
        "10.7.7.7/0->10.8.8.8/0 0x0 N/A N/A 1 trust-to-untrust trust untrust 43"
    )
    denied = structure.tokenize(deny)
    closed = structure.tokenize(close)
    ping = structure.tokenize(icmp)
    assert denied.mode == closed.mode == ping.mode == "rt_flow"
    assert denied.fields["event"] == "RT_FLOW_SESSION_DENY"
    assert denied.fields["protocol"] == "6"
    assert denied.fields["dst_port"] == "22"
    assert closed.fields["event"] == "RT_FLOW_SESSION_CLOSE"
    assert closed.fields["protocol"] == "17"
    assert ping.fields["protocol"] == "1"
    assert ping.fields["src_port"] == "0"
    assert "policy" not in denied.fields
    assert "session_id" not in closed.fields


def test_sd_twin_stays_syslog_kv_and_projects_onto_rt_flow_keys() -> None:
    line = (
        "<14>1 2026-10-04T12:00:01Z edge-test RT_FLOW - RT_FLOW_SESSION_CREATE "
        '[junos@2636.1.1.1.2.26 source-address="10.7.7.7" source-port="1000" '
        'destination-address="10.8.8.8" destination-port="53" protocol-id="17"]'
    )
    tokenized = structure.tokenize(line)
    assert tokenized.mode == "syslog_kv"
    assert tokenized.fields["source-address"] == "10.7.7.7"
    assert tokenized.fields["syslog_msgid"] == "RT_FLOW_SESSION_CREATE"
    projected = structure.rt_flow_fields(line)
    assert projected is not None
    assert projected["src_ip"] == "10.7.7.7"
    assert projected["dst_port"] == "53"
    assert projected["protocol"] == "17"
    assert projected["event"] == "RT_FLOW_SESSION_CREATE"
    assert projected["timestamp"] == "2026-10-04T12:00:01Z"
    assert projected["pri"] == "14"


def test_mikrotik_firewall_sentence_is_its_own_mode() -> None:
    forward = (
        "sep/03 09:01:02 firewall,info forward: in:ether1 out:ether2, "
        "src-mac 02:00:00:00:00:01, proto TCP (SYN), 10.7.7.7:1234->10.8.8.8:443, len 60"
    )
    icmp = (
        "sep/03 09:02:02 firewall,info drop forward: in:ether2 out:(unknown 0), "
        "src-mac 02:00:00:00:00:02, proto ICMP (type 8, code 0), 10.7.7.7->10.8.8.8, len 84"
    )
    pri = (
        "<30>Sep  3 09:03:02 edge-test firewall,info input: in:ether1 out:ether2, "
        "src-mac 02:00:00:00:00:03, proto UDP, 10.7.7.7:5300->10.8.8.8:53, len 72"
    )
    forwarded = structure.tokenize(forward)
    dropped = structure.tokenize(icmp)
    hosted = structure.tokenize(pri)
    syslog_time = (
        "Sep  3 09:03:02 edge-test firewall,info input: in:ether1 out:ether2, "
        "src-mac 02:00:00:00:00:03, proto UDP, 10.7.7.7:5300->10.8.8.8:53, len 72"
    )
    assert forwarded.mode == dropped.mode == hosted.mode == "mikrotik"
    assert structure.detect_mode([forward, icmp, pri]) == "mikrotik"
    assert "action" not in forwarded.fields
    assert forwarded.fields["chain"] == "forward"
    assert forwarded.fields["src_port"] == "1234"
    assert forwarded.fields["protocol"] == "TCP"
    assert forwarded.fields["in_if"] == "ether1"
    assert dropped.fields["action"] == "drop"
    assert dropped.fields["chain"] == "forward"
    assert dropped.fields["out_if"] == "(unknown 0)"
    assert "src_port" not in dropped.fields
    assert dropped.fields["protocol"] == "ICMP"
    assert hosted.fields["host"] == "edge-test"
    assert hosted.fields["timestamp"] == "Sep  3 09:03:02"
    assert hosted.fields["protocol"] == "UDP"
    assert hosted.fields["pri"] == "30"
    assert "action" not in hosted.fields
    assert hosted.fields["chain"] == "input"
    assert structure.tokenize(syslog_time).mode == "mikrotik"
    assert structure.route_for([forward]) == "routeros"
    assert structure.route_for([pri]) == "syslog"
    assert structure.route_for([syslog_time]) == "routeros"
    assert structure.route_for([forward, icmp, pri]) == "routeros"
