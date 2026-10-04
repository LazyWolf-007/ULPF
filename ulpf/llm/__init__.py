"""Offline LLM parser generator.

Given a handful of sample lines from a device with no dedicated parser,
`structure.py` tokenizes them (quoted key=value, JSON, CEF/LEEF, a syslog
header plus a key=value body, positional RT_FLOW, or a RouterOS firewall
sentence). A local model then maps those source keys onto ULPF fields.
It does not write a regex unless no detector matches, and then with at
most 6 capture groups. For `rt_flow` and `mikrotik` the detector sets the
mode; a model `line_regex` is discarded.

The config is validated (schema, match rate, required-field coverage; regex
safety only in regex mode), shown to a human, and written to
`ulpf/mappings/<vendor>.yaml` only on approval. `ulpf/parsers/dynamic.py`
loads it at the next process start and tokenizes with the same code.

See SPEC.md ("Offline LLM parser generator") for the full design and
`python -m ulpf.llm.generate --help` for usage.
"""
