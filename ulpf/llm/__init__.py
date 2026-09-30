"""Offline LLM parser generator.

Given a handful of sample lines from a device with no dedicated parser, a
local Ollama (or OpenAI-compatible) model proposes a YAML mapping + regex
config for it. The config is validated mechanically (schema, regex safety,
match rate, required-field coverage), shown to a human for approval, and
only written to `ulpf/mappings/<vendor>.yaml` on approval -
`ulpf/parsers/dynamic.py` then loads and registers it at the next process
start, same as any hand-written parser.

See SPEC.md ("Offline LLM parser generator") for the full design and
`python -m ulpf.llm.generate --help` for usage.
"""
