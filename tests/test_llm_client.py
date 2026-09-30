from __future__ import annotations

import json
from typing import Any
from urllib.error import URLError

import pytest

from ulpf.llm import client as client_mod


class _FakeHTTPResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeHTTPResponse":
        return self

    def __exit__(self, *exc_info: object) -> None:
        return None


# ---------------------------------------------------------------------------
# Loopback enforcement - must happen before any network I/O.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["8.8.8.8", "evil.example.com", "0.0.0.0", "10.0.0.5"])
def test_ollama_client_rejects_non_loopback_host(host: str) -> None:
    with pytest.raises(client_mod.NonLoopbackHostError):
        client_mod.OllamaClient(host=host)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_ollama_client_accepts_loopback_host(host: str) -> None:
    client_mod.OllamaClient(host=host)  # must not raise


def test_openai_client_rejects_non_loopback_base_url() -> None:
    with pytest.raises(client_mod.NonLoopbackHostError):
        client_mod.OpenAICompatClient(base_url="http://8.8.8.8:11434/v1")


def test_openai_client_accepts_loopback_base_url() -> None:
    client_mod.OpenAICompatClient(base_url="http://127.0.0.1:11434/v1")  # must not raise


def test_make_client_rejects_non_loopback_host_before_backend_dispatch() -> None:
    with pytest.raises(client_mod.NonLoopbackHostError):
        client_mod.make_client(backend="ollama", host="8.8.8.8")
    with pytest.raises(client_mod.NonLoopbackHostError):
        client_mod.make_client(backend="openai", host="8.8.8.8")


def test_make_client_rejects_unknown_backend() -> None:
    with pytest.raises(ValueError):
        client_mod.make_client(backend="carrier-pigeon")


def test_make_client_dispatches_to_correct_class() -> None:
    assert isinstance(client_mod.make_client(backend="ollama"), client_mod.OllamaClient)
    assert isinstance(client_mod.make_client(backend="openai"), client_mod.OpenAICompatClient)


# ---------------------------------------------------------------------------
# generate() - HTTP is mocked; no real network call ever happens here.
# ---------------------------------------------------------------------------


def test_ollama_client_generate_extracts_response_field(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_urlopen(request, timeout=None):  # noqa: ANN001
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return _FakeHTTPResponse({"response": '{"vendor": "Acme"}', "done": True})

    monkeypatch.setattr(client_mod.urllib.request, "urlopen", fake_urlopen)

    c = client_mod.OllamaClient(model="qwen2.5-coder:3b", timeout=42)
    text = c.generate("hello prompt")

    assert text == '{"vendor": "Acme"}'
    assert captured["url"] == "http://127.0.0.1:11434/api/generate"
    assert captured["body"]["model"] == "qwen2.5-coder:3b"
    assert captured["body"]["prompt"] == "hello prompt"
    assert captured["body"]["stream"] is False
    assert captured["body"]["format"] == "json"
    assert captured["body"]["options"]["temperature"] == 0
    assert captured["timeout"] == 42


def test_ollama_client_generate_raises_clear_error_when_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request, timeout=None):  # noqa: ANN001
        raise URLError("connection refused")

    monkeypatch.setattr(client_mod.urllib.request, "urlopen", fake_urlopen)

    c = client_mod.OllamaClient()
    with pytest.raises(client_mod.LLMConnectionError, match="Ollama"):
        c.generate("hello")


def test_ollama_client_generate_raises_on_missing_response_field(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request, timeout=None):  # noqa: ANN001
        return _FakeHTTPResponse({"done": True})

    monkeypatch.setattr(client_mod.urllib.request, "urlopen", fake_urlopen)

    c = client_mod.OllamaClient()
    with pytest.raises(client_mod.LLMResponseError):
        c.generate("hello")


def test_openai_client_generate_extracts_message_content(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    def fake_urlopen(request, timeout=None):  # noqa: ANN001
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return _FakeHTTPResponse({"choices": [{"message": {"content": '{"vendor": "Beta"}'}}]})

    monkeypatch.setattr(client_mod.urllib.request, "urlopen", fake_urlopen)

    c = client_mod.OpenAICompatClient(base_url="http://127.0.0.1:8080/v1", model="local-model")
    text = c.generate("hello")

    assert text == '{"vendor": "Beta"}'
    assert captured["url"] == "http://127.0.0.1:8080/v1/chat/completions"
    assert captured["body"]["messages"] == [{"role": "user", "content": "hello"}]
    assert captured["body"]["temperature"] == 0


def test_openai_client_generate_raises_on_unexpected_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request, timeout=None):  # noqa: ANN001
        return _FakeHTTPResponse({"unexpected": "shape"})

    monkeypatch.setattr(client_mod.urllib.request, "urlopen", fake_urlopen)

    c = client_mod.OpenAICompatClient()
    with pytest.raises(client_mod.LLMResponseError):
        c.generate("hello")
