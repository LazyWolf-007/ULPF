"""Minimal, loopback-only LLM client. stdlib only (urllib) - no new dependency.

Two backends, both speaking to a *local* server only:

- `OllamaClient` - Ollama's native `/api/generate` (default; `stream: false`,
  `format: "json"`, `options.temperature: 0` for deterministic output).
- `OpenAICompatClient` - any OpenAI-compatible `/chat/completions` endpoint
  (e.g. llama.cpp's server, LM Studio), for `--backend openai`.

Both refuse to construct against a non-loopback host - this is checked
before any network I/O, so a bad `--host`/`--base-url` fails fast and
loud rather than silently phoning out.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

DEFAULT_OLLAMA_PORT = 11434
DEFAULT_TIMEOUT = 120.0
DEFAULT_MODEL = "qwen2.5-coder:3b"

# Hostnames/IPs accepted as "loopback". Deliberately a fixed allow-list
# (not a DNS resolve-and-check) - simple, auditable, and correct for the
# air-gapped local-only deployments this tool targets.
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1", "[::1]"})


class LLMError(Exception):
    """Base class for every error this module raises."""


class NonLoopbackHostError(LLMError):
    """Raised when a client is constructed against a non-loopback host."""


class LLMConnectionError(LLMError):
    """The local model server could not be reached (not running, wrong port, ...)."""


class LLMResponseError(LLMError):
    """The server responded, but not with a usable generation."""


def require_loopback(host: str) -> None:
    if host not in _LOOPBACK_HOSTS:
        raise NonLoopbackHostError(
            f"refusing to contact non-loopback host {host!r}; ULPF is air-gapped and "
            "only talks to a model server on 127.0.0.1/localhost/::1. If this is really "
            "a local server under a different name, use 127.0.0.1 directly."
        )


class OllamaClient:
    """Talks to Ollama's native `/api/generate` endpoint."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = DEFAULT_OLLAMA_PORT,
        model: str = DEFAULT_MODEL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        require_loopback(host)
        self.host = host
        self.port = port
        self.model = model
        self.timeout = timeout
        self._url = f"http://{host}:{port}/api/generate"

    def generate(self, prompt: str) -> str:
        """Send `prompt`, return the model's raw text response."""
        body = json.dumps(
            {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0},
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self._url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise LLMConnectionError(
                f"could not reach Ollama at {self._url} ({exc}). Is `ollama serve` running? "
                "If Ollama isn't available right now, use --replay <saved_config.json> instead."
            ) from exc
        text = payload.get("response")
        if not isinstance(text, str) or not text.strip():
            raise LLMResponseError(f"Ollama response had no usable 'response' text: {payload!r}")
        return text


class OpenAICompatClient:
    """Talks to any OpenAI-compatible `/chat/completions` endpoint."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:11434/v1",
        model: str = DEFAULT_MODEL,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        host = urlparse(base_url).hostname or ""
        require_loopback(host)
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._url = f"{self.base_url}/chat/completions"

    def generate(self, prompt: str) -> str:
        body = json.dumps(
            {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0,
                "response_format": {"type": "json_object"},
            }
        ).encode("utf-8")
        request = urllib.request.Request(
            self._url, data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise LLMConnectionError(
                f"could not reach the OpenAI-compatible server at {self._url} ({exc}). "
                "Is it running? If not, use --replay <saved_config.json> instead."
            ) from exc
        try:
            text = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMResponseError(f"unexpected response shape: {payload!r}") from exc
        if not isinstance(text, str) or not text.strip():
            raise LLMResponseError(f"empty completion content: {payload!r}")
        return text


LLMClient = OllamaClient | OpenAICompatClient


def make_client(
    backend: str = "ollama",
    host: str = "127.0.0.1",
    port: int = DEFAULT_OLLAMA_PORT,
    base_url: str | None = None,
    model: str = DEFAULT_MODEL,
    timeout: float = DEFAULT_TIMEOUT,
) -> LLMClient:
    """Build a client for `backend` ("ollama" or "openai"). Loopback-only."""
    if backend == "ollama":
        return OllamaClient(host=host, port=port, model=model, timeout=timeout)
    if backend == "openai":
        resolved_base_url = base_url or f"http://{host}:{port}/v1"
        return OpenAICompatClient(base_url=resolved_base_url, model=model, timeout=timeout)
    raise ValueError(f"unknown backend {backend!r}; expected 'ollama' or 'openai'")
