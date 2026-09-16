"""
Provider-agnostic LLM layer for the ATRIUM research agent.

The agent needs exactly one thing from a model: a tool-calling conversation
loop.  This module hides the wire format differences behind a small interface
so the agent loop never sees provider-specific message shapes.

Supported back ends
-------------------
anthropic   Claude via the official SDK.
openai      OpenAI Chat Completions.
local       Any OpenAI-compatible server — Ollama, LM Studio, vLLM,
            llama.cpp's server, OpenRouter, Groq, Together.  One adapter
            covers all of them because they speak the same wire format;
            only the base URL differs.
none        No model configured.  The agent is unavailable, and every other
            part of ATRIUM (relay, fingerprint, mutations, logs, intel)
            keeps working.

The OpenAI-compatible transport is plain urllib rather than the `openai`
SDK: it is a single non-streaming POST, and avoiding the dependency means a
local-model user needs nothing installed beyond the standard library.

Configuration (environment)
---------------------------
ATRIUM_LLM_PROVIDER   anthropic | openai | local | none.  Omit to auto-detect.
ATRIUM_LLM_MODEL      Model id.  Required for `local`, optional elsewhere.
ATRIUM_LLM_BASE_URL   OpenAI-compatible endpoint, e.g.
                      http://localhost:11434/v1  (Ollama)
                      http://localhost:1234/v1   (LM Studio)
ATRIUM_LLM_API_KEY    Key for the endpoint.  Local servers usually ignore it.
ANTHROPIC_API_KEY     Used when the provider is `anthropic`.
OPENAI_API_KEY        Used when the provider is `openai`.

Tool schemas are written once in Anthropic form — {name, description,
input_schema} — and translated per provider.
"""
from __future__ import annotations

import abc
import dataclasses
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

__all__ = [
    "ToolCall", "Turn", "Provider", "ProviderError", "ProviderUnavailable",
    "resolve_provider", "describe_providers", "DEFAULT_MODELS",
]

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-6",
    "openai":    "gpt-4o",
    "local":     "",          # no sensible default; local model ids are arbitrary
}

_LOCAL_HINTS = [
    ("Ollama",    "http://localhost:11434/v1"),
    ("LM Studio", "http://localhost:1234/v1"),
    ("vLLM",      "http://localhost:8000/v1"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Normalised types
# ─────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclasses.dataclass
class Turn:
    """One assistant turn, normalised across providers."""
    text: str
    tool_calls: list[ToolCall]
    stop_reason: str

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


class ProviderError(RuntimeError):
    """The provider was reachable but the request failed."""


class ProviderUnavailable(ProviderError):
    """The provider is not installed or not configured. Message is user-facing."""


# ─────────────────────────────────────────────────────────────────────────────
# Interface
# ─────────────────────────────────────────────────────────────────────────────

class Provider(abc.ABC):
    """
    Owns its own conversation state in whatever format its API expects, so the
    agent loop stays format-agnostic.  Call begin() once, then alternate
    complete() with add_tool_results()/add_user().
    """

    id: str = ""
    label: str = ""

    def __init__(self, model: str) -> None:
        self.model = model

    @abc.abstractmethod
    def begin(self, system: str, first_user: str) -> None: ...

    @abc.abstractmethod
    def add_user(self, text: str) -> None: ...

    @abc.abstractmethod
    def add_tool_results(self, results: list[tuple[str, dict]]) -> None:
        """results: list of (tool_call_id, result_dict)."""

    @abc.abstractmethod
    def complete(self, tools: list[dict], max_tokens: int = 4096) -> Turn: ...

    def describe(self) -> str:
        return f"{self.label} · {self.model}"


# ─────────────────────────────────────────────────────────────────────────────
# Anthropic
# ─────────────────────────────────────────────────────────────────────────────

class AnthropicProvider(Provider):
    id = "anthropic"
    label = "Anthropic"

    def __init__(self, model: str) -> None:
        super().__init__(model or DEFAULT_MODELS["anthropic"])
        try:
            import anthropic
        except ImportError as exc:
            raise ProviderUnavailable(
                "The anthropic SDK is not installed.  Run: pip install anthropic"
            ) from exc
        if not os.environ.get("ANTHROPIC_API_KEY"):
            raise ProviderUnavailable(
                "ANTHROPIC_API_KEY is not set in the environment."
            )
        self._sdk = anthropic
        self._client = anthropic.Anthropic()
        self._system = ""
        self._messages: list[dict] = []

    def begin(self, system: str, first_user: str) -> None:
        self._system = system
        self._messages = [{"role": "user", "content": first_user}]

    def add_user(self, text: str) -> None:
        self._messages.append({"role": "user", "content": text})

    def add_tool_results(self, results: list[tuple[str, dict]]) -> None:
        self._messages.append({
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": cid, "content": json.dumps(res)}
                for cid, res in results
            ],
        })

    def complete(self, tools: list[dict], max_tokens: int = 4096) -> Turn:
        try:
            resp = self._client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                system=self._system,
                tools=tools,
                messages=self._messages,
            )
        except self._sdk.APIError as exc:
            raise ProviderError(str(exc)) from exc

        # Carry the assistant turn forward verbatim — Anthropic requires the
        # original content blocks so tool_use ids line up with our results.
        self._messages.append({"role": "assistant", "content": resp.content})

        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [
            ToolCall(id=b.id, name=b.name, input=b.input)
            for b in resp.content if b.type == "tool_use"
        ]
        return Turn(text=text, tool_calls=calls, stop_reason=resp.stop_reason or "")


# ─────────────────────────────────────────────────────────────────────────────
# OpenAI and any OpenAI-compatible server
# ─────────────────────────────────────────────────────────────────────────────

def _http_json(url: str, payload: dict | None, api_key: str, timeout: int = 300,
               method: str = "POST") -> dict:
    """Minimal JSON over HTTP. Local endpoints bypass any configured proxy."""
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")

    host = urllib.parse.urlparse(url).hostname or ""
    if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    else:
        opener = urllib.request.build_opener()

    try:
        with opener.open(req, timeout=timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")[:500]
        raise ProviderError(f"HTTP {exc.code} from {url}: {body}") from exc
    except urllib.error.URLError as exc:
        raise ProviderError(
            f"Cannot reach {url}: {exc.reason}.  Is the model server running?"
        ) from exc
    except json.JSONDecodeError as exc:
        raise ProviderError(f"Non-JSON response from {url}") from exc


class OpenAICompatProvider(Provider):
    """
    OpenAI Chat Completions.  Also drives Ollama, LM Studio, vLLM, llama.cpp,
    OpenRouter and friends, which implement the same endpoint.

    The model must support tool calling.  Many small local models do not; when
    one silently ignores the `tools` field the agent cannot act, so complete()
    raises a clear error rather than looping on empty turns.
    """

    def __init__(self, model: str, base_url: str, api_key: str,
                 provider_id: str = "openai", label: str = "OpenAI") -> None:
        super().__init__(model)
        self.id = provider_id
        self.label = label
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._messages: list[dict] = []
        self._empty_turns = 0

    # ── conversation state ────────────────────────────────────────────────
    def begin(self, system: str, first_user: str) -> None:
        self._messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": first_user},
        ]

    def add_user(self, text: str) -> None:
        self._messages.append({"role": "user", "content": text})

    def add_tool_results(self, results: list[tuple[str, dict]]) -> None:
        for cid, res in results:
            self._messages.append({
                "role": "tool",
                "tool_call_id": cid,
                "content": json.dumps(res),
            })

    # ── schema translation ────────────────────────────────────────────────
    @staticmethod
    def _translate_tools(tools: list[dict]) -> list[dict]:
        return [{
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
            },
        } for t in tools]

    def complete(self, tools: list[dict], max_tokens: int = 4096) -> Turn:
        payload = {
            "model": self.model,
            "messages": self._messages,
            "tools": self._translate_tools(tools),
            "tool_choice": "auto",
            "max_tokens": max_tokens,
        }
        data = _http_json(f"{self.base_url}/chat/completions", payload, self.api_key)

        try:
            choice = data["choices"][0]
            msg = choice["message"]
        except (KeyError, IndexError) as exc:
            raise ProviderError(f"Unexpected response shape: {json.dumps(data)[:300]}") from exc

        text = msg.get("content") or ""
        raw_calls = msg.get("tool_calls") or []

        calls: list[ToolCall] = []
        for rc in raw_calls:
            fn = rc.get("function", {})
            raw_args = fn.get("arguments") or "{}"
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except json.JSONDecodeError:
                # A model emitted malformed JSON arguments. Surface it to the
                # agent as a tool error so it can retry rather than crashing.
                args = {"__parse_error__": raw_args}
            calls.append(ToolCall(id=rc.get("id") or fn.get("name", "call"),
                                  name=fn.get("name", ""), input=args))

        # Echo the assistant turn back into history in OpenAI's format
        assistant: dict[str, Any] = {"role": "assistant", "content": text or None}
        if raw_calls:
            assistant["tool_calls"] = raw_calls
        self._messages.append(assistant)

        finish = choice.get("finish_reason") or ""

        # Detect a model that cannot (or will not) call tools: repeated turns
        # with no tool calls and no meaningful text means the loop is stuck.
        if not calls and not text.strip():
            self._empty_turns += 1
            if self._empty_turns >= 2:
                raise ProviderError(
                    f"{self.label} model '{self.model}' returned no text and no tool "
                    "calls twice in a row.  It likely does not support tool calling — "
                    "pick a tool-capable model (e.g. llama3.1, qwen2.5, mistral-nemo)."
                )
        else:
            self._empty_turns = 0

        stop = "tool_use" if calls else ("end_turn" if finish == "stop" else finish)
        return Turn(text=text, tool_calls=calls, stop_reason=stop)

    def list_models(self) -> list[str]:
        """Ask an OpenAI-compatible server what it can serve. Best effort."""
        try:
            data = _http_json(f"{self.base_url}/models", None, self.api_key,
                              timeout=10, method="GET")
        except ProviderError:
            return []
        return sorted(
            m.get("id", "") for m in data.get("data", []) if m.get("id")
        )


# ─────────────────────────────────────────────────────────────────────────────
# Resolution
# ─────────────────────────────────────────────────────────────────────────────

def _env(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _detect() -> str:
    """Pick a provider when none was named explicitly."""
    explicit = _env("ATRIUM_LLM_PROVIDER").lower()
    if explicit:
        return explicit
    if _env("ANTHROPIC_API_KEY"):
        return "anthropic"
    if _env("OPENAI_API_KEY"):
        return "openai"
    if _env("ATRIUM_LLM_BASE_URL"):
        return "local"
    return "none"


def resolve_provider(name: str | None = None, model: str | None = None) -> Provider:
    """
    Build the configured provider.

    Raises ProviderUnavailable with an actionable message when nothing is
    configured, so callers can show setup guidance instead of a stack trace.
    """
    pid = (name or _detect()).lower()
    model = (model or "").strip() or _env("ATRIUM_LLM_MODEL")

    if pid in ("none", ""):
        raise ProviderUnavailable(
            "No language model is configured, so the AI agent is unavailable.  "
            "Everything else in ATRIUM — relay, fingerprinting, mutations, logs "
            "and card intel — works without one.\n\n"
            "To enable the agent, set one of:\n"
            "  • ANTHROPIC_API_KEY=sk-ant-…            (Claude)\n"
            "  • OPENAI_API_KEY=sk-…                   (OpenAI)\n"
            "  • ATRIUM_LLM_BASE_URL=http://localhost:11434/v1 "
            "and ATRIUM_LLM_MODEL=llama3.1   (local model)"
        )

    if pid == "anthropic":
        return AnthropicProvider(model)

    if pid == "openai":
        key = _env("OPENAI_API_KEY") or _env("ATRIUM_LLM_API_KEY")
        if not key:
            raise ProviderUnavailable("OPENAI_API_KEY is not set in the environment.")
        base = _env("ATRIUM_LLM_BASE_URL", "https://api.openai.com/v1")
        return OpenAICompatProvider(model or DEFAULT_MODELS["openai"], base, key,
                                    "openai", "OpenAI")

    if pid == "local":
        base = _env("ATRIUM_LLM_BASE_URL")
        if not base:
            hints = "\n".join(f"  • {n}: {u}" for n, u in _LOCAL_HINTS)
            raise ProviderUnavailable(
                "ATRIUM_LLM_BASE_URL is not set.  Point it at your OpenAI-compatible "
                f"server:\n{hints}"
            )
        if not model:
            raise ProviderUnavailable(
                "ATRIUM_LLM_MODEL is not set.  Name the model your server should "
                "load, e.g. llama3.1 or qwen2.5:14b."
            )
        # Local servers commonly ignore the key but require the header to exist
        key = _env("ATRIUM_LLM_API_KEY", "local")
        return OpenAICompatProvider(model, base, key, "local", "Local")

    raise ProviderUnavailable(
        f"Unknown provider '{pid}'. Expected one of: anthropic, openai, local, none."
    )


def describe_providers() -> dict:
    """
    Report what is installed and configured, for the settings UI.
    Never raises — this drives the screen that explains what is missing.
    """
    def sdk_present(mod: str) -> bool:
        import importlib.util
        return importlib.util.find_spec(mod) is not None

    active = _detect()
    base_url = _env("ATRIUM_LLM_BASE_URL")

    providers = [
        {
            "id": "anthropic",
            "label": "Anthropic (Claude)",
            "configured": bool(_env("ANTHROPIC_API_KEY")),
            "sdk_installed": sdk_present("anthropic"),
            "requires": "ANTHROPIC_API_KEY",
            "default_model": DEFAULT_MODELS["anthropic"],
            "models": ["claude-opus-4-7", "claude-sonnet-4-6", "claude-haiku-4-5-20251001"],
        },
        {
            "id": "openai",
            "label": "OpenAI",
            "configured": bool(_env("OPENAI_API_KEY")),
            "sdk_installed": True,          # plain HTTP, nothing to install
            "requires": "OPENAI_API_KEY",
            "default_model": DEFAULT_MODELS["openai"],
            "models": ["gpt-4o", "gpt-4o-mini", "gpt-4.1", "o4-mini"],
        },
        {
            "id": "local",
            "label": "Local / OpenAI-compatible",
            "configured": bool(base_url),
            "sdk_installed": True,
            "requires": "ATRIUM_LLM_BASE_URL + ATRIUM_LLM_MODEL",
            "default_model": _env("ATRIUM_LLM_MODEL"),
            "base_url": base_url,
            "models": [],                   # filled in below when reachable
            "hints": [{"name": n, "base_url": u} for n, u in _LOCAL_HINTS],
        },
    ]

    # Ask a configured local server what it actually has loaded
    if base_url:
        try:
            probe = OpenAICompatProvider("", base_url, _env("ATRIUM_LLM_API_KEY", "local"),
                                         "local", "Local")
            providers[2]["models"] = probe.list_models()
            providers[2]["reachable"] = True
        except Exception:
            providers[2]["reachable"] = False

    return {
        "active": active,
        "agent_available": active != "none",
        "model": _env("ATRIUM_LLM_MODEL") or DEFAULT_MODELS.get(active, ""),
        "providers": providers,
    }
