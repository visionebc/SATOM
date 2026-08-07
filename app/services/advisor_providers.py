"""AI Advisor provider clients.

Built on ``httpx`` alone — already a dependency — instead of the official
``openai``/``anthropic`` SDKs. Those would be new pip packages that every
offline installer bundle (debian/rhel/suse) has to carry for a REST call this
small; same reasoning that keeps the operator CLI and the update-package
verifier stdlib-only. ``openai`` kind also covers any OpenAI-COMPATIBLE
gateway (Azure OpenAI behind a proxy, LiteLLM, vLLM with an API-key front
door) by pointing ``base_url`` at it — that is the "custom endpoint,
non-personal credential" case from the design discussion, not a second code
path.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import httpx

DEFAULT_TIMEOUT = 180.0  # a cold 32B model load on the shared Ollama host measured ~101s end-to-end
KINDS = ("ollama", "openai", "anthropic")


@dataclass
class ChatResult:
    """``prompt_tokens``/``completion_tokens`` are ``None`` when the provider
    did NOT report usage -- which is not the same statement as zero. Several
    OpenAI-compatible gateways omit the ``usage`` block entirely; coercing that
    to 0 would publish a token count the product never measured."""
    text: str
    raw: dict = field(default_factory=dict)
    prompt_tokens: int | None = None
    completion_tokens: int | None = None


class ProviderError(RuntimeError):
    """A provider call failed. The message is safe to show the operator —
    never includes the API key (httpx exceptions do not echo headers back)."""


def chat_ollama(base_url: str, model: str, system: str, messages: list[dict],
                 *, timeout: float = DEFAULT_TIMEOUT) -> ChatResult:
    url = base_url.rstrip("/") + "/api/chat"
    payload = []
    if system:
        payload.append({"role": "system", "content": system})
    payload.extend(messages)
    try:
        r = httpx.post(url, json={"model": model, "messages": payload, "stream": False},
                        timeout=timeout)
        r.raise_for_status()
    except httpx.HTTPError as exc:
        raise ProviderError(f"Ollama request failed: {exc}") from exc
    data = r.json()
    text = (data.get("message") or {}).get("content", "")
    return ChatResult(text=text, raw=data,
                       prompt_tokens=data.get("prompt_eval_count"),
                       completion_tokens=data.get("eval_count"))


def chat_openai_compatible(base_url: str, api_key: str, model: str, system: str,
                            messages: list[dict], *, timeout: float = DEFAULT_TIMEOUT,
                            extra_headers: dict | None = None) -> ChatResult:
    url = base_url.rstrip("/") + "/chat/completions"
    payload = []
    if system:
        payload.append({"role": "system", "content": system})
    payload.extend(messages)
    headers = {"Authorization": f"Bearer {api_key}"}
    if extra_headers:
        headers.update(extra_headers)
    try:
        r = httpx.post(url, json={"model": model, "messages": payload},
                        headers=headers, timeout=timeout)
        r.raise_for_status()
    except httpx.HTTPError as exc:
        raise ProviderError(f"provider request failed: {exc}") from exc
    data = r.json()
    choice = (data.get("choices") or [{}])[0]
    text = ((choice.get("message") or {}).get("content", "")) or ""
    usage = data.get("usage") or {}
    return ChatResult(text=text, raw=data,
                       prompt_tokens=usage.get("prompt_tokens"),
                       completion_tokens=usage.get("completion_tokens"))


def chat_anthropic(base_url: str, api_key: str, model: str, system: str,
                    messages: list[dict], *, timeout: float = DEFAULT_TIMEOUT) -> ChatResult:
    url = base_url.rstrip("/") + "/v1/messages"
    body = {
        "model": model,
        "max_tokens": 4096,
        "messages": [{"role": m["role"], "content": m["content"]} for m in messages
                     if m.get("role") in ("user", "assistant")],
    }
    if system:
        body["system"] = system
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    try:
        r = httpx.post(url, json=body, headers=headers, timeout=timeout)
        r.raise_for_status()
    except httpx.HTTPError as exc:
        raise ProviderError(f"provider request failed: {exc}") from exc
    data = r.json()
    parts = data.get("content") or []
    text = "".join(p.get("text", "") for p in parts if isinstance(p, dict) and p.get("type") == "text")
    usage = data.get("usage") or {}
    return ChatResult(text=text, raw=data,
                       prompt_tokens=usage.get("input_tokens"),
                       completion_tokens=usage.get("output_tokens"))


def send(kind: str, *, base_url: str, api_key: str, model: str, system: str,
          messages: list[dict], timeout: float = DEFAULT_TIMEOUT) -> ChatResult:
    """Single dispatch point — the ONE place a provider kind maps to a
    function, so adding a fourth kind is one branch here, not a hunt through
    the view for every call site."""
    if kind == "ollama":
        return chat_ollama(base_url, model, system, messages, timeout=timeout)
    if kind == "openai":
        return chat_openai_compatible(base_url, api_key, model, system, messages, timeout=timeout)
    if kind == "anthropic":
        return chat_anthropic(base_url, api_key, model, system, messages, timeout=timeout)
    raise ProviderError(f"unknown provider kind {kind!r}")
