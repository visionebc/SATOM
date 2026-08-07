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

import json
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


# ---------------------------------------------------------------------------
# streaming
# ---------------------------------------------------------------------------
# Each ``stream_*`` is a generator yielding ``("delta", str)`` for every text
# chunk and finally exactly one ``("done", ChatResult)`` carrying the full
# text and whatever usage the provider reported.
#
# Streaming exists for two reasons, and the second is the one that matters:
#   1. the operator sees the answer forming instead of a frozen page, and
#   2. **Stop can be honest.** Closing the response body closes the socket to
#      the provider, so generation actually ends. A cancel button that only
#      stopped the browser waiting would leave the model running, the tokens
#      billed and the reply landing on the next page load — a control that
#      does not control anything, which is worse than having no button.


def _sse_data_lines(response):
    """Yield the JSON payload of each ``data:`` line of an SSE body.

    ``event:`` lines are deliberately ignored: both SSE providers here also
    carry a ``type`` inside the JSON, so parsing one field instead of
    correlating two lines removes a whole class of framing bug."""
    for line in response.iter_lines():
        if not line or not line.startswith("data:"):
            continue
        blob = line[5:].strip()
        if not blob or blob == "[DONE]":
            continue
        try:
            yield json.loads(blob)
        except (ValueError, TypeError):
            continue


def _raise_for_stream_status(response, label: str) -> None:
    """A streamed error body is not read by default, so the useful part of a
    4xx/5xx (the provider's own explanation) would be thrown away and the
    operator would get a bare status code."""
    if response.status_code < 400:
        return
    response.read()
    detail = (response.text or "").strip()[:300]
    raise ProviderError(
        f"{label} returned HTTP {response.status_code}"
        + (f": {detail}" if detail else ""))


def stream_ollama(base_url: str, model: str, system: str, messages: list[dict],
                   *, timeout: float = DEFAULT_TIMEOUT):
    url = base_url.rstrip("/") + "/api/chat"
    payload = ([{"role": "system", "content": system}] if system else []) + list(messages)
    parts: list[str] = []
    prompt_tokens = completion_tokens = None
    try:
        with httpx.stream("POST", url, timeout=timeout,
                           json={"model": model, "messages": payload, "stream": True}) as r:
            _raise_for_stream_status(r, "Ollama")
            for line in r.iter_lines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                except (ValueError, TypeError):
                    continue
                chunk = (data.get("message") or {}).get("content") or ""
                if chunk:
                    parts.append(chunk)
                    yield ("delta", chunk)
                if data.get("done"):
                    prompt_tokens = data.get("prompt_eval_count")
                    completion_tokens = data.get("eval_count")
    except httpx.HTTPError as exc:
        raise ProviderError(f"Ollama request failed: {exc}") from exc
    yield ("done", ChatResult(text="".join(parts), raw={},
                               prompt_tokens=prompt_tokens,
                               completion_tokens=completion_tokens))


def stream_openai_compatible(base_url: str, api_key: str, model: str, system: str,
                              messages: list[dict], *, timeout: float = DEFAULT_TIMEOUT,
                              extra_headers: dict | None = None):
    url = base_url.rstrip("/") + "/chat/completions"
    payload = ([{"role": "system", "content": system}] if system else []) + list(messages)
    headers = {"Authorization": f"Bearer {api_key}"}
    if extra_headers:
        headers.update(extra_headers)

    def body(with_usage: bool) -> dict:
        b = {"model": model, "messages": payload, "stream": True}
        if with_usage:
            # OpenAI reports usage on a streamed call only when asked. It is
            # requested optimistically and dropped on a 400 (below) because
            # ``kind="openai"`` also covers gateways that reject unknown
            # fields outright — losing a token count is a smaller failure than
            # losing streaming on the deployments this kind exists to serve.
            b["stream_options"] = {"include_usage": True}
        return b

    parts: list[str] = []
    prompt_tokens = completion_tokens = None
    for attempt, with_usage in enumerate((True, False)):
        parts = []
        try:
            with httpx.stream("POST", url, json=body(with_usage), headers=headers,
                               timeout=timeout) as r:
                if r.status_code == 400 and with_usage:
                    r.read()
                    continue  # retry once without stream_options
                _raise_for_stream_status(r, "provider")
                for data in _sse_data_lines(r):
                    choices = data.get("choices") or []
                    if choices:
                        chunk = ((choices[0].get("delta") or {}).get("content")) or ""
                        if chunk:
                            parts.append(chunk)
                            yield ("delta", chunk)
                    usage = data.get("usage") or {}
                    if usage:
                        prompt_tokens = usage.get("prompt_tokens", prompt_tokens)
                        completion_tokens = usage.get("completion_tokens", completion_tokens)
        except httpx.HTTPError as exc:
            raise ProviderError(f"provider request failed: {exc}") from exc
        break
    yield ("done", ChatResult(text="".join(parts), raw={},
                               prompt_tokens=prompt_tokens,
                               completion_tokens=completion_tokens))


def stream_anthropic(base_url: str, api_key: str, model: str, system: str,
                      messages: list[dict], *, timeout: float = DEFAULT_TIMEOUT):
    url = base_url.rstrip("/") + "/v1/messages"
    body = {
        "model": model,
        "max_tokens": 4096,
        "stream": True,
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
    parts: list[str] = []
    prompt_tokens = completion_tokens = None
    try:
        with httpx.stream("POST", url, json=body, headers=headers, timeout=timeout) as r:
            _raise_for_stream_status(r, "provider")
            for data in _sse_data_lines(r):
                kind = data.get("type")
                if kind == "content_block_delta":
                    chunk = (data.get("delta") or {}).get("text") or ""
                    if chunk:
                        parts.append(chunk)
                        yield ("delta", chunk)
                elif kind == "message_start":
                    usage = ((data.get("message") or {}).get("usage")) or {}
                    prompt_tokens = usage.get("input_tokens", prompt_tokens)
                    completion_tokens = usage.get("output_tokens", completion_tokens)
                elif kind == "message_delta":
                    usage = data.get("usage") or {}
                    if "output_tokens" in usage:
                        completion_tokens = usage["output_tokens"]
                elif kind == "error":
                    err = (data.get("error") or {}).get("message") or "stream error"
                    raise ProviderError(f"provider request failed: {err}")
    except httpx.HTTPError as exc:
        raise ProviderError(f"provider request failed: {exc}") from exc
    yield ("done", ChatResult(text="".join(parts), raw={},
                               prompt_tokens=prompt_tokens,
                               completion_tokens=completion_tokens))


def stream(kind: str, *, base_url: str, api_key: str, model: str, system: str,
            messages: list[dict], timeout: float = DEFAULT_TIMEOUT):
    """Streaming twin of :func:`send`, and the same single dispatch point."""
    if kind == "ollama":
        return stream_ollama(base_url, model, system, messages, timeout=timeout)
    if kind == "openai":
        return stream_openai_compatible(base_url, api_key, model, system, messages,
                                         timeout=timeout)
    if kind == "anthropic":
        return stream_anthropic(base_url, api_key, model, system, messages, timeout=timeout)
    raise ProviderError(f"unknown provider kind {kind!r}")
