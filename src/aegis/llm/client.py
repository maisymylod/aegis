"""The single choke point for talking to a model (seeded from gauntlet).

``AnthropicClient`` wraps the real Messages API; ``StubLLMClient`` serves
recorded responses so the suite and CI run with no network. The stub performs no
reasoning: it replays fixtures keyed by a request fingerprint and fails loudly on
a miss, so fixtures can never silently drift into a live call.
"""
from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from .types import LLMRequest, LLMResponse, ToolCall


class LLMClient(Protocol):
    name: str

    def complete(self, request: LLMRequest) -> LLMResponse: ...


def fingerprint(request: LLMRequest) -> str:
    payload = {
        "model": request.model,
        "system": request.system,
        "messages": request.messages,
        "tools": sorted(t.name for t in request.tools),
    }
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


class StubMiss(KeyError):
    """No recorded response for a request; failing loudly keeps tests honest."""


class StubLLMClient:
    """Serves recorded responses. The default client for tests and CI."""

    name = "stub"

    def __init__(
        self,
        responses: Sequence[LLMResponse] | None = None,
        by_fingerprint: Mapping[str, LLMResponse] | None = None,
    ) -> None:
        self._queue: list[LLMResponse] = list(responses or [])
        self._by_fingerprint: dict[str, LLMResponse] = dict(by_fingerprint or {})
        self.calls: list[LLMRequest] = []

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.calls.append(request)
        fp = fingerprint(request)
        if fp in self._by_fingerprint:
            return self._by_fingerprint[fp]
        if self._queue:
            return self._queue.pop(0)
        raise StubMiss(f"no recorded response for fingerprint {fp}")


class AnthropicClient:
    """Wraps the Anthropic Messages API. SDK imported lazily (kept optional)."""

    name = "anthropic"

    def __init__(self, *, timeout: float = 30.0, max_retries: int = 4) -> None:
        import anthropic  # noqa: PLC0415

        self._client = anthropic.Anthropic().with_options(
            timeout=timeout, max_retries=max_retries
        )

    def complete(self, request: LLMRequest) -> LLMResponse:
        kwargs: dict[str, Any] = {
            "model": request.model,
            "max_tokens": request.max_tokens,
            "messages": request.messages,
        }
        if request.system is not None:
            kwargs["system"] = request.system
        if request.tools:
            kwargs["tools"] = [
                {"name": t.name, "description": t.description, "input_schema": t.input_schema}
                for t in request.tools
            ]
        return _to_response(self._client.messages.create(**kwargs))


def _to_response(message: Any) -> LLMResponse:
    text_parts: list[str] = []
    tool_calls: list[ToolCall] = []
    blocks: list[dict[str, Any]] = []
    for block in message.content:
        if getattr(block, "type", None) == "text":
            text_parts.append(block.text)
            blocks.append({"type": "text", "text": block.text})
        elif getattr(block, "type", None) == "tool_use":
            args = dict(block.input) if block.input else {}
            tool_calls.append(ToolCall(id=block.id, name=block.name, arguments=args))
            blocks.append({"type": "tool_use", "id": block.id, "name": block.name, "input": args})
    return LLMResponse(
        stop_reason=message.stop_reason or "end_turn",
        text="".join(text_parts),
        tool_calls=tuple(tool_calls),
        content_blocks=tuple(blocks),
    )


def select_client() -> LLMClient:
    """Real Anthropic when a key is present, else the deterministic stub.

    The stub here is empty (no fixtures); callers that need model-dependent
    behaviour offline construct a StubLLMClient with recorded responses.
    """
    if os.environ.get("ANTHROPIC_API_KEY"):
        return AnthropicClient()
    return StubLLMClient()
