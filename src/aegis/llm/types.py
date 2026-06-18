"""Provider-neutral request/response types for the model client.

Seeded from the gauntlet harness. Small and provider-neutral: the Anthropic
client maps the Messages API onto these; the stub fabricates them from recorded
data. Nothing outside this package depends on the Anthropic SDK directly.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class ToolDef:
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class LLMRequest:
    model: str
    messages: list[dict[str, Any]]
    system: str | None = None
    tools: tuple[ToolDef, ...] = ()
    max_tokens: int = 2048


@dataclass(frozen=True)
class LLMResponse:
    stop_reason: str
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()
    content_blocks: tuple[dict[str, Any], ...] = field(default_factory=tuple)

    @classmethod
    def make(
        cls, *, stop_reason: str, text: str = "", tool_calls: tuple[ToolCall, ...] = ()
    ) -> "LLMResponse":
        blocks: list[dict[str, Any]] = []
        if text:
            blocks.append({"type": "text", "text": text})
        for call in tool_calls:
            blocks.append(
                {"type": "tool_use", "id": call.id, "name": call.name, "input": call.arguments}
            )
        return cls(
            stop_reason=stop_reason,
            text=text,
            tool_calls=tuple(tool_calls),
            content_blocks=tuple(blocks),
        )
