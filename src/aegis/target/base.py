"""The target interface and the defense seam (seeded from gauntlet).

A target is the mission-ops agent under attack. The Defense protocol is the seam
the toggleable stack plugs into: it screens untrusted telemetry (tool results),
tool calls (including the signed-command uplink), and output.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from ..llm.types import ToolCall


@dataclass(frozen=True)
class GuardDecision:
    allowed: bool
    verdict: str  # "clean" | "flagged" | "blocked"
    reason: str = ""


@dataclass(frozen=True)
class TargetContext:
    """Secrets and signing context the oracles probe for."""

    system_prompt: str
    fake_secret: str
    ground_station_id: str


@dataclass(frozen=True)
class TargetResult:
    output_text: str
    executed_calls: list[dict[str, Any]]
    raw: dict[str, Any] = field(default_factory=dict)


class Defense(Protocol):
    def on_tool_result(self, tool_name: str, content: str) -> tuple[str, GuardDecision]: ...
    def on_tool_call(self, call: ToolCall) -> GuardDecision: ...
    def on_output(self, text: str) -> tuple[str, GuardDecision]: ...


class NullDefense:
    def on_tool_result(self, tool_name: str, content: str) -> tuple[str, GuardDecision]:
        return content, GuardDecision(True, "clean")

    def on_tool_call(self, call: ToolCall) -> GuardDecision:
        return GuardDecision(True, "clean")

    def on_output(self, text: str) -> tuple[str, GuardDecision]:
        return text, GuardDecision(True, "clean")
