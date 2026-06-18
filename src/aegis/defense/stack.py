"""The composed, toggleable defense stack.

Each guard is independent, so the harness can enable one at a time and measure
its contribution to the block rate.
"""
from __future__ import annotations

from dataclasses import dataclass

from ..crypto.verifier import CommandVerifier
from ..llm.types import ToolCall
from ..target.base import GuardDecision, TargetContext
from .guards import CommandAuth, OutputGuard, PolicyConfig, TelemetrySanitizer, ToolPolicy

_CLEAN = GuardDecision(True, "clean")


@dataclass(frozen=True)
class DefenseConfig:
    telemetry_sanitizer: bool = False
    tool_policy: bool = False
    output_guard: bool = False
    command_auth: bool = False

    @classmethod
    def all_on(cls) -> "DefenseConfig":
        return cls(True, True, True, True)

    @classmethod
    def all_off(cls) -> "DefenseConfig":
        return cls()

    def enabled_names(self) -> list[str]:
        return [n for n in ("telemetry_sanitizer", "tool_policy", "output_guard", "command_auth")
                if getattr(self, n)]


class DefenseStack:
    """Routes the defense seam to the enabled guards.

    Built fresh per case so the command verifier's replay/nonce state is clean.
    """

    def __init__(
        self,
        *,
        config: DefenseConfig,
        context: TargetContext,
        verifier: CommandVerifier,
        policy: PolicyConfig | None = None,
    ) -> None:
        self.config = config
        self._sanitizer = TelemetrySanitizer()
        self._policy = ToolPolicy(policy)
        self._output = OutputGuard(context)
        self._command_auth = CommandAuth(verifier)

    def on_tool_result(self, tool_name: str, content: str) -> tuple[str, GuardDecision]:
        if self.config.telemetry_sanitizer:
            decision = self._sanitizer.scan(content)
            return content, decision
        return content, _CLEAN

    def on_tool_call(self, call: ToolCall) -> GuardDecision:
        if self.config.command_auth:
            decision = self._command_auth.check(call)
            if not decision.allowed:
                return decision
        if self.config.tool_policy:
            decision = self._policy.check(call)
            if not decision.allowed:
                return decision
        return _CLEAN

    def on_output(self, text: str) -> tuple[str, GuardDecision]:
        if self.config.output_guard:
            return self._output.redact(text)
        return text, _CLEAN
