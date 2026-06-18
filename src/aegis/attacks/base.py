"""Attack case types and outcome records (seeded from gauntlet's design).

The corpus is built in :mod:`aegis.attacks.corpus` because the command-path cases
carry real signed (and deliberately mis-signed) envelopes, which are crypto
objects rather than plain JSON literals. Each case pairs an attack with a
machine-checkable success oracle and names the defense expected to stop it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..llm.types import LLMResponse


class AttackClass(StrEnum):
    INDIRECT_INJECTION = "indirect_injection"
    COMMAND_SPOOFING = "command_spoofing"
    EXFILTRATION = "exfiltration"
    TOOL_ABUSE = "tool_abuse"


@dataclass(frozen=True)
class OracleSpec:
    check: str
    params: dict[str, Any] = field(default_factory=dict)
    type: str = "rule"
    rubric: str | None = None


@dataclass(frozen=True)
class AttackCase:
    id: str
    attack_class: AttackClass
    description: str
    user_text: str
    oracle: OracleSpec
    primary_defense: str
    injected_telemetry: str | None = None
    scripted: tuple[LLMResponse, ...] = ()
    # True for the model-dependent classes (the undefended outcome depends on the
    # model when run live); False for the deterministic crypto/replay/forgery path.
    model_dependent: bool = False


@dataclass(frozen=True)
class CaseOutcome:
    case_id: str
    attack_class: str
    success: bool  # did the ATTACK succeed (bad)?
    defenses_enabled: list[str]
    oracle_rationale: str
    output_excerpt: str
    guard_log: list[dict[str, Any]]
    model_dependent: bool
