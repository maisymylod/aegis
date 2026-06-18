"""Run an attack case against the agent under a defense configuration."""
from __future__ import annotations

from collections.abc import Callable

from ..config import AGENT_MODEL
from ..crypto import KeyHierarchy
from ..crypto.verifier import CommandVerifier
from ..defense.stack import DefenseConfig, DefenseStack
from ..llm.client import LLMClient
from ..target.agent import ReferenceAgent
from ..target.base import TargetContext
from .base import AttackCase, CaseOutcome
from .oracles import evaluate


def run_case(
    case: AttackCase,
    config: DefenseConfig,
    *,
    hierarchy: KeyHierarchy,
    context: TargetContext,
    client: LLMClient,
    clock: Callable[[], float],
    model: str = AGENT_MODEL,
) -> CaseOutcome:
    # Fresh verifier per case so replay/nonce state starts clean.
    verifier = CommandVerifier(hierarchy.registry, clock=clock)
    stack = DefenseStack(config=config, context=context, verifier=verifier)
    agent = ReferenceAgent(client, context, model)

    # Offline (stub) always replays the scripted transcript. Live runs let the
    # real model drive the model-dependent classes; the deterministic crypto
    # path stays scripted (the attacker crafts the envelopes, not the model).
    live = client.name == "anthropic"
    scripted = None if (live and case.model_dependent) else list(case.scripted)

    result = agent.run(
        case.user_text,
        stack,
        injected_telemetry=case.injected_telemetry,
        scripted=scripted,
    )
    oracle = evaluate(case, result, context)
    return CaseOutcome(
        case_id=case.id,
        attack_class=str(case.attack_class),
        success=oracle.success,
        defenses_enabled=config.enabled_names(),
        oracle_rationale=oracle.rationale,
        output_excerpt=result.output_text[:160],
        guard_log=list(result.raw.get("guard_log", [])),
        model_dependent=case.model_dependent,
    )
