"""Structured security events: one per attack-case session.

A flat, serializable audit record of what the guards saw and how the case
resolved. Events feed the adversary-detection pass and the incident report.
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..attacks.base import CaseOutcome

SCHEMA_VERSION = 1


@dataclass(frozen=True)
class SecurityEvent:
    run_id: str
    case_id: str
    attack_class: str
    defenses_enabled: list[str]
    blocked_stages: list[str]
    block_reasons: list[str]
    attack_succeeded: bool
    oracle_rationale: str
    output_excerpt: str
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def event_from_outcome(run_id: str, outcome: CaseOutcome) -> SecurityEvent:
    blocked_stages: list[str] = []
    reasons: list[str] = []
    for entry in outcome.guard_log:
        decision = entry.get("decision", {})
        if not decision.get("allowed", True):
            blocked_stages.append(str(entry.get("stage", "")))
            reasons.append(str(decision.get("reason", "")))
    return SecurityEvent(
        run_id=run_id,
        case_id=outcome.case_id,
        attack_class=outcome.attack_class,
        defenses_enabled=list(outcome.defenses_enabled),
        blocked_stages=blocked_stages,
        block_reasons=reasons,
        attack_succeeded=outcome.success,
        oracle_rationale=outcome.oracle_rationale,
        output_excerpt=outcome.output_excerpt,
    )


def write_events(events: Sequence[SecurityEvent], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for event in events:
            fh.write(json.dumps(event.to_dict()) + "\n")
