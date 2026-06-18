"""Adversary-detection pass over security events.

Flags a session as adversarial when a guard blocked something or when an attack
succeeded. Independent of the defenses themselves: an operator runs this over the
event stream to surface incidents even when a defense let an attack through.
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from .events import SecurityEvent


@dataclass(frozen=True)
class Detection:
    case_id: str
    attack_class: str
    severity: str  # "critical" | "blocked" | "info"
    signal: str


def detect(events: Sequence[SecurityEvent]) -> list[Detection]:
    detections: list[Detection] = []
    for event in events:
        if event.attack_succeeded:
            detections.append(
                Detection(event.case_id, event.attack_class, "critical",
                          f"attack succeeded: {event.oracle_rationale}")
            )
        elif event.blocked_stages:
            detections.append(
                Detection(event.case_id, event.attack_class, "blocked",
                          f"blocked at {','.join(event.blocked_stages)}: "
                          f"{'; '.join(r for r in event.block_reasons if r)}")
            )
    return detections
