"""Aggregate case outcomes into success/block rates (seeded from gauntlet)."""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..attacks.base import CaseOutcome


@dataclass(frozen=True)
class ClassScore:
    attack_class: str
    total: int
    succeeded: int

    @property
    def success_rate(self) -> float:
        return self.succeeded / self.total if self.total else 0.0


@dataclass(frozen=True)
class RunScore:
    total: int
    succeeded: int
    by_class: dict[str, ClassScore]

    @property
    def success_rate(self) -> float:
        return self.succeeded / self.total if self.total else 0.0

    @property
    def block_rate(self) -> float:
        return 1.0 - self.success_rate


def summarize(outcomes: Sequence[CaseOutcome]) -> RunScore:
    by_class: dict[str, ClassScore] = {}
    for attack_class in sorted({o.attack_class for o in outcomes}):
        rows = [o for o in outcomes if o.attack_class == attack_class]
        by_class[attack_class] = ClassScore(
            attack_class, len(rows), sum(1 for o in rows if o.success)
        )
    return RunScore(len(outcomes), sum(1 for o in outcomes if o.success), by_class)
