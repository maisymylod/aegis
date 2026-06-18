"""Red-team / blue-team harness.

Runs the corpus with defenses off, with the full stack on, and with each defense
alone, then assembles the scoreboard, security events, adversary detections, and
an incident report. Deterministic offline (stub client); with ANTHROPIC_API_KEY
set, the model-dependent classes run against the real model.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from .attacks.base import CaseOutcome
from .attacks.corpus import build_corpus
from .attacks.runner import run_case
from .crypto import build_hierarchy
from .detect.detector import Detection, detect
from .detect.events import SecurityEvent, event_from_outcome
from .detect.incident import build_incident_report
from .defense.stack import DefenseConfig
from .llm.client import LLMClient, select_client
from .report.scoring import RunScore, summarize
from .target.agent import build_context

# Fixed time anchor so signed envelopes and the verifier agree on freshness.
T0 = 1_700_000_000.0
DEFENSE_NAMES = ("telemetry_sanitizer", "tool_policy", "output_guard", "command_auth")


def _deterministic_nonce_factory():
    counter = itertools.count(1)
    return lambda: f"nonce-{next(counter):06d}"


@dataclass
class Scoreboard:
    run_id: str
    backend: str
    corpus_size: int
    off: RunScore
    on: RunScore
    per_defense: dict[str, RunScore]
    events: list[SecurityEvent] = field(default_factory=list)
    detections: list[Detection] = field(default_factory=list)
    incident: str = ""


def run_suite(client: LLMClient | None = None, run_id: str = "local") -> Scoreboard:
    client = client or select_client()
    hierarchy = build_hierarchy(clock=lambda: T0, nonce_factory=_deterministic_nonce_factory())
    context = build_context()
    corpus = build_corpus(hierarchy)
    clock = lambda: T0  # noqa: E731

    def run_all(config: DefenseConfig) -> list[CaseOutcome]:
        return [
            run_case(c, config, hierarchy=hierarchy, context=context, client=client, clock=clock)
            for c in corpus
        ]

    off = summarize(run_all(DefenseConfig.all_off()))
    on_outcomes = run_all(DefenseConfig.all_on())
    on = summarize(on_outcomes)
    per_defense = {
        name: summarize(run_all(DefenseConfig(**{name: True}))) for name in DEFENSE_NAMES
    }

    events = [event_from_outcome(run_id, o) for o in on_outcomes]
    detections = detect(events)
    incident = build_incident_report(run_id, events, detections)

    return Scoreboard(
        run_id=run_id,
        backend=client.name,
        corpus_size=len(corpus),
        off=off,
        on=on,
        per_defense=per_defense,
        events=events,
        detections=detections,
        incident=incident,
    )
