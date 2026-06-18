"""Human-readable incident report from detections and events."""
from __future__ import annotations

from collections.abc import Sequence

from .detector import Detection
from .events import SecurityEvent


def build_incident_report(
    run_id: str, events: Sequence[SecurityEvent], detections: Sequence[Detection]
) -> str:
    critical = [d for d in detections if d.severity == "critical"]
    blocked = [d for d in detections if d.severity == "blocked"]
    lines = [
        f"# Incident Report — run {run_id}",
        "",
        f"- Sessions analysed: {len(events)}",
        f"- Attacks that succeeded (critical): {len(critical)}",
        f"- Attacks blocked by a defense: {len(blocked)}",
        "",
    ]
    if critical:
        lines.append("## Critical — attack succeeded")
        for d in critical:
            lines.append(f"- `{d.case_id}` [{d.attack_class}] {d.signal}")
        lines.append("")
    if blocked:
        lines.append("## Blocked — defense held")
        for d in blocked:
            lines.append(f"- `{d.case_id}` [{d.attack_class}] {d.signal}")
        lines.append("")
    if not critical:
        lines.append("No attack succeeded under the active defense configuration.")
    return "\n".join(lines)
