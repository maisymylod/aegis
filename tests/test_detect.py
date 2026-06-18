from aegis.attacks.base import CaseOutcome
from aegis.detect import build_incident_report, detect, event_from_outcome


def _outcome(success: bool, blocked: bool) -> CaseOutcome:
    guard_log = (
        [{"stage": "tool", "decision": {"allowed": False, "reason": "blocked by policy"}}]
        if blocked
        else []
    )
    return CaseOutcome(
        case_id="c1",
        attack_class="tool_abuse",
        success=success,
        defenses_enabled=["tool_policy"],
        oracle_rationale="rationale",
        output_excerpt="",
        guard_log=guard_log,
        model_dependent=False,
    )


def test_event_captures_block_reason():
    event = event_from_outcome("run", _outcome(success=False, blocked=True))
    assert event.blocked_stages == ["tool"]
    assert "blocked by policy" in event.block_reasons[0]


def test_detect_flags_success_as_critical():
    events = [event_from_outcome("run", _outcome(success=True, blocked=False))]
    detections = detect(events)
    assert detections[0].severity == "critical"


def test_incident_report_clean_when_no_success():
    events = [event_from_outcome("run", _outcome(success=False, blocked=True))]
    report = build_incident_report("run", events, detect(events))
    assert "No attack succeeded" in report
