from __future__ import annotations

from .investigator import validate_report
from .models import Incident, InvestigationReport


def simulate_investigation(incident: Incident) -> InvestigationReport:
    """Produce a deterministic, clearly labeled investigator demo report.

    This is not an LLM and is never used as a fallback for the real provider.
    It converts already-validated incident evidence into the same structured
    report contract used by the grounded provider path.
    """
    claims = []
    evidence_refs: list[str] = []

    for stage in incident.stages:
        ids = [item.event_id for item in stage.evidence]
        evidence_refs.extend(ids)
        if not ids:
            continue
        claims.append({
            "claim": f"{stage.stage}: {stage.reason}",
            "claim_type": "fact",
            "evidence_event_ids": ids,
            "confidence": stage.confidence,
        })

    first = evidence_refs[0] if evidence_refs else incident.timeline[0].event_id
    summary = (
        f"Simulated investigator synthesis: the validated incident contains "
        f"{len(incident.stages)} supported attack stages, beginning with evidence [{first]}. "
        f"The deterministic engine reports {incident.confidence:.0%} campaign confidence."
    )

    raw = {
        "summary": summary,
        "claims": claims,
        "unanswered_questions": [
            "Whether the observed credentials were compromised before the first observed event.",
            "Whether additional telemetry outside the supplied evidence window changes attribution.",
        ],
        "recommended_actions": incident.recommended_actions,
    }
    return validate_report(
        raw,
        incident_id=incident.incident_id,
        allowed_event_ids={event.event_id for event in incident.timeline},
        provider="simulation",
        model="deterministic-demo",
    )
