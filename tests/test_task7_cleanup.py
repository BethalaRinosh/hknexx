from datetime import datetime, timezone

from backend.detector import analyze
from backend.models import SecurityEvent


def test_configured_stage_reasons_are_used_for_all_stage_evidence():
    events = [
        SecurityEvent(
            event_id="T7-LOGIN",
            timestamp=datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc),
            event_type="login",
            user="alice",
            device="laptop-7",
            src_ip="203.0.113.7",
            source="test",
            metadata={"unusual_ip": True, "new_device": True},
        ),
        SecurityEvent(
            event_id="T7-FILE",
            timestamp=datetime(2026, 1, 1, 10, 5, tzinfo=timezone.utc),
            event_type="file_access",
            user="alice",
            device="laptop-7",
            resource="finance/payroll.csv",
            source="test",
            metadata={"sensitive": True},
        ),
        SecurityEvent(
            event_id="T7-USB",
            timestamp=datetime(2026, 1, 1, 10, 10, tzinfo=timezone.utc),
            event_type="usb_mount",
            user="alice",
            device="laptop-7",
            source="test",
            metadata={"removable": True},
        ),
        SecurityEvent(
            event_id="T7-COPY",
            timestamp=datetime(2026, 1, 1, 10, 15, tzinfo=timezone.utc),
            event_type="file_copy",
            user="alice",
            device="laptop-7",
            source="test",
            action="copy to usb",
            metadata={"bytes": 1_500_000_000, "destination": "usb://drive-7"},
        ),
    ]

    config = {
        "stages": {
            "identity": {
                "reason": "CUSTOM IDENTITY REASON",
                "evidence_reasons": {
                    "login": "CUSTOM LOGIN EVIDENCE",
                    "device": "CUSTOM DEVICE EVIDENCE",
                },
            },
            "sensitive_access": {
                "reason": "CUSTOM SENSITIVE REASON",
                "evidence_reason": "CUSTOM SENSITIVE EVIDENCE",
            },
            "exfiltration": {
                "reason": "CUSTOM EXFIL REASON",
                "evidence_reasons": {
                    "usb": "CUSTOM USB EVIDENCE",
                    "copy": "CUSTOM COPY EVIDENCE",
                },
            },
        },
        "templates": {
            "incident": {
                "title": "Custom incident",
                "recommended_actions": ["Custom action"],
            }
        },
    }

    result = analyze(events, config=config)
    assert result.correlated_incidents == 1
    incident = result.incidents[0]

    assert {stage.reason for stage in incident.stages} == {
        "CUSTOM IDENTITY REASON",
        "CUSTOM SENSITIVE REASON",
        "CUSTOM EXFIL REASON",
    }
    evidence_reasons = {
        item.reason
        for stage in incident.stages
        for item in stage.evidence
    }
    assert {
        "CUSTOM LOGIN EVIDENCE",
        "CUSTOM DEVICE EVIDENCE",
        "CUSTOM SENSITIVE EVIDENCE",
        "CUSTOM USB EVIDENCE",
        "CUSTOM COPY EVIDENCE",
    } <= evidence_reasons
