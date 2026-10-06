from datetime import datetime, timedelta, timezone

from backend.behavior import build_profiles, enrich_events
from backend.detector import analyze
from backend.models import SecurityEvent


def event(
    event_id: str,
    minute: int,
    event_type: str = "login",
    *,
    user: str = "alice",
    device: str = "WS-01",
    ip: str = "10.0.0.10",
    metadata: dict | None = None,
    **kwargs,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=datetime(2026, 10, 1, tzinfo=timezone.utc) + timedelta(minutes=minute),
        event_type=event_type,
        user=user,
        device=device,
        src_ip=ip,
        source="test",
        metadata=metadata or {},
        **kwargs,
    )


def baseline_events() -> list[SecurityEvent]:
    return [
        event(f"B{i}", i * 10, user="alice", device="WS-01", ip="10.0.0.10")
        for i in range(8)
    ]


def test_profile_learns_entity_identity():
    profiles = build_profiles(baseline_events())
    profile = profiles["user:alice"]
    assert profile.event_count == 8
    assert profile.known_ips == {"10.0.0.10"}
    assert profile.known_devices == {"WS-01"}


def test_novel_ip_and_device_are_anomalous():
    current = [
        event(
            "C1",
            100,
            user="alice",
            device="WS-99",
            ip="203.0.113.50",
            metadata={"unusual_ip": False},
        )
    ]
    enriched, signals = enrich_events(baseline_events(), current)
    assert signals[0].anomalous is True
    assert signals[0].score >= 0.70
    assert enriched[0].metadata["unusual_ip"] is True
    assert enriched[0].metadata["new_device"] is True


def test_known_identity_stays_benign():
    current = [event("C1", 100, user="alice", device="WS-01", ip="10.0.0.10")]
    enriched, signals = enrich_events(baseline_events(), current)
    assert signals[0].score == 0.0
    assert signals[0].anomalous is False
    assert enriched[0].metadata["behavior_anomalous"] is False


def test_no_baseline_does_not_guess_anomaly():
    current = [event("C1", 100, user="new-user", device="WS-99", ip="203.0.113.50")]
    enriched, signals = enrich_events([], current)
    assert signals[0].score == 0.0
    assert signals[0].anomalous is False
    assert "Insufficient historical baseline" in signals[0].reasons[0]


def test_behavior_anomaly_alone_cannot_create_incident():
    current = [event("C1", 100, user="alice", device="WS-99", ip="203.0.113.50")]
    enriched, signals = enrich_events(baseline_events(), current)
    result = analyze(enriched)
    assert signals[0].anomalous is True
    assert result.correlated_incidents == 0
    assert result.suppressed is True


def test_behavior_signals_can_support_full_attack_without_replacing_evidence_chain():
    current = [
        event(
            "A1",
            100,
            user="alice",
            device="WS-99",
            ip="203.0.113.50",
            metadata={"sensitive": False},
        ),
        event(
            "A2",
            104,
            event_type="device_enroll",
            user="alice",
            device="WS-99",
            ip="203.0.113.50",
            metadata={"new_device": True},
        ),
        event(
            "A3",
            108,
            event_type="file_access",
            user="alice",
            device="WS-99",
            ip="203.0.113.50",
            resource="/finance/acquisition.pdf",
            action="read",
            severity="high",
            metadata={"sensitive": True},
        ),
        event(
            "A4",
            112,
            event_type="usb_mount",
            user="alice",
            device="WS-99",
            ip="203.0.113.50",
            severity="medium",
            metadata={"removable": True},
        ),
        event(
            "A5",
            114,
            event_type="file_copy",
            user="alice",
            device="WS-99",
            ip="203.0.113.50",
            action="copy_to_usb",
            severity="critical",
            metadata={
                "bytes": 2_000_000_000,
                "destination": "USB:E:",
                "removable_destination": True,
            },
        ),
    ]
    enriched, signals = enrich_events(baseline_events(), current)
    result = analyze(enriched)
    assert any(signal.anomalous for signal in signals)
    assert result.correlated_incidents == 1
    incident = result.incidents[0]
    assert incident.chain_completeness == 1.0
    assert incident.evidence_count >= 4
