import json
from pathlib import Path

from backend.detector import analyze
from backend.models import SecurityEvent
from backend.reconstructor import reconstruct


ROOT = Path(__file__).resolve().parents[1]
SCENARIO_PATH = ROOT / "backend" / "data" / "scenarios.json"


def load_scenario(name: str) -> list[SecurityEvent]:
    with SCENARIO_PATH.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    return [SecurityEvent.model_validate(item) for item in raw[name]]


def test_slow_attack_uses_guarded_drift_window():
    result = analyze(load_scenario("slow_attack"))

    assert result.correlated_incidents == 1
    incident = result.incidents[0]
    assert incident.reconstruction is not None
    assert incident.reconstruction.temporal_valid is True
    assert incident.reconstruction.reconstruction_score >= 0.65
    assert incident.reconstruction.selected_event_ids == [
        "SLOW-001",
        "SLOW-002",
        "SLOW-004",
    ]


def test_long_spacing_without_strong_identity_is_not_reconstructed():
    events = load_scenario("slow_attack")
    events[1] = SecurityEvent.model_validate(
        events[1].model_dump(
            mode="json",
            round_trip=True,
        )
        | {"user": "different-user", "device": "DEV-99"}
    )

    reconstruction = reconstruct(events)

    assert reconstruction.selected_event_ids == []
    assert reconstruction.temporal_valid is False


def test_reconstruction_retains_decoy_candidates():
    events = load_scenario("full_attack")
    events.append(
        SecurityEvent.model_validate(
            events[2].model_dump(mode="json", round_trip=True)
            | {
                "event_id": "DECOY-SENSITIVE",
                "timestamp": "2026-10-06T09:16:00Z",
                "resource": "/finance/payroll.xlsx",
                "user": "decoy-user",
                "device": "DECOY-01",
            }
        )
    )

    reconstruction = reconstruct(events)

    assert reconstruction.selected_event_ids
    assert "DECOY-SENSITIVE" in reconstruction.decoy_event_ids
