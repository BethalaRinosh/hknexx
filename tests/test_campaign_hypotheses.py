import json
from pathlib import Path

from backend.detector import analyze
from backend.models import SecurityEvent


ROOT = Path(__file__).resolve().parents[1]
SCENARIO_PATH = ROOT / "backend" / "data" / "scenarios.json"


def load(name: str) -> list[SecurityEvent]:
    raw = json.loads(SCENARIO_PATH.read_text(encoding="utf-8"))
    return [SecurityEvent.model_validate(item) for item in raw[name]]


def test_partial_attack_surfaces_grounded_campaign_hypothesis():
    result = analyze(load("partial_attack"))

    assert result.correlated_incidents == 0
    assert len(result.campaign_hypotheses) == 1

    hypothesis = result.campaign_hypotheses[0]
    assert hypothesis.observed_stages == [
        "Initial Access / Identity Anomaly",
        "Sensitive Data Access",
    ]
    assert hypothesis.missing_stages == ["Collection / Exfiltration"]
    assert hypothesis.temporal_valid is True
    assert hypothesis.evidence_event_ids == [
        "PARTIAL-001",
        "PARTIAL-002",
        "PARTIAL-003",
    ]


def test_reversed_order_surfaces_temporal_contradiction():
    result = analyze(load("reversed_order"))

    assert result.correlated_incidents == 0
    assert result.campaign_hypotheses
    hypothesis = result.campaign_hypotheses[0]
    assert hypothesis.missing_stages == []
    assert hypothesis.temporal_valid is False
