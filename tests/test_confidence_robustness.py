import json
from pathlib import Path

from backend.detector import analyze
from backend.models import SecurityEvent


ROOT = Path(__file__).resolve().parents[1]
SCENARIO_PATH = ROOT / "backend" / "data" / "scenarios.json"


def load(name: str) -> list[SecurityEvent]:
    raw = json.loads(SCENARIO_PATH.read_text(encoding="utf-8"))
    return [SecurityEvent.model_validate(item) for item in raw[name]]


def test_complete_campaign_has_clear_confidence_gap_over_partial_hypothesis():
    complete = analyze(load("full_attack"))
    partial = analyze(load("partial_attack"))

    assert complete.correlated_incidents == 1
    assert partial.correlated_incidents == 0
    hypothesis = partial.campaign_hypotheses[0]
    assert complete.incidents[0].confidence - hypothesis.confidence >= 0.10


def test_duplicate_attack_telemetry_does_not_create_duplicate_incidents():
    events = load("full_attack") * 2
    result = analyze(events)

    assert result.correlated_incidents == 1
    assert result.incidents[0].evidence_count == 4


def test_large_benign_haystack_stays_silent():
    events = load("clean") * 100
    result = analyze(events)

    assert result.correlated_incidents == 0
    assert result.suppressed is True


def test_reversed_input_order_preserves_complete_campaign():
    result = analyze(list(reversed(load("full_attack"))))

    assert result.correlated_incidents == 1
    assert result.incidents[0].reconstruction is not None
    assert result.incidents[0].reconstruction.temporal_valid is True
