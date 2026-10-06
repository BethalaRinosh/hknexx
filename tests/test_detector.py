import json
from pathlib import Path

from backend.detector import analyze
from backend.models import SecurityEvent


ROOT = Path(__file__).resolve().parents[1]


def load(name: str) -> list[SecurityEvent]:
    with (ROOT / "backend" / "data" / name).open("r", encoding="utf-8") as f:
        return [SecurityEvent.model_validate(x) for x in json.load(f)]


def test_attack_chain_is_validated():
    result = analyze(load("attack_logs.json"))
    assert result.correlated_incidents == 1
    incident = result.incidents[0]
    assert incident.status == "validated"
    assert incident.evidence_count >= 3
    assert len(incident.stages) >= 3
    assert len(incident.graph_nodes) >= 4
    assert len(incident.graph_edges) >= 3


def test_clean_logs_stay_silent():
    result = analyze(load("clean_logs.json"))
    assert result.correlated_incidents == 0
    assert result.suppressed is True
