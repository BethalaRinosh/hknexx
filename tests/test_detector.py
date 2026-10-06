import json
from pathlib import Path

from backend.detector import analyze
from backend.models import SecurityEvent


ROOT = Path(__file__).resolve().parents[1]
SCENARIO_PATH = ROOT / "backend" / "data" / "scenarios.json"


def load_file(name: str) -> list[SecurityEvent]:
    with (ROOT / "backend" / "data" / name).open("r", encoding="utf-8") as f:
        return [SecurityEvent.model_validate(x) for x in json.load(f)]


def load_scenarios() -> dict[str, list[SecurityEvent]]:
    with SCENARIO_PATH.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    return {
        name: [SecurityEvent.model_validate(item) for item in events]
        for name, events in raw.items()
    }


def test_attack_chain_is_validated():
    result = analyze(load_file("attack_logs.json"))
    assert result.correlated_incidents == 1
    incident = result.incidents[0]
    assert incident.status == "validated"
    assert incident.chain_completeness == 1.0
    assert incident.corroboration_score == 1.0
    assert incident.temporal_score == 1.0
    assert incident.entity_consistency_score >= 0.99
    assert incident.evidence_count >= 4
    assert len(incident.stages) == 3
    assert len(incident.graph_nodes) >= 4
    assert len(incident.graph_edges) >= 3


def test_clean_logs_stay_silent():
    result = analyze(load_file("clean_logs.json"))
    assert result.correlated_incidents == 0
    assert result.suppressed is True
    assert result.suspicious_events == 0


def test_login_only_is_not_an_attack():
    result = analyze(load_scenarios()["login_only"])
    assert result.correlated_incidents == 0
    assert result.watchlist_candidates == 1
    assert result.suppressed is True


def test_legitimate_sensitive_access_is_not_an_attack():
    result = analyze(load_scenarios()["legitimate_sensitive_access"])
    assert result.correlated_incidents == 0
    assert result.suppressed is True


def test_usb_alone_is_not_an_attack():
    result = analyze(load_scenarios()["usb_only"])
    assert result.correlated_incidents == 0
    assert result.suppressed is True
    assert result.suspicious_events == 0


def test_mismatched_entities_are_not_merged():
    result = analyze(load_scenarios()["mismatched_entities"])
    assert result.correlated_incidents == 0
    assert result.suppressed is True


def test_reversed_attack_order_is_not_validated():
    result = analyze(load_scenarios()["reversed_order"])
    assert result.correlated_incidents == 0
    assert result.watchlist_candidates >= 1
    assert result.suppressed is True


def test_slow_attack_outside_window_is_not_validated():
    result = analyze(load_scenarios()["slow_attack"])
    assert result.correlated_incidents == 0
    assert result.suppressed is True


def test_large_benign_backup_does_not_equal_exfiltration():
    result = analyze(load_scenarios()["benign_backup"])
    assert result.correlated_incidents == 0
    assert result.suppressed is True
