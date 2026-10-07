import json
from pathlib import Path

from backend.detector import analyze
from backend.models import SecurityEvent


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "backend" / "data" / "scenarios.json"


def load_scenarios():
    raw = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    return {
        name: [SecurityEvent.model_validate(item) for item in events]
        for name, events in raw.items()
    }


def test_judge_full_attack_contract():
    result = analyze(load_scenarios()["full_attack"])
    assert result.correlated_incidents == 1

    incident = result.incidents[0]
    assert incident.status == "validated"
    assert len(incident.stages) == 3
    assert all(stage.evidence for stage in incident.stages)
    assert incident.reconstruction is not None
    assert incident.reconstruction.selected_event_ids
    assert incident.attack_techniques
    assert incident.recommended_actions

    # These are the fields consumed directly by the judge dashboard.
    assert result.total_events > 0
    assert result.suspicious_events > 0
    assert result.watchlist_candidates >= 0
    assert result.correlated_incidents == 1


def test_judge_clean_control_contract():
    result = analyze(load_scenarios()["clean"])
    assert result.correlated_incidents == 0
    assert result.suppressed is True
    assert result.incidents == []


def test_judge_partial_controls_remain_silent():
    scenarios = load_scenarios()
    for name in ("login_only", "usb_only", "reversed_order", "mismatched_entities"):
        result = analyze(scenarios[name])
        assert result.correlated_incidents == 0, name
        assert result.suppressed is True, name


def test_fixed_demo_routes_are_not_shadowed_by_scenario_route():
    from fastapi.testclient import TestClient
    from backend.main import app

    client = TestClient(app)
    attack = client.get("/api/demo/attack")
    clean = client.get("/api/demo/clean")

    assert attack.status_code == 200
    assert attack.json()["correlated_incidents"] == 1
    assert clean.status_code == 200
    assert clean.json()["correlated_incidents"] == 0
