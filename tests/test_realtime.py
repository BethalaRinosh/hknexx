import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import app


ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "backend" / "data" / "scenarios.json"


def test_realtime_simulation_streams_events_and_final_incident():
    with TestClient(app) as client:
        with client.websocket_connect("/ws/simulate/full_attack?delay=0") as websocket:
            messages = []
            while True:
                message = websocket.receive_json()
                messages.append(message)
                if message["type"] == "complete":
                    break

    event_messages = [item for item in messages if item["type"] == "event"]
    assert len(event_messages) == 5
    assert [item["event"]["event_id"] for item in event_messages] == [
        "ATTACK-001",
        "ATTACK-002",
        "ATTACK-003",
        "ATTACK-004",
        "ATTACK-005",
    ]

    progress = [item["analysis"]["correlated_incidents"] for item in event_messages]
    assert progress[:3] == [0, 0, 0]
    assert progress[-2:] == [1, 1]

    complete = messages[-1]
    assert complete["type"] == "complete"
    assert complete["analysis"]["correlated_incidents"] == 1
    assert complete["event_count"] == 5


def test_realtime_simulation_rejects_unknown_scenario():
    with TestClient(app) as client:
        with client.websocket_connect("/ws/simulate/does-not-exist?delay=0") as websocket:
            message = websocket.receive_json()

    assert message["type"] == "error"
    assert "unknown scenario" in message["message"]


def test_simulation_data_matches_repository_scenario():
    raw = json.loads(SCENARIOS.read_text(encoding="utf-8"))
    assert len(raw["full_attack"]) == 5
