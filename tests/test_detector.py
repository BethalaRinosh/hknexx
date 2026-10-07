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
    assert result.watchlist_candidates == 0
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
    assert result.watchlist_candidates == 1
    assert result.suppressed is True


def test_large_benign_backup_does_not_equal_exfiltration():
    result = analyze(load_scenarios()["benign_backup"])
    assert result.correlated_incidents == 0
    assert result.suppressed is True



def test_partial_chain_is_watchlisted_not_validated():
    events = [
        SecurityEvent(event_id="P1", timestamp="2026-10-06T17:00:00Z", event_type="login",
                      user="jane", device="DEV-30", src_ip="185.88.20.2",
                      application="IdentityPortal", source="auth", severity="medium",
                      metadata={"unusual_ip": True, "new_device": True}),
        SecurityEvent(event_id="P2", timestamp="2026-10-06T17:03:00Z", event_type="device_enroll",
                      user="jane", device="DEV-30", src_ip="185.88.20.2",
                      application="EndpointManager", source="endpoint", severity="medium",
                      metadata={"new_device": True}),
        SecurityEvent(event_id="P3", timestamp="2026-10-06T17:06:00Z", event_type="file_access",
                      user="jane", device="DEV-30", src_ip="185.88.20.2",
                      application="FileServer", resource="/finance/report.pdf", action="read",
                      source="file_server", severity="high", metadata={"sensitive": True}),
    ]
    result = analyze(events)
    assert result.correlated_incidents == 0
    assert result.watchlist_candidates == 1
    assert result.suppressed is True



def test_raw_log_normalizer_maps_common_aliases():
    from backend.normalizer import normalize_events

    raw = [
        {
            "id": "R1",
            "@timestamp": "2026-10-06T18:00:00Z",
            "type": "authentication",
            "username": "alex",
            "hostname": "WS-44",
            "source_ip": "185.90.8.4",
            "app": "IdentityPortal",
            "log_source": "windows",
            "level": "medium",
            "metadata": {"unusual_ip": True},
        },
        {
            "eventId": "R2",
            "timestamp": "2026-10-06T18:04:00Z",
            "event": "file_read",
            "account": "alex",
            "host": "WS-44",
            "srcip": "185.90.8.4",
            "application": "FileServer",
            "path": "/finance/acquisition.pdf",
            "source": "file-monitor",
            "severity": "high",
            "metadata": {"sensitive": True},
        },
    ]
    normalized = normalize_events(raw)
    assert normalized[0].event_type == "login"
    assert normalized[0].user == "alex"
    assert normalized[0].device == "WS-44"
    assert normalized[0].src_ip == "185.90.8.4"
    assert normalized[1].event_type == "file_access"
    assert normalized[1].resource == "/finance/acquisition.pdf"



def test_authorized_transfer_is_suppressed():
    result = analyze(load_scenarios()["authorized_transfer"])
    assert result.correlated_incidents == 0
    assert result.watchlist_candidates == 0
    assert result.suppressed is True


def test_large_backup_with_sensitive_access_is_suppressed():
    result = analyze(load_scenarios()["large_backup_with_sensitive_access"])
    assert result.correlated_incidents == 0
    assert result.suppressed is True


def test_shared_ip_does_not_merge_different_users():
    result = analyze(load_scenarios()["shared_ip_collision"])
    assert result.correlated_incidents == 0
    assert result.watchlist_candidates >= 1
    assert result.suppressed is True


def test_phase2_manifest_has_zero_false_positives_and_missed_attacks():
    from backend.evaluator import run_phase2

    report = run_phase2()
    assert report.failed_cases == 0
    assert report.false_positive_cases == 0
    assert report.missed_attack_cases == 0


def test_raw_attack_without_preset_flags_is_validated():
    from backend.normalizer import normalize_events

    raw = [
        {"event_id":"RAW-A1","timestamp":"2026-10-06T09:12:00Z","event_type":"login","user":"alice","device":"DEV-07","src_ip":"185.12.22.14","application":"IdentityPortal","source":"auth","severity":"medium"},
        {"event_id":"RAW-A2","timestamp":"2026-10-06T09:17:00Z","event_type":"file_access","user":"alice","device":"DEV-07","src_ip":"185.12.22.14","application":"FileServer","resource":"/finance/acquisition.pdf","action":"read","source":"file_server","severity":"high"},
        {"event_id":"RAW-A3","timestamp":"2026-10-06T09:20:00Z","event_type":"usb_mount","user":"alice","device":"DEV-07","src_ip":"185.12.22.14","application":"EndpointManager","resource":"USB-44","action":"mount","source":"endpoint","severity":"high"},
        {"event_id":"RAW-A4","timestamp":"2026-10-06T09:21:00Z","event_type":"file_copy","user":"alice","device":"DEV-07","src_ip":"185.12.22.14","application":"FileExplorer","resource":"/finance/acquisition.pdf","action":"copy_to_usb","source":"endpoint","severity":"critical","metadata":{"bytes":2400000000,"destination":"USB-44"}},
    ]
    result = analyze(normalize_events(raw))
    assert result.correlated_incidents == 1


def test_raw_clean_log_without_preset_flags_stays_silent():
    from backend.normalizer import normalize_events

    raw = [
        {"event_id":"RAW-C1","timestamp":"2026-10-06T08:30:00Z","event_type":"login","user":"bob","device":"DEV-02","src_ip":"10.0.0.21","application":"IdentityPortal","source":"auth","severity":"info"},
        {"event_id":"RAW-C2","timestamp":"2026-10-06T08:45:00Z","event_type":"file_access","user":"bob","device":"DEV-02","src_ip":"10.0.0.21","application":"FileServer","resource":"/team/project-plan.docx","action":"read","source":"file_server","severity":"info"},
        {"event_id":"RAW-C3","timestamp":"2026-10-06T09:10:00Z","event_type":"usb_mount","user":"bob","device":"DEV-02","src_ip":"10.0.0.21","application":"EndpointManager","resource":"USB-12","action":"mount","source":"endpoint","severity":"info"},
    ]
    result = analyze(normalize_events(raw))
    assert result.correlated_incidents == 0
    assert result.suppressed is True


def test_enrichment_derives_flags_without_overwriting_explicit_metadata():
    from backend.enrichment import enrich_events

    events = [
        SecurityEvent(event_id="E1", timestamp="2026-10-06T09:00:00Z", event_type="login",
                      user="alice", device="DEV-07", src_ip="185.12.22.14",
                      application="IdentityPortal", source="auth", metadata={}),
        SecurityEvent(event_id="E2", timestamp="2026-10-06T09:02:00Z", event_type="device_enroll",
                      user="alice", device="DEV-07", src_ip="185.12.22.14",
                      application="EndpointManager", source="endpoint", metadata={}),
        SecurityEvent(event_id="E3", timestamp="2026-10-06T09:04:00Z", event_type="file_access",
                      user="alice", device="DEV-07", src_ip="185.12.22.14",
                      application="FileServer", resource="/finance/acquisition.pdf",
                      source="file_server", metadata={}),
        SecurityEvent(event_id="E4", timestamp="2026-10-06T09:05:00Z", event_type="file_copy",
                      user="alice", device="DEV-07", src_ip="185.12.22.14",
                      application="FileExplorer", action="copy_to_usb", source="endpoint",
                      metadata={"bytes": 2_000_000_000, "destination": "USB-44",
                               "unusual_ip": False}),
    ]

    enriched = enrich_events(events)

    assert enriched[0].metadata["unusual_ip"] is True
    assert enriched[0].metadata["new_device"] is False
    assert enriched[1].metadata["new_device"] is True
    assert enriched[2].metadata["sensitive"] is True
    assert enriched[3].metadata["large_transfer"] is True
    assert enriched[3].metadata["removable_destination"] is True
    assert enriched[3].metadata["unusual_ip"] is False
