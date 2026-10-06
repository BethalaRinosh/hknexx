import json
from pathlib import Path

from backend.attack_intel import load_catalog, validate_emitted_techniques
from backend.detector import analyze
from backend.models import SecurityEvent


ROOT = Path(__file__).resolve().parents[1]


def load_attack() -> list[SecurityEvent]:
    with (ROOT / "backend" / "data" / "attack_logs.json").open("r", encoding="utf-8") as handle:
        return [SecurityEvent.model_validate(item) for item in json.load(handle)]


def test_attack_catalog_is_pinned_to_current_enterprise_version():
    catalog = load_catalog()
    assert set(catalog) == {"T1078", "T1005", "T1052.001"}
    assert {item["attack_version"] for item in catalog.values()} == {"19.2"}


def test_full_attack_gets_grounded_attack_mappings():
    result = analyze(load_attack())
    assert result.correlated_incidents == 1

    incident = result.incidents[0]
    mappings = {item.technique_id: item for item in incident.attack_techniques}

    assert set(mappings) == {"T1078", "T1005", "T1052.001"}
    assert mappings["T1078"].detection_strategy_id == "DET0560"
    assert mappings["T1005"].detection_strategy_id == "DET0380"
    assert mappings["T1052.001"].detection_strategy_id == "DET0220"
    assert "EVT-1001" in mappings["T1078"].evidence_event_ids
    assert "EVT-1003" in mappings["T1005"].evidence_event_ids
    assert set(mappings["T1052.001"].evidence_event_ids) == {"EVT-1004", "EVT-1005"}

    assert all(0.0 <= item.mapping_confidence <= 1.0 for item in incident.attack_techniques)
    assert all(item.evidence_event_ids for item in incident.attack_techniques)


def test_unknown_attack_ids_are_rejected():
    try:
        validate_emitted_techniques(["T9999"])
    except ValueError as exc:
        assert "T9999" in str(exc)
    else:
        raise AssertionError("unknown ATT&CK IDs must fail validation")


def test_usb_copy_uses_exfiltration_over_usb_not_data_from_removable_media():
    result = analyze(load_attack())
    techniques = {item.technique_id for item in result.incidents[0].attack_techniques}
    assert "T1052.001" in techniques
    assert "T1025" not in techniques
