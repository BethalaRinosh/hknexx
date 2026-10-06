import json
from pathlib import Path

from backend.reconstructor import STAGE_EXFIL, STAGE_IDENTITY, STAGE_SENSITIVE, reconstruct
from backend.models import SecurityEvent


ROOT = Path(__file__).resolve().parents[1]


def load_scenario(name: str) -> list[SecurityEvent]:
    with (ROOT / "backend" / "data" / "scenarios.json").open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    return [SecurityEvent.model_validate(item) for item in raw[name]]


def test_full_attack_reconstructs_one_coherent_path():
    result = reconstruct(load_scenario("full_attack"))
    assert result.temporal_valid is True
    assert len(result.selected_event_ids) == 3
    assert result.reconstruction_score >= 0.65
    assert result.entity_conflicts == 0
    assert set(result.stage_event_ids) == {
        STAGE_IDENTITY,
        STAGE_SENSITIVE,
        STAGE_EXFIL,
    }
    assert len(result.edges) == 2
    assert "ATTACK-005" in result.decoy_event_ids
    assert "ATTACK-004" in result.decoy_event_ids


def test_reconstruction_chooses_best_identity_candidate_and_keeps_decoys():
    events = load_scenario("full_attack")
    events.insert(
        2,
        SecurityEvent(
            event_id="DECOY-IDENTITY",
            timestamp="2026-10-06T09:15:30Z",
            event_type="login",
            user="alice",
            device="DEV-99",
            src_ip="10.0.0.99",
            application="IdentityPortal",
            source="auth",
            severity="high",
            metadata={"unusual_ip": True},
        ),
    )
    result = reconstruct(events)
    assert result.temporal_valid is True
    assert result.selected_event_ids[0] == "ATTACK-001"
    assert "DECOY-IDENTITY" in result.decoy_event_ids
    assert result.entity_conflicts == 0


def test_mismatched_entities_have_no_complete_reconstruction():
    result = reconstruct(load_scenario("mismatched_entities"))
    assert result.selected_event_ids == []
    assert result.temporal_valid is False
    assert result.reconstruction_score == 0.0


def test_reversed_order_has_no_valid_causal_path():
    result = reconstruct(load_scenario("reversed_order"))
    assert result.selected_event_ids == []
    assert result.temporal_valid is False


def test_slow_attack_is_not_reconstructed_across_window():
    result = reconstruct(load_scenario("slow_attack"))
    assert result.selected_event_ids == []
    assert result.temporal_valid is False
