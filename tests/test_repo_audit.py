from pathlib import Path

from backend.detector import _is_removable_exfil, _stage_config
from backend.enrichment import enrich_events
from backend.models import SecurityEvent

ROOT = Path(__file__).resolve().parents[1]

def _event(**kwargs):
    return SecurityEvent(
        event_id=kwargs.pop("event_id", "AUDIT-1"),
        timestamp=kwargs.pop("timestamp", "2026-10-07T09:00:00Z"),
        event_type=kwargs.pop("event_type", "file_copy"),
        user=kwargs.pop("user", "alice"),
        device=kwargs.pop("device", "WS-1"),
        source="audit",
        metadata=kwargs.pop("metadata", {}),
        **kwargs,
    )

def test_partial_nested_stage_config_preserves_default_keys():
    merged = _stage_config({"stages": {"identity": {"confidence": {"with_login_and_device": 0.99}}}}, "identity")
    assert merged["confidence"]["with_login_and_device"] == 0.99
    assert merged["confidence"]["without_device"] == 0.76
    assert merged["evidence_reasons"]["login"]

def test_malformed_copy_size_fails_closed():
    event = _event(metadata={"bytes": "not-a-number", "destination": "usb://drive", "removable_destination": True})
    assert _is_removable_exfil(event) is False

def test_explicit_non_removable_override_wins_over_destination_text():
    event = _event(metadata={"bytes": 2_000_000_000, "destination": "usb://drive", "removable_destination": False})
    assert _is_removable_exfil(event) is False

def test_configured_large_transfer_threshold_controls_exfiltration():
    event = _event(metadata={"bytes": 600_000_000, "destination": "archive://external"})
    enriched = enrich_events([event], config={"enrichment": {
        "large_transfer": {"enabled": True, "bytes": 500_000_000},
        "removable_destination": {"enabled": True, "tokens": ["external"]},
    }})[0]
    assert enriched.metadata["large_transfer"] is True
    assert enriched.metadata["removable_destination"] is True
    assert _is_removable_exfil(enriched) is True

def test_new_device_signal_does_not_backdate_from_future_enrollment():
    login = _event(event_id="AUDIT-LOGIN", timestamp="2026-10-07T09:00:00Z", event_type="login", metadata={})
    enrollment = _event(event_id="AUDIT-DEVICE", timestamp="2026-10-07T09:05:00Z", event_type="device_enroll", metadata={})
    enriched = enrich_events([login, enrollment], config={"enrichment": {
        "new_device": {"enabled": True, "event_types": ["device_enroll"]},
    }})
    assert enriched[0].metadata.get("new_device") is not True
    assert enriched[1].metadata["new_device"] is True

def test_dashboard_escapes_untrusted_event_type():
    app_js = (ROOT / "frontend" / "app.js").read_text(encoding="utf-8")
    assert '${esc(pretty(e.event_type))}' in app_js

def test_phase7_spec_documents_offline_hardening():
    spec = (ROOT / "docs" / "PHASE7_SPEC.md").read_text(encoding="utf-8")
    assert "LLM_OFFLINE=1" in spec
    assert "LLM_MAX_RESPONSE_BYTES" in spec
    assert "HTTP or HTTPS" in spec
