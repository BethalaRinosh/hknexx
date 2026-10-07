from pathlib import Path

import yaml

from backend.detector import analyze
from backend.models import SecurityEvent


ROOT = Path(__file__).resolve().parents[1]


def _events():
    return [
        SecurityEvent(event_id="T3-1", timestamp="2026-10-07T09:00:00Z", event_type="login",
                      user="alice", device="DEV-07", src_ip="185.12.22.14",
                      application="IdentityPortal", source="auth", severity="medium"),
        SecurityEvent(event_id="T3-2", timestamp="2026-10-07T09:04:00Z", event_type="device_enroll",
                      user="alice", device="DEV-07", src_ip="185.12.22.14",
                      application="EndpointManager", source="endpoint", severity="medium"),
        SecurityEvent(event_id="T3-3", timestamp="2026-10-07T09:07:00Z", event_type="file_access",
                      user="alice", device="DEV-07", src_ip="185.12.22.14",
                      application="FileServer", resource="/finance/acquisition.pdf",
                      action="read", source="file_server", severity="high"),
        SecurityEvent(event_id="T3-4", timestamp="2026-10-07T09:10:00Z", event_type="usb_mount",
                      user="alice", device="DEV-07", src_ip="185.12.22.14",
                      application="EndpointManager", resource="USB-44", action="mount",
                      source="endpoint", severity="high"),
        SecurityEvent(event_id="T3-5", timestamp="2026-10-07T09:11:00Z", event_type="file_copy",
                      user="alice", device="DEV-07", src_ip="185.12.22.14",
                      application="FileExplorer", resource="/finance/acquisition.pdf",
                      action="copy_to_usb", source="endpoint", severity="critical",
                      metadata={"bytes": 2_400_000_000, "destination": "USB-44"}),
    ]


def test_rules_file_declares_stage_definitions_and_templates():
    rules = yaml.safe_load((ROOT / "config" / "rules.yml").read_text(encoding="utf-8"))
    assert len(rules["stages"]) == 3
    assert set(rules["stages"]) == {
        "identity",
        "sensitive_access",
        "exfiltration",
    }
    assert rules["templates"]["incident"]["title"]
    assert rules["templates"]["incident"]["recommended_actions"]


def test_custom_stage_and_incident_template_changes_output(tmp_path):
    config = yaml.safe_load((ROOT / "config" / "rules.yml").read_text(encoding="utf-8"))
    config["stages"]["identity"]["name"] = "Identity Gate"
    config["stages"]["identity"]["technique"] = "T9999"
    config["templates"]["incident"]["title"] = "Configured Exfiltration Case"
    config["templates"]["incident"]["recommended_actions"] = ["Follow the configured response playbook."]

    config_path = tmp_path / "rules.yml"
    config_path.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")

    result = analyze(_events(), config=config_path)

    assert result.correlated_incidents == 1
    incident = result.incidents[0]
    assert incident.title == "Configured Exfiltration Case"
    assert incident.recommended_actions == ["Follow the configured response playbook."]
    identity = next(stage for stage in incident.stages if stage.stage == "Identity Gate")
    assert identity.technique == "T9999"
