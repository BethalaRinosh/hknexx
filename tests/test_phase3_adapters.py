import json
from pathlib import Path

from backend.adapters import (
    normalize_sysmon_event,
    normalize_windows_event,
    normalize_windows_event_xml,
    normalize_zeek_event,
)
from backend.models import SecurityEvent
from backend.normalizer import normalize_event


ROOT = Path(__file__).resolve().parents[1]
SCENARIO_PATH = ROOT / "backend" / "data" / "scenarios.json"


def load_scenarios() -> dict[str, list[SecurityEvent]]:
    with SCENARIO_PATH.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    return {
        name: [SecurityEvent.model_validate(item) for item in events]
        for name, events in raw.items()
    }


def test_sysmon_process_event_normalizes_real_fields():
    event = normalize_sysmon_event(
        {
            "System": {"EventID": 1, "Computer": "WIN-01"},
            "EventData": {
                "UtcTime": "2026-10-06T19:00:00Z",
                "User": "CORP\\alice",
                "Image": "C:\\Windows\\System32\\powershell.exe",
                "ProcessId": "0x1234",
                "ParentImage": "C:\\Windows\\explorer.exe",
                "CommandLine": "powershell.exe -enc AAAA",
            },
        }
    )
    assert event.event_type == "process_create"
    assert event.user == r"CORP\alice"
    assert event.device == "WIN-01"
    assert event.process.endswith("powershell.exe")
    assert event.pid == int("0x1234", 16)
    assert event.parent_process.endswith("explorer.exe")
    assert event.metadata["sysmon_event_id"] == 1


def test_windows_4624_normalizes_identity_and_source_ip():
    event = normalize_windows_event(
        {
            "System": {
                "EventID": 4624,
                "Computer": "WIN-DC01",
                "TimeCreated": {"SystemTime": "2026-10-06T19:05:00Z"},
                "Provider": {"Name": "Microsoft-Windows-Security-Auditing"},
            },
            "EventData": {
                "TargetUserName": "alice",
                "TargetLogonId": "0x9ab",
                "IpAddress": "203.0.113.44",
                "LogonType": "10",
            },
        }
    )
    assert event.event_type == "login"
    assert event.user == "alice"
    assert event.device == "WIN-DC01"
    assert event.src_ip == "203.0.113.44"
    assert event.session_id == "0x9ab"
    assert event.metadata["windows_event_id"] == 4624


def test_windows_4663_normalizes_file_object_access():
    event = normalize_windows_event(
        {
            "System": {
                "EventID": 4663,
                "Computer": "WIN-FS01",
                "TimeCreated": {"SystemTime": "2026-10-06T19:08:00Z"},
            },
            "EventData": {
                "SubjectUserName": "alice",
                "SubjectLogonId": "0x9ab",
                "ObjectType": "File",
                "ObjectName": "C:\\Finance\\acquisition.pdf",
                "ProcessName": "C:\\Windows\\explorer.exe",
                "AccessList": "%%4416",
            },
        }
    )
    assert event.event_type == "file_access"
    assert event.user == "alice"
    assert event.resource.endswith("acquisition.pdf")
    assert event.process.endswith("explorer.exe")
    assert event.session_id == "0x9ab"
    assert event.action == "read"


def test_windows_security_xml_is_supported():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Microsoft-Windows-Security-Auditing"/>
        <EventID>4624</EventID>
        <TimeCreated SystemTime="2026-10-06T19:10:00Z"/>
        <Computer>WIN-DC01</Computer>
      </System>
      <EventData>
        <Data Name="TargetUserName">alice</Data>
        <Data Name="TargetLogonId">0x123</Data>
        <Data Name="IpAddress">203.0.113.55</Data>
      </EventData>
    </Event>"""
    event = normalize_windows_event_xml(xml)
    assert event.event_type == "login"
    assert event.user == "alice"
    assert event.src_ip == "203.0.113.55"


def test_zeek_http_json_is_supported():
    event = normalize_zeek_event(
        {
            "ts": 1791313800.125,
            "uid": "C123",
            "id.orig_h": "10.0.0.20",
            "id.resp_h": "93.184.216.34",
            "id.resp_p": 443,
            "method": "GET",
            "host": "example.com",
            "uri": "/download",
            "user_agent": "Mozilla/5.0",
        },
        stream="http",
    )
    assert event.event_type == "http_request"
    assert event.src_ip == "10.0.0.20"
    assert event.dst_ip == "93.184.216.34"
    assert event.resource == "/download"
    assert event.action == "GET"


def test_generic_normalizer_preserves_expanded_identity_fields():
    event = normalize_event(
        {
            "event_id": "GEN-1",
            "timestamp": "2026-10-06T19:15:00Z",
            "type": "network_connection",
            "user": "alice",
            "hostname": "DEV-01",
            "src_ip": "10.0.0.2",
            "destination_ip": "10.0.0.8",
            "process": "chrome.exe",
            "pid": "1234",
            "logon_id": "0x555",
            "source": "application",
        }
    )
    assert event.dst_ip == "10.0.0.8"
    assert event.process == "chrome.exe"
    assert event.pid == 1234
    assert event.session_id == "0x555"


def test_windows_xml_export_with_multiple_events_is_supported():
    xml = """<Events xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <Event>
        <System>
          <EventID>4624</EventID>
          <TimeCreated SystemTime="2026-10-06T19:10:00Z"/>
          <Computer>WIN-DC01</Computer>
        </System>
        <EventData>
          <Data Name="TargetUserName">alice</Data>
          <Data Name="IpAddress">203.0.113.55</Data>
        </EventData>
      </Event>
      <Event>
        <System>
          <EventID>4624</EventID>
          <TimeCreated SystemTime="2026-10-06T19:11:00Z"/>
          <Computer>WIN-DC02</Computer>
        </System>
        <EventData>
          <Data Name="TargetUserName">bob</Data>
          <Data Name="IpAddress">203.0.113.56</Data>
        </EventData>
      </Event>
    </Events>"""

    from backend.adapters import normalize_windows_events_xml

    events = normalize_windows_events_xml(xml)
    assert len(events) == 2
    assert events[0].user == "alice"
    assert events[1].user == "bob"
