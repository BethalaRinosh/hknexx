from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from .models import SecurityEvent
from .normalizer import canonical_event_type, normalize_event


def _eventdata_map(event_data: Any) -> dict[str, Any]:
    if isinstance(event_data, dict):
        data = event_data.get("Data") or event_data.get("data") or event_data
        if isinstance(data, dict):
            return {str(k): v for k, v in data.items()}
        if isinstance(data, list):
            result: dict[str, Any] = {}
            for item in data:
                if isinstance(item, dict) and "Name" in item:
                    result[str(item["Name"])] = item.get("#text", item.get("value"))
            return result

    if isinstance(event_data, list):
        result: dict[str, Any] = {}
        for item in event_data:
            if isinstance(item, dict) and "Name" in item:
                result[str(item["Name"])] = item.get("#text", item.get("value"))
        return result

    return {}


def normalize_windows_event(raw: dict[str, Any], index: int = 0) -> SecurityEvent:
    system = raw.get("System") or raw.get("system") or {}
    data = _eventdata_map(raw.get("EventData") or raw.get("event_data") or {})

    event_id = str(
        system.get("EventID")
        or system.get("event_id")
        or raw.get("event_id")
        or f"WIN-{index + 1:05d}"
    )
    created = system.get("TimeCreated") or system.get("time_created") or {}
    timestamp = (
        created.get("SystemTime")
        if isinstance(created, dict)
        else created
    ) or raw.get("timestamp")

    computer = system.get("Computer") or system.get("computer")
    try:
        code = int(str(system.get("EventID") or event_id))
    except ValueError:
        code = 0

    metadata = dict(data)
    metadata["windows_event_id"] = code
    provider = system.get("Provider") or system.get("provider")
    metadata["provider"] = (
        provider.get("Name") if isinstance(provider, dict) else provider
    )

    if code == 4624:
        return normalize_event(
            {
                "event_id": event_id,
                "timestamp": timestamp,
                "event_type": "login",
                "user": data.get("TargetUserName") or data.get("SubjectUserName"),
                "device": computer,
                "src_ip": data.get("IpAddress"),
                "application": "Windows Security",
                "source": "windows_security_4624",
                "severity": "info",
                "session_id": data.get("TargetLogonId") or data.get("SubjectLogonId"),
                "metadata": metadata,
            },
            index,
        )

    if code == 4663:
        accesses = str(data.get("AccessList") or "")
        action = "read" if "%%4416" in accesses else "object_access"
        event_type = "file_access" if data.get("ObjectType") == "File" else "object_access"
        return normalize_event(
            {
                "event_id": event_id,
                "timestamp": timestamp,
                "event_type": event_type,
                "user": data.get("SubjectUserName"),
                "device": computer,
                "application": data.get("ProcessName"),
                "process": data.get("ProcessName"),
                "resource": data.get("ObjectName"),
                "action": action,
                "source": "windows_security_4663",
                "severity": "medium",
                "session_id": data.get("SubjectLogonId"),
                "metadata": metadata,
            },
            index,
        )

    return normalize_event(
        {
            "event_id": event_id,
            "timestamp": timestamp,
            "event_type": canonical_event_type(raw.get("event_type") or f"windows_event_{code}"),
            "user": data.get("TargetUserName") or data.get("SubjectUserName"),
            "device": computer,
            "src_ip": data.get("IpAddress"),
            "application": data.get("Application") or data.get("ProcessName"),
            "process": data.get("ProcessName"),
            "resource": data.get("ObjectName"),
            "source": f"windows_security_{code}",
            "severity": "info",
            "session_id": data.get("TargetLogonId") or data.get("SubjectLogonId"),
            "metadata": metadata,
        },
        index,
    )


def _normalize_windows_xml_node(root: ET.Element, index: int = 0) -> SecurityEvent:
    namespaces = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    system = root.find("e:System", namespaces)
    event_data = root.find("e:EventData", namespaces)

    system_map: dict[str, Any] = {}
    if system is not None:
        provider = system.find("e:Provider", namespaces)
        time_created = system.find("e:TimeCreated", namespaces)
        system_map["EventID"] = system.findtext("e:EventID", default="", namespaces=namespaces)
        system_map["Computer"] = system.findtext("e:Computer", default="", namespaces=namespaces)
        system_map["Provider"] = {"Name": provider.get("Name")} if provider is not None else {}
        system_map["TimeCreated"] = {
            "SystemTime": time_created.get("SystemTime")
        } if time_created is not None else {}

    data_map: dict[str, Any] = {}
    if event_data is not None:
        for node in event_data.findall("e:Data", namespaces):
            name = node.get("Name")
            if name:
                data_map[name] = node.text

    return normalize_windows_event(
        {"System": system_map, "EventData": data_map},
        index=index,
    )


def normalize_windows_events_xml(xml_text: str) -> list[SecurityEvent]:
    root = ET.fromstring(xml_text)
    namespaces = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

    if root.tag.endswith("Event"):
        nodes = [root]
    else:
        nodes = root.findall(".//e:Event", namespaces)

    if not nodes:
        raise ET.ParseError("Windows XML contains no Event elements")

    return [_normalize_windows_xml_node(node, index=i) for i, node in enumerate(nodes)]


def normalize_windows_event_xml(xml_text: str, index: int = 0) -> SecurityEvent:
    root = ET.fromstring(xml_text)
    namespaces = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    if root.tag.endswith("Event"):
        node = root
    else:
        nodes = root.findall(".//e:Event", namespaces)
        if not nodes:
            raise ET.ParseError("Windows XML contains no Event elements")
        node = nodes[0]
    return _normalize_windows_xml_node(node, index=index)


def normalize_sysmon_event(raw: dict[str, Any], index: int = 0) -> SecurityEvent:
    data = dict(
        raw.get("EventData")
        or raw.get("event_data")
        or raw.get("data")
        or raw
    )
    system = raw.get("System") or raw.get("system") or {}

    event_id = str(
        system.get("EventID")
        or raw.get("EventID")
        or raw.get("event_id")
        or f"SYSMON-{index + 1:05d}"
    )
    timestamp = (
        data.get("UtcTime")
        or raw.get("UtcTime")
        or raw.get("@timestamp")
        or raw.get("timestamp")
    )
    computer = system.get("Computer") or raw.get("Computer") or raw.get("computer")

    try:
        numeric_event_id = int(str(event_id))
    except ValueError:
        numeric_event_id = 0

    type_map = {
        1: "process_create",
        3: "network_connection",
        11: "file_create",
        22: "dns_query",
    }
    event_type = type_map.get(numeric_event_id, f"sysmon_event_{numeric_event_id}")

    return normalize_event(
        {
            "event_id": event_id,
            "timestamp": timestamp,
            "event_type": event_type,
            "user": data.get("User") or data.get("UserName"),
            "device": computer,
            "src_ip": data.get("SourceIp"),
            "dst_ip": data.get("DestinationIp"),
            "application": "Sysmon",
            "process": data.get("Image"),
            "pid": data.get("ProcessId"),
            "parent_process": data.get("ParentImage"),
            "resource": data.get("TargetFilename"),
            "action": event_type,
            "source": "sysmon",
            "severity": "info",
            "metadata": {
                **data,
                "sysmon_event_id": numeric_event_id,
                "rule_name": data.get("RuleName"),
                "destination_port": data.get("DestinationPort"),
            },
        },
        index,
    )


def normalize_zeek_event(
    raw: dict[str, Any],
    stream: str = "conn",
    index: int = 0,
) -> SecurityEvent:
    timestamp = raw.get("ts") or raw.get("timestamp") or raw.get("@timestamp")
    orig_h = raw.get("id.orig_h")
    resp_h = raw.get("id.resp_h")

    if stream == "http":
        event_type = "http_request"
        application = "Zeek HTTP"
        resource = raw.get("uri") or raw.get("host")
        action = raw.get("method") or "HTTP"
    elif stream == "dns":
        event_type = "dns_query"
        application = "Zeek DNS"
        resource = raw.get("query")
        action = "DNS"
    else:
        event_type = "network_connection"
        application = "Zeek"
        resource = raw.get("service") or raw.get("proto")
        action = "connection"

    return normalize_event(
        {
            "event_id": raw.get("uid") or f"ZEEK-{index + 1:05d}",
            "timestamp": timestamp,
            "event_type": event_type,
            "device": raw.get("local_orig_h") or orig_h,
            "src_ip": orig_h,
            "dst_ip": resp_h,
            "application": application,
            "resource": resource,
            "action": action,
            "source": f"zeek_{stream}",
            "severity": "info",
            "metadata": dict(raw),
        },
        index,
    )
