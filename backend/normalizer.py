from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .models import SecurityEvent

ALIASES = {
    "event_id": ("event_id", "id", "eventId", "uid"),
    "timestamp": ("timestamp", "time", "@timestamp", "datetime", "ts"),
    "event_type": ("event_type", "type", "category", "event", "action"),
    "user": ("user", "username", "account", "principal", "actor"),
    "device": ("device", "device_id", "hostname", "host", "computer"),
    "src_ip": ("src_ip", "source_ip", "srcip", "client_ip", "ip"),
    "application": ("application", "app", "process", "service", "program"),
    "resource": ("resource", "file", "path", "object"),
    "action": ("action", "operation", "activity"),
    "source": ("source", "log_source", "vendor", "channel"),
    "severity": ("severity", "level", "priority"),
}


def _first(raw: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        if name in raw and raw[name] not in (None, ""):
            return raw[name]
    return None


def _timestamp(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        # Heuristic: milliseconds are much larger than Unix seconds.
        seconds = float(value) / 1000 if float(value) > 10_000_000_000 else float(value)
        return datetime.fromtimestamp(seconds, tz=timezone.utc)

    text = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _canonical_event_type(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    mappings = {
        "authentication": "login",
        "auth": "login",
        "signin": "login",
        "sign_in": "login",
        "device_registration": "device_enroll",
        "new_device": "device_enroll",
        "file_read": "file_access",
        "read": "file_access",
        "usb_insert": "usb_mount",
        "removable_media": "usb_mount",
        "copy": "file_copy",
        "file_transfer": "file_copy",
    }
    return mappings.get(text, text)


def normalize_event(raw: dict[str, Any], index: int = 0) -> SecurityEvent:
    metadata = dict(raw.get("metadata") or {})

    event_id = _first(raw, ALIASES["event_id"]) or f"NORM-{index + 1:05d}"
    timestamp = _timestamp(_first(raw, ALIASES["timestamp"]))
    event_type = _canonical_event_type(_first(raw, ALIASES["event_type"]))

    return SecurityEvent(
        event_id=str(event_id),
        timestamp=timestamp,
        event_type=event_type,
        user=_first(raw, ALIASES["user"]),
        device=_first(raw, ALIASES["device"]),
        src_ip=_first(raw, ALIASES["src_ip"]),
        application=_first(raw, ALIASES["application"]),
        resource=_first(raw, ALIASES["resource"]),
        action=_first(raw, ALIASES["action"]),
        source=str(_first(raw, ALIASES["source"]) or "unknown"),
        severity=str(_first(raw, ALIASES["severity"]) or "info").lower(),
        metadata=metadata,
    )


def normalize_events(raw_events: list[dict[str, Any]]) -> list[SecurityEvent]:
    return [normalize_event(raw, index=i) for i, raw in enumerate(raw_events)]
