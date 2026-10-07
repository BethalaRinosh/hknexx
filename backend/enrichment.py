from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import yaml

from .models import SecurityEvent

ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = ROOT / "config" / "rules.yml"


def _load_rules() -> dict[str, Any]:
    with RULES_PATH.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _truthy(value: Any) -> bool:
    return bool(value) and str(value).strip().lower() not in {"false", "0", "no", "none"}


def _is_private_ip(value: str | None, ranges: list[str]) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(item) for item in ranges)


def _contains_token(value: Any, tokens: list[str]) -> bool:
    text = str(value or "").lower()
    return any(token.lower() in text for token in tokens)


def enrich_events(events: list[SecurityEvent]) -> list[SecurityEvent]:
    """Derive detector signals from normalized events without overwriting explicit flags."""
    rules = _load_rules().get("enrichment", {})
    result: list[SecurityEvent] = []

    device_enrollments = {
        (event.user, event.device)
        for event in events
        if event.event_type in set(rules.get("new_device", {}).get("event_types", []))
        and event.user
        and event.device
    }

    for event in events:
        metadata = dict(event.metadata)
        resource = str(event.resource or "")
        action = str(event.action or "")
        destination = str(metadata.get("destination", ""))

        public_ip_rule = rules.get("suspicious_public_ip", {})
        if (
            public_ip_rule.get("enabled", True)
            and event.event_type == "login"
            and event.src_ip
            and "unusual_ip" not in metadata
        ):
            metadata["unusual_ip"] = not _is_private_ip(
                event.src_ip,
                public_ip_rule.get("private_ranges", []),
            )

        device_rule = rules.get("new_device", {})
        if device_rule.get("enabled", True) and "new_device" not in metadata:
            metadata["new_device"] = (
                (event.user, event.device) in device_enrollments
                or event.event_type in set(device_rule.get("event_types", []))
            )

        sensitive_rule = rules.get("sensitive_resource", {})
        if sensitive_rule.get("enabled", True) and "sensitive" not in metadata:
            metadata["sensitive"] = _contains_token(
                resource,
                sensitive_rule.get("keywords", []),
            )

        transfer_rule = rules.get("large_transfer", {})
        try:
            copied_bytes = int(metadata.get("bytes", 0) or 0)
        except (TypeError, ValueError):
            copied_bytes = 0
        if transfer_rule.get("enabled", True) and "large_transfer" not in metadata:
            metadata["large_transfer"] = copied_bytes >= int(transfer_rule.get("bytes", 1_000_000_000))

        removable_rule = rules.get("removable_destination", {})
        if removable_rule.get("enabled", True) and "removable_destination" not in metadata:
            metadata["removable_destination"] = _contains_token(
                destination,
                removable_rule.get("tokens", []),
            ) or _contains_token(action, removable_rule.get("tokens", []))

        result.append(event.model_copy(update={"metadata": metadata}))

    return result
