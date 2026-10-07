from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import yaml

from .models import SecurityEvent

ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = ROOT / "config" / "rules.yml"


def _load_rules(config: str | Path | dict[str, Any] | None = None) -> dict[str, Any]:
    if config is None:
        path = RULES_PATH
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    if isinstance(config, dict):
        return config
    with Path(config).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _is_private_ip(value: str | None, ranges: list[str]) -> bool:
    if not value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in ipaddress.ip_network(item) for item in ranges)


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


def enrich_events(
    events: list[SecurityEvent],
    config: str | Path | dict[str, Any] | None = None,
) -> list[SecurityEvent]:
    """Derive detector signals from normalized events without overwriting explicit flags."""
    rules = _load_rules(config).get("enrichment", {})
    result: list[SecurityEvent] = []
    ordered = sorted(events, key=lambda event: event.timestamp)

    device_rule = rules.get("new_device", {})
    enrollment_types = set(device_rule.get("event_types", []))
    device_enrollments = {
        (event.user, event.device)
        for event in ordered
        if event.event_type in enrollment_types and event.user and event.device
    }

    seen_ips: dict[str, set[str]] = {}
    for event in ordered:
        metadata = dict(event.metadata)
        user = str(event.user or "")
        resource = str(event.resource or "")
        action = str(event.action or "")
        destination = str(metadata.get("destination", ""))

        public_ip_rule = rules.get("suspicious_public_ip", {})
        if public_ip_rule.get("enabled", True) and event.event_type == "login" and "unusual_ip" not in metadata:
            previous_ips = seen_ips.get(user, set())
            metadata["unusual_ip"] = bool(
                event.src_ip
                and event.src_ip not in previous_ips
                and not _is_private_ip(event.src_ip, public_ip_rule.get("private_ranges", []))
            )
        if event.src_ip and user:
            seen_ips.setdefault(user, set()).add(event.src_ip)

        if device_rule.get("enabled", True) and "new_device" not in metadata:
            metadata["new_device"] = (
                (event.user, event.device) in device_enrollments
                or event.event_type in enrollment_types
            )

        sensitive_rule = rules.get("sensitive_resource", {})
        if sensitive_rule.get("enabled", True) and "sensitive" not in metadata:
            metadata["sensitive"] = _contains_token(resource, sensitive_rule.get("keywords", []))

        transfer_rule = rules.get("large_transfer", {})
        try:
            copied_bytes = int(metadata.get("bytes", 0) or 0)
        except (TypeError, ValueError):
            copied_bytes = 0
        if transfer_rule.get("enabled", True) and "large_transfer" not in metadata:
            metadata["large_transfer"] = copied_bytes >= int(
                transfer_rule.get("bytes", 1_000_000_000)
            )

        removable_rule = rules.get("removable_destination", {})
        if removable_rule.get("enabled", True) and "removable_destination" not in metadata:
            metadata["removable_destination"] = (
                bool(metadata.get("removable"))
                or _contains_token(destination, removable_rule.get("tokens", []))
                or _contains_token(action, removable_rule.get("tokens", []))
                or _contains_token(resource, removable_rule.get("tokens", []))
            )

        result.append(event.model_copy(update={"metadata": metadata}))

    return result
