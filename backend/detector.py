from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Iterable

from .models import AnalysisResponse, AttackStage, EvidenceItem, Incident, SecurityEvent


DEMO_WINDOW = timedelta(minutes=30)


def _entity_keys(event: SecurityEvent) -> set[str]:
    keys = set()
    if event.user:
        keys.add(f"user:{event.user}")
    if event.device:
        keys.add(f"device:{event.device}")
    if event.src_ip:
        keys.add(f"ip:{event.src_ip}")
    if event.application:
        keys.add(f"app:{event.application}")
    if event.resource:
        keys.add(f"resource:{event.resource}")
    return keys


def _event_score(event: SecurityEvent) -> float:
    score = 0.0
    unusual_ip = event.metadata.get("unusual_ip", False)
    new_device = event.metadata.get("new_device", False)
    sensitive = event.metadata.get("sensitive", False)

    if event.event_type == "login" and unusual_ip:
        score += 0.25
    if new_device:
        score += 0.20
    if event.event_type == "file_access" and sensitive:
        score += 0.20
    if event.event_type == "usb_mount":
        score += 0.20
    if event.event_type == "file_copy" and event.metadata.get("bytes", 0) >= 1_000_000_000:
        score += 0.30

    severity_bonus = {"critical": 0.20, "high": 0.15, "medium": 0.08}.get(event.severity, 0.0)
    return min(1.0, score + severity_bonus)


def _same_campaign(events: list[SecurityEvent]) -> list[SecurityEvent]:
    if not events:
        return []

    events = sorted(events, key=lambda e: e.timestamp)
    anchor = events[0]

    candidates = [
        e for e in events
        if e.timestamp - anchor.timestamp <= DEMO_WINDOW
        and (
            (anchor.user and e.user == anchor.user)
            or (anchor.device and e.device == anchor.device)
            or (anchor.src_ip and e.src_ip == anchor.src_ip)
        )
    ]
    return candidates


def _stage(events: list[SecurityEvent], event_type: str) -> SecurityEvent | None:
    return next((e for e in events if e.event_type == event_type), None)


def analyze(events: Iterable[SecurityEvent]) -> AnalysisResponse:
    ordered = sorted(events, key=lambda e: e.timestamp)

    suspicious = [e for e in ordered if _event_score(e) > 0]
    if not suspicious:
        return AnalysisResponse(
            total_events=len(ordered),
            suspicious_events=0,
            correlated_incidents=0,
            incidents=[],
            suppressed=True,
        )

    grouped: dict[str, list[SecurityEvent]] = defaultdict(list)
    for event in suspicious:
        key = event.user or event.device or event.src_ip or "unknown"
        grouped[key].append(event)

    incidents: list[Incident] = []

    for key, group in grouped.items():
        chain = _same_campaign(group)

        login = next(
            (
                e for e in chain
                if e.event_type == "login" and e.metadata.get("unusual_ip", False)
            ),
            None,
        )
        file_access = next(
            (
                e for e in chain
                if e.event_type == "file_access" and e.metadata.get("sensitive", False)
            ),
            None,
        )
        usb = _stage(chain, "usb_mount")
        copy = next(
            (
                e for e in chain
                if e.event_type == "file_copy"
                and e.metadata.get("bytes", 0) >= 1_000_000_000
            ),
            None,
        )

        evidence = [e for e in (login, file_access, usb, copy) if e is not None]

        # A single anomaly is deliberately insufficient.
        if len(evidence) < 3:
            continue

        stages: list[AttackStage] = []

        if login:
            stages.append(
                AttackStage(
                    stage="Initial Access / Credential Misuse",
                    technique="T1078",
                    confidence=0.86,
                    evidence=[EvidenceItem(event_id=login.event_id, reason="Unusual authentication from a previously unseen IP.")],
                    entities=sorted(_entity_keys(login)),
                    reason="The authentication differs from the user's observed baseline.",
                )
            )

        if file_access:
            stages.append(
                AttackStage(
                    stage="Sensitive Data Access",
                    technique="T1005",
                    confidence=0.90,
                    evidence=[EvidenceItem(event_id=file_access.event_id, reason="Sensitive resource accessed after anomalous authentication.")],
                    entities=sorted(_entity_keys(file_access)),
                    reason="The same user/device reached a marked sensitive resource.",
                )
            )

        if usb:
            stages.append(
                AttackStage(
                    stage="Removable Media Access",
                    technique="T1025",
                    confidence=0.91,
                    evidence=[EvidenceItem(event_id=usb.event_id, reason="Removable media was mounted during the suspicious session.")],
                    entities=sorted(_entity_keys(usb)),
                    reason="A removable device appeared within the correlated attack window.",
                )
            )

        if copy:
            stages.append(
                AttackStage(
                    stage="Collection / Exfiltration",
                    technique="T1025",
                    confidence=0.96,
                    evidence=[EvidenceItem(event_id=copy.event_id, reason="Large-volume file transfer to removable media.")],
                    entities=sorted(_entity_keys(copy)),
                    reason="The transfer volume and timing strongly support data exfiltration.",
                )
            )

        chain_completeness = len(stages) / 4
        corroboration = min(1.0, len(evidence) / 4)
        confidence = round(min(0.99, 0.45 + 0.35 * corroboration + 0.20 * chain_completeness), 2)
        risk = min(100, int(round(confidence * 100)))

        all_entities = sorted(set().union(*(_entity_keys(e) for e in chain)))
        first_seen = chain[0].timestamp
        last_seen = chain[-1].timestamp

        incidents.append(
            Incident(
                incident_id=f"INC-{key.upper()}-001",
                title="Suspected multi-stage data exfiltration",
                severity="critical" if confidence >= 0.90 else "high",
                confidence=confidence,
                risk_score=risk,
                status="validated",
                first_seen=first_seen,
                last_seen=last_seen,
                entities=all_entities,
                timeline=chain,
                stages=stages,
                evidence_count=len(evidence),
                recommended_actions=[
                    "Disable or step-up authenticate the affected account.",
                    "Isolate the correlated device from the network.",
                    "Preserve endpoint, file and removable-media telemetry.",
                    "Investigate the accessed sensitive resources and transfer destination.",
                ],
            )
        )

    return AnalysisResponse(
        total_events=len(ordered),
        suspicious_events=len(suspicious),
        correlated_incidents=len(incidents),
        incidents=incidents,
        suppressed=len(incidents) == 0,
    )
