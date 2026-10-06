from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class SecurityEvent(BaseModel):
    event_id: str
    timestamp: datetime
    event_type: str
    user: str | None = None
    device: str | None = None
    src_ip: str | None = None
    application: str | None = None
    resource: str | None = None
    action: str | None = None
    source: str
    severity: str = "info"
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceItem(BaseModel):
    event_id: str
    reason: str


class AttackStage(BaseModel):
    stage: str
    technique: str | None = None
    confidence: float
    evidence: list[EvidenceItem]
    entities: list[str]
    reason: str


class Incident(BaseModel):
    incident_id: str
    title: str
    severity: str
    confidence: float
    risk_score: int
    status: str
    first_seen: datetime
    last_seen: datetime
    entities: list[str]
    timeline: list[SecurityEvent]
    stages: list[AttackStage]
    evidence_count: int
    recommended_actions: list[str]


class AnalysisResponse(BaseModel):
    total_events: int
    suspicious_events: int
    correlated_incidents: int
    incidents: list[Incident]
    suppressed: bool
