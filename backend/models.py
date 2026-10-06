from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

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


class GraphNode(BaseModel):
    id: str
    label: str
    type: str


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str
    event_id: str


class Incident(BaseModel):
    incident_id: str
    title: str
    severity: str
    confidence: float
    risk_score: int
    status: Literal["validated"] = "validated"
    first_seen: datetime
    last_seen: datetime
    entities: list[str]
    timeline: list[SecurityEvent]
    stages: list[AttackStage]
    chain_completeness: float
    corroboration_score: float
    temporal_score: float
    entity_consistency_score: float
    missing_stages: list[str]
    graph_nodes: list[GraphNode]
    graph_edges: list[GraphEdge]
    evidence_count: int
    recommended_actions: list[str]


class AnalysisResponse(BaseModel):
    total_events: int
    suspicious_events: int
    watchlist_candidates: int
    suppressed_events: int
    correlated_incidents: int
    incidents: list[Incident]
    suppressed: bool
