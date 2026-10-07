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
    dst_ip: str | None = None
    application: str | None = None
    process: str | None = None
    pid: int | None = None
    parent_process: str | None = None
    session_id: str | None = None
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


class ReconstructionEdge(BaseModel):
    source_event_id: str
    target_event_id: str
    relation: str
    score: float
    reasons: list[str]


class AttackReconstruction(BaseModel):
    selected_event_ids: list[str]
    stage_event_ids: dict[str, list[str]]
    reconstruction_score: float
    temporal_valid: bool
    entity_conflicts: int
    decoy_event_ids: list[str]
    edges: list[ReconstructionEdge]
    explanation: str


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
    attack_techniques: list[AttackTechnique] = Field(default_factory=list)
    reconstruction: AttackReconstruction | None = None


Disposition = Literal["validated", "watchlist", "suppressed"]


class EvaluationCase(BaseModel):
    scenario: str
    expected: Disposition
    actual: Disposition
    passed: bool
    incidents: int
    watchlist_candidates: int
    suspicious_events: int
    reason: str



class AdversarialCase(BaseModel):
    scenario: str
    ground_truth: Literal["malicious", "benign"]
    expected: Disposition
    actual: Disposition
    passed: bool
    incidents: int
    watchlist_candidates: int
    reason: str


class AdversarialReport(BaseModel):
    total_cases: int
    passed_cases: int
    failed_cases: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    false_negative_rate: float
    cases: list[AdversarialCase]


class Phase2Report(BaseModel):
    total_cases: int
    passed_cases: int
    failed_cases: int
    accuracy: float
    validated_cases: int
    false_positive_cases: int
    missed_attack_cases: int
    watchlist_cases: int
    cases: list[EvaluationCase]


class AnalysisResponse(BaseModel):
    total_events: int
    suspicious_events: int
    watchlist_candidates: int
    suppressed_events: int
    correlated_incidents: int
    incidents: list[Incident]
    suppressed: bool


class BehaviorSignalResponse(BaseModel):
    event_id: str
    entity: str | None = None
    score: float
    reasons: list[str]
    anomalous: bool


class BehaviorAnalysisResponse(BaseModel):
    total_events: int
    baseline_entities: int
    anomalous_events: int
    signals: list[BehaviorSignalResponse]
    analysis: AnalysisResponse


class AttackTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    description: str
    attack_version: str
    technique_version: str
    detection_strategy_id: str | None = None
    detection_strategy_name: str | None = None
    analytics: list[str] = Field(default_factory=list)
    log_sources: list[str] = Field(default_factory=list)
    evidence_event_ids: list[str]
    rationale: str
    mapping_type: Literal["stage_inference", "behavioral_inference"] = "stage_inference"
    mapping_confidence: float


class InvestigationClaim(BaseModel):
    claim: str
    claim_type: Literal["fact", "inference", "uncertainty", "recommendation"]
    evidence_event_ids: list[str] = Field(default_factory=list)
    confidence: float


class InvestigationReport(BaseModel):
    incident_id: str
    provider: str
    model: str
    grounded: bool
    summary: str
    claims: list[InvestigationClaim]
    unanswered_questions: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)


class InvestigationRequest(BaseModel):
    events: list[SecurityEvent]
    incident_id: str | None = None
    question: str | None = None
