from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Iterable

import yaml

from .attack_intel import enrich_technique, validate_emitted_techniques
from .enrichment import enrich_events
from .reconstructor import reconstruct
from .models import (
    AnalysisResponse,
    AttackStage,
    EvidenceItem,
    GraphEdge,
    GraphNode,
    Incident,
    SecurityEvent,
)

CHAIN_WINDOW = timedelta(minutes=30)
CANDIDATE_THRESHOLD = 0.10
STRONG_SIGNAL_THRESHOLD = 0.25
REQUIRED_STAGES = ("identity", "sensitive_access", "exfiltration")
RULES_PATH = Path(__file__).resolve().parent.parent / "config" / "rules.yml"

DEFAULT_STAGE_CONFIG = {
    "identity": {"name": "Initial Access / Identity Anomaly", "technique": "T1078", "confidence": {"with_login_and_device": 0.88, "without_device": 0.76}, "reason": stage_defs["identity"]["reason"], "evidence_reasons": {"login": "Authentication from an unusual IP.", "device": "Previously unseen device associated with the session."}},
    "sensitive_access": {"name": "Sensitive Data Access", "technique": "T1005", "confidence": 0.90, "reason": stage_defs["sensitive_access"]["reason"], "evidence_reason": "Sensitive resource accessed after the identity anomaly."},
    "exfiltration": {"name": "Collection / Exfiltration", "technique": "T1052.001", "confidence": {"with_usb_and_copy": 0.96, "with_copy": 0.82, "usb_only": 0.60}, "reason": stage_defs["exfiltration"]["reason"], "evidence_reasons": {"usb": "Removable media was mounted during the correlated session.", "copy": "Large-volume transfer occurred during the correlated session."}},
}
DEFAULT_INCIDENT_TEMPLATE = {"title": "Suspected multi-stage data exfiltration", "recommended_actions": ["Disable or step-up authenticate the affected account.", "Isolate the correlated device from the network.", "Preserve endpoint, file and removable-media telemetry.", "Investigate the accessed sensitive resources and transfer destination."]}

def _load_detector_config(config: Any = None) -> dict[str, Any]:
    if config is None:
        with RULES_PATH.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle) or {}
    if isinstance(config, dict):
        return config
    with Path(config).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}

def _stage_config(config: dict[str, Any], key: str) -> dict[str, Any]:
    merged = dict(DEFAULT_STAGE_CONFIG[key])
    merged.update(config.get("stages", {}).get(key, {}))
    return merged

def _incident_template(config: dict[str, Any]) -> dict[str, Any]:
    merged = dict(DEFAULT_INCIDENT_TEMPLATE)
    merged.update(config.get("templates", {}).get("incident", {}))
    return merged


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


def _identity_compatible(a: SecurityEvent, b: SecurityEvent) -> bool:
    if a.user and b.user and a.user != b.user:
        return False
    if a.device and b.device and a.device != b.device:
        return False

    a_identity = {x for x in (a.user, a.device, a.src_ip) if x}
    b_identity = {x for x in (b.user, b.device, b.src_ip) if x}
    return bool(a_identity & b_identity)


def _event_score(event: SecurityEvent) -> float:
    score = 0.0

    if event.event_type == "login" and event.metadata.get("unusual_ip"):
        score += 0.45
    if event.metadata.get("new_device"):
        score += 0.20
    if event.event_type == "file_access" and event.metadata.get("sensitive"):
        score += 0.35
    if event.event_type == "usb_mount" and event.metadata.get("removable", True):
        score += 0.12
    if event.event_type == "file_copy":
        copied_bytes = int(event.metadata.get("bytes", 0) or 0)
        if copied_bytes >= 1_000_000_000:
            score += 0.50
        elif copied_bytes >= 250_000_000:
            score += 0.20

    # Behavior anomaly is supporting context, not campaign confidence.
    # The maximum contribution is deliberately small so a single unusual
    # event cannot become a validated incident by itself.
    behavior_score = float(event.metadata.get("behavior_score", 0.0) or 0.0)
    score += min(0.15, 0.15 * max(0.0, behavior_score))

    # Severity is context, not the detector.
    score += {"critical": 0.05, "high": 0.04, "medium": 0.02}.get(event.severity, 0.0)
    return min(1.0, score)


def _cluster(events: list[SecurityEvent]) -> list[list[SecurityEvent]]:
    events = sorted(events, key=lambda e: e.timestamp)
    clusters: list[list[SecurityEvent]] = []

    for event in events:
        placed = False
        for cluster in clusters:
            if event.timestamp - cluster[0].timestamp > CHAIN_WINDOW:
                continue
            if any(
                event.timestamp >= existing.timestamp
                and _identity_compatible(event, existing)
                for existing in cluster
            ):
                cluster.append(event)
                placed = True
                break

        if not placed:
            clusters.append([event])

    return [sorted(cluster, key=lambda e: e.timestamp) for cluster in clusters]


def _find(cluster: list[SecurityEvent], predicate: Callable[[SecurityEvent], bool]) -> SecurityEvent | None:
    return next((e for e in cluster if predicate(e)), None)


def _is_removable_exfil(event: SecurityEvent) -> bool:
    if event.event_type != "file_copy":
        return False
    copied_bytes = int(event.metadata.get("bytes", 0) or 0)
    if copied_bytes < 1_000_000_000:
        return False

    destination = str(event.metadata.get("destination", "")).lower()
    action = str(event.action or "").lower()
    return (
        "usb" in destination
        or "removable" in destination
        or "usb" in action
        or "removable" in action
        or bool(event.metadata.get("removable_destination"))
    )


def _context_is_authorized(event: SecurityEvent) -> bool:
    return bool(
        event.metadata.get("approved_transfer")
        or event.metadata.get("authorized_activity")
        or event.metadata.get("sanctioned_usb")
    )


def _stage(
    name: str,
    technique: str | None,
    confidence: float,
    evidence: list[EvidenceItem],
    entities: set[str],
    reason: str,
) -> AttackStage:
    return AttackStage(
        stage=name,
        technique=technique,
        confidence=round(confidence, 2),
        evidence=evidence,
        entities=sorted(entities),
        reason=reason,
    )


def _build_graph(event_chain: list[SecurityEvent]) -> tuple[list[GraphNode], list[GraphEdge]]:
    nodes: dict[str, GraphNode] = {}
    edges: dict[tuple[str, str, str], GraphEdge] = {}

    labels = {
        "user": "User",
        "device": "Device",
        "ip": "IP",
        "app": "Application",
        "resource": "Resource",
    }

    for event in event_chain:
        parts = [
            ("user", f"user:{event.user}") if event.user else None,
            ("device", f"device:{event.device}") if event.device else None,
            ("ip", f"ip:{event.src_ip}") if event.src_ip else None,
            ("app", f"app:{event.application}") if event.application else None,
            ("resource", f"resource:{event.resource}") if event.resource else None,
        ]
        entity_chain = [part for part in parts if part]

        for node_type, node_id in entity_chain:
            nodes[node_id] = GraphNode(
                id=node_id,
                label=node_id.split(":", 1)[1],
                type=labels[node_type],
            )

        for (_, source), (_, target) in zip(entity_chain, entity_chain[1:]):
            relation = event.action or event.event_type.replace("_", " ")
            edges[(source, target, relation)] = GraphEdge(
                source=source,
                target=target,
                relation=relation,
                event_id=event.event_id,
            )

    return list(nodes.values()), list(edges.values())


def _entity_consistency(events: list[SecurityEvent]) -> float:
    if len(events) < 2:
        return 0.0

    scores = []
    for a, b in zip(events, events[1:]):
        if not _identity_compatible(a, b):
            scores.append(0.0)
            continue

        a_identity = {x for x in (a.user, a.device, a.src_ip) if x}
        b_identity = {x for x in (b.user, b.device, b.src_ip) if x}
        shared = len(a_identity & b_identity)
        scores.append(min(1.0, shared / 2))

    return round(sum(scores) / len(scores), 2)


def analyze(events: Iterable[SecurityEvent], config=None) -> AnalysisResponse:
    detector_config = _load_detector_config(config)
    enriched = enrich_events(list(events), config=config)
    ordered = sorted(enriched, key=lambda e: e.timestamp)
    scored = [(event, _event_score(event)) for event in ordered]

    # Weak context events participate in correlation, but don't inflate the
    # headline suspicious count unless they cross the stronger signal threshold.
    candidates = [event for event, score in scored if score >= CANDIDATE_THRESHOLD]
    suspicious = [event for event, score in scored if score >= STRONG_SIGNAL_THRESHOLD]

    if not candidates:
        return AnalysisResponse(
            total_events=len(ordered),
            suspicious_events=0,
            watchlist_candidates=0,
            suppressed_events=len(ordered),
            correlated_incidents=0,
            incidents=[],
            suppressed=True,
        )

    clusters = _cluster(candidates)
    incidents: list[Incident] = []
    incident_template = _incident_template(detector_config)
    stage_defs = {key: _stage_config(detector_config, key) for key in REQUIRED_STAGES}
    watchlist = 0
    evidence_events: set[str] = set()

    for cluster in clusters:
        login = _find(
            cluster,
            lambda e: e.event_type == "login" and bool(e.metadata.get("unusual_ip")),
        )
        new_device = _find(cluster, lambda e: e.event_type == "device_enroll" and bool(e.metadata.get("new_device")))
        if not new_device:
            new_device = _find(cluster, lambda e: e.event_type != "login" and bool(e.metadata.get("new_device")))
        sensitive = _find(
            cluster,
            lambda e: e.event_type == "file_access" and bool(e.metadata.get("sensitive")),
        )
        usb = _find(cluster, lambda e: e.event_type == "usb_mount")
        copy = _find(cluster, _is_removable_exfil)
        authorized_context = sum(1 for e in cluster if _context_is_authorized(e))

        stage_events: dict[str, list[SecurityEvent]] = {
            "identity": [e for e in (login, new_device) if e],
            "sensitive_access": [sensitive] if sensitive else [],
            "exfiltration": [e for e in (usb, copy) if e],
        }

        stages: list[AttackStage] = []

        if stage_events["identity"]:
            stage_evidence = stage_events["identity"]
            stages.append(
                _stage(
                    stage_defs["identity"]["name"],
                    stage_defs["identity"]["technique"],
                    stage_defs["identity"]["confidence"]["with_login_and_device"] if login and new_device else stage_defs["identity"]["confidence"]["without_device"],
                    [
                        EvidenceItem(
                            event_id=e.event_id,
                            reason=(
                                stage_defs["identity"]["evidence_reasons"]["login"]
                                if e.event_type == "login"
                                else stage_defs["identity"]["evidence_reasons"]["device"]
                            ),
                        )
                        for e in stage_evidence
                    ],
                    set().union(*(_entity_keys(e) for e in stage_evidence)),
                    "Authentication and device identity differ from the user's expected baseline.",
                )
            )

        if sensitive:
            stages.append(
                _stage(
                    stage_defs["sensitive_access"]["name"],
                    stage_defs["sensitive_access"]["technique"],
                    stage_defs["sensitive_access"]["confidence"],
                    [
                        EvidenceItem(
                            event_id=sensitive.event_id,
                            reason=stage_defs["sensitive_access"]["evidence_reason"],
                        )
                    ],
                    _entity_keys(sensitive),
                    "A sensitive resource was accessed by the same correlated identity/device.",
                )
            )

        if stage_events["exfiltration"]:
            exfil_events = stage_events["exfiltration"]
            has_copy = copy is not None
            stages.append(
                _stage(
                    stage_defs["exfiltration"]["name"],
                    stage_defs["exfiltration"]["technique"] if has_copy else None,
                    stage_defs["exfiltration"]["confidence"]["with_usb_and_copy"] if has_copy and usb else (stage_defs["exfiltration"]["confidence"]["with_copy"] if has_copy else stage_defs["exfiltration"]["confidence"]["usb_only"]),
                    [
                        EvidenceItem(
                            event_id=e.event_id,
                            reason=(
                                stage_defs["exfiltration"]["evidence_reasons"]["usb"]
                                if e.event_type == "usb_mount"
                                else stage_defs["exfiltration"]["evidence_reasons"]["copy"]
                            ),
                        )
                        for e in exfil_events
                    ],
                    set().union(*(_entity_keys(e) for e in exfil_events)),
                    "Removable-media presence and/or large-volume transfer provides collection/exfiltration evidence.",
                )
            )

        found = {stage.stage for stage in stages}
        missing = [stage_defs[key]["name"] for key in REQUIRED_STAGES if not stage_events[key]]

        if len(stages) < 3:
            if len(stages) >= 2:
                watchlist += 1
            continue

        chain = sorted(
            {
                event.event_id: event
                for events_for_stage in stage_events.values()
                for event in events_for_stage
            }.values(),
            key=lambda e: e.timestamp,
        )

        first_stage_times = [
            min((e.timestamp for e in stage_events[name]), default=None)
            for name in REQUIRED_STAGES
        ]
        temporal_ok = all(t is not None for t in first_stage_times) and first_stage_times == sorted(first_stage_times)
        temporal_score = 1.0 if temporal_ok else 0.35

        entity_score = _entity_consistency(chain)
        chain_completeness = round(len(stages) / len(REQUIRED_STAGES), 2)
        corroboration = min(1.0, len({e.event_id for e in chain}) / 5)

        confidence = round(
            min(
                0.99,
                0.35 * chain_completeness
                + 0.25 * corroboration
                + 0.20 * temporal_score
                + 0.20 * entity_score,
            ),
            2,
        )

        # Multiple explicit enterprise authorization signals can suppress a
        # superficially attack-like workflow. This is intentionally conservative:
        # one approval flag alone never suppresses an incident.
        if authorized_context >= 2 and bool(copy):
            # Explicitly sanctioned activity is a suppression, not a weaker alert.
            continue

        reconstruction = reconstruct(cluster)
        if (
            not temporal_ok
            or entity_score < 0.60
            or confidence < 0.78
            or not reconstruction.temporal_valid
            or not reconstruction.selected_event_ids
            or reconstruction.reconstruction_score < 0.65
        ):
            watchlist += 1
            continue

        evidence_events.update(e.event_id for e in chain)
        all_entities = sorted(set().union(*(_entity_keys(e) for e in chain)))
        graph_nodes, graph_edges = _build_graph(chain)

        attack_techniques = []
        initial_evidence = stage_events["identity"]
        if initial_evidence:
            mapped = enrich_technique(
                stage_defs["identity"]["technique"],
                initial_evidence,
                rationale=(
                    "The identity stage is linked to Valid Accounts because the "
                    "correlated authentication pattern is consistent with misuse of "
                    "an existing account; credential theft itself is not asserted."
                ),
                mapping_type="behavioral_inference",
                mapping_confidence=0.72,
            )
            if mapped:
                attack_techniques.append(mapped)

        if sensitive:
            mapped = enrich_technique(
                stage_defs["sensitive_access"]["technique"],
                [sensitive],
                rationale=(
                    "The chain contains sensitive local-resource access immediately "
                    "before the physical-medium transfer stage."
                ),
                mapping_type="stage_inference",
                mapping_confidence=0.84,
            )
            if mapped:
                attack_techniques.append(mapped)

        if copy:
            exfil_evidence = [event for event in (usb, copy) if event]
            mapped = enrich_technique(
                stage_defs["exfiltration"]["technique"],
                exfil_evidence,
                rationale=(
                    "The chain contains removable-media insertion plus a large copy "
                    "whose destination/action identifies the USB device."
                ),
                mapping_type="stage_inference",
                mapping_confidence=0.96,
            )
            if mapped:
                attack_techniques.append(mapped)

        validate_emitted_techniques(item.technique_id for item in attack_techniques)

        incidents.append(
            Incident(
                incident_id=f"INC-{key_for_incident(chain)}",
                title=incident_template["title"],
                severity="critical" if confidence >= 0.90 else "high",
                confidence=confidence,
                risk_score=min(100, int(round(confidence * 100))),
                status="validated",
                first_seen=chain[0].timestamp,
                last_seen=chain[-1].timestamp,
                entities=all_entities,
                timeline=chain,
                stages=stages,
                chain_completeness=chain_completeness,
                corroboration_score=round(corroboration, 2),
                temporal_score=round(temporal_score, 2),
                entity_consistency_score=round(entity_score, 2),
                missing_stages=missing,
                graph_nodes=graph_nodes,
                graph_edges=graph_edges,
                evidence_count=len(chain),
                attack_techniques=attack_techniques,
                reconstruction=reconstruction,
                recommended_actions=list(incident_template["recommended_actions"]),
            )
        )

    return AnalysisResponse(
        total_events=len(ordered),
        suspicious_events=len(suspicious),
        watchlist_candidates=watchlist,
        suppressed_events=max(0, len(candidates) - len(evidence_events)),
        correlated_incidents=len(incidents),
        incidents=incidents,
        suppressed=len(incidents) == 0,
    )


def key_for_incident(chain: list[SecurityEvent]) -> str:
    user = next((e.user for e in chain if e.user), None)
    device = next((e.device for e in chain if e.device), None)
    base = (user or device or "unknown").upper().replace(" ", "_")
    return f"{base}-001"
