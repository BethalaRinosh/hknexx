from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from .models import AttackReconstruction, ReconstructionEdge, SecurityEvent

CHAIN_WINDOW = timedelta(minutes=30)
DRIFT_RECONSTRUCTION_WINDOW = timedelta(minutes=90)

STAGE_IDENTITY = "Initial Access / Identity Anomaly"
STAGE_SENSITIVE = "Sensitive Data Access"
STAGE_EXFIL = "Collection / Exfiltration"
STAGES = (STAGE_IDENTITY, STAGE_SENSITIVE, STAGE_EXFIL)


@dataclass(frozen=True)
class Candidate:
    stage: str
    event: SecurityEvent
    stage_quality: float


def _identity_fields(event: SecurityEvent) -> dict[str, str]:
    return {
        key: value
        for key, value in (
            ("user", event.user),
            ("device", event.device),
            ("src_ip", event.src_ip),
            ("session", event.session_id),
        )
        if value
    }


def _compatible(a: SecurityEvent, b: SecurityEvent) -> bool:
    if a.user and b.user and a.user != b.user:
        return False
    if a.device and b.device and a.device != b.device:
        return False
    if a.session_id and b.session_id and a.session_id != b.session_id:
        return False
    return True


def _shared_identity_count(a: SecurityEvent, b: SecurityEvent) -> int:
    aa = _identity_fields(a)
    bb = _identity_fields(b)
    return sum(
        1
        for key in ("user", "device", "src_ip", "session")
        if aa.get(key) and aa.get(key) == bb.get(key)
    )


def _resource_continuity(a: SecurityEvent, b: SecurityEvent) -> bool:
    if a.resource and b.resource and a.resource == b.resource:
        return True

    destination = str(b.metadata.get("destination", "")).lower()
    action = str(b.action or "").lower()

    if a.resource and destination and a.resource.lower() in destination:
        return True

    if a.event_type == "usb_mount" and b.event_type == "file_copy":
        mounted = (a.resource or "").lower()
        return bool(mounted and mounted in destination) or "usb" in action or "removable" in action

    return False


def _behavior_support(a: SecurityEvent, b: SecurityEvent) -> float:
    values = []
    for event in (a, b):
        try:
            values.append(float(event.metadata.get("behavior_score", 0.0) or 0.0))
        except (TypeError, ValueError):
            values.append(0.0)
    return max(values)


def _strong_drift_link(a: SecurityEvent, b: SecurityEvent) -> bool:
    return bool(
        a.user
        and b.user
        and a.user == b.user
        and (
            (a.device and b.device and a.device == b.device)
            or (a.session_id and b.session_id and a.session_id == b.session_id)
        )
    )


def _edge_score(a: SecurityEvent, b: SecurityEvent) -> tuple[float, list[str]]:
    reasons: list[str] = []

    if b.timestamp < a.timestamp:
        return 0.0, ["Target event occurs before source event."]

    gap = b.timestamp - a.timestamp
    if gap > DRIFT_RECONSTRUCTION_WINDOW:
        return 0.0, ["Events exceed the 90-minute reconstruction window."]

    if not _compatible(a, b):
        return 0.0, ["User, device, or session contradiction blocks causal linkage."]

    resource_link = _resource_continuity(a, b)
    behavior_link = _behavior_support(a, b) >= 0.50

    if gap > CHAIN_WINDOW and not (
        _strong_drift_link(a, b) and (resource_link or behavior_link)
    ):
        return 0.0, [
            "Long temporal gap requires strong identity plus independent continuity evidence."
        ]

    score = 0.20
    reasons.append("Events are temporally ordered inside the reconstruction window.")

    if gap > CHAIN_WINDOW:
        reasons.append("Long-spacing transition is accepted only with strong identity continuity and corroboration.")

    shared = _shared_identity_count(a, b)
    if shared >= 1:
        score += 0.30
        reasons.append(f"Shared identity context: {shared} field(s).")
    if shared >= 2:
        score += 0.15
        reasons.append("Multiple identity fields corroborate continuity.")

    if a.application and b.application and a.application == b.application:
        score += 0.05
        reasons.append("Same application context.")

    if resource_link:
        score += 0.20
        reasons.append("Resource or removable-media continuity links the events.")

    if behavior_link:
        score += 0.10
        reasons.append("Behavior baseline independently supports the transition.")

    decay = max(
        0.0,
        1.0 - (gap.total_seconds() / DRIFT_RECONSTRUCTION_WINDOW.total_seconds()),
    )
    score += 0.10 * decay

    return round(min(1.0, score), 2), reasons


def _copy_is_removable(event: SecurityEvent) -> bool:
    if event.event_type != "file_copy":
        return False

    try:
        copied_bytes = int(event.metadata.get("bytes", 0) or 0)
    except (TypeError, ValueError):
        copied_bytes = 0

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


def _stage_candidates(events: list[SecurityEvent]) -> dict[str, list[Candidate]]:
    candidates: dict[str, list[Candidate]] = {stage: [] for stage in STAGES}

    for event in events:
        if event.event_type == "login" and event.metadata.get("unusual_ip"):
            quality = 0.90 + (0.10 if event.metadata.get("new_device") else 0.0)
            candidates[STAGE_IDENTITY].append(Candidate(STAGE_IDENTITY, event, quality))
        elif event.event_type == "device_enroll" and event.metadata.get("new_device"):
            candidates[STAGE_IDENTITY].append(Candidate(STAGE_IDENTITY, event, 0.82))
        elif event.event_type == "file_access" and event.metadata.get("sensitive"):
            candidates[STAGE_SENSITIVE].append(Candidate(STAGE_SENSITIVE, event, 0.92))
        elif event.event_type == "usb_mount" and event.metadata.get("removable", True):
            candidates[STAGE_EXFIL].append(Candidate(STAGE_EXFIL, event, 0.78))
        elif _copy_is_removable(event):
            candidates[STAGE_EXFIL].append(Candidate(STAGE_EXFIL, event, 1.0))

    return candidates


def _best_path(
    candidates: dict[str, list[Candidate]],
) -> tuple[list[Candidate], list[ReconstructionEdge], float]:
    best_path: list[Candidate] = []
    best_edges: list[ReconstructionEdge] = []
    best_score = 0.0

    for first in candidates[STAGE_IDENTITY]:
        for second in candidates[STAGE_SENSITIVE]:
            score12, reasons12 = _edge_score(first.event, second.event)
            if not score12:
                continue

            for third in candidates[STAGE_EXFIL]:
                score23, reasons23 = _edge_score(second.event, third.event)
                if not score23 or third.event.timestamp < second.event.timestamp:
                    continue

                stage_quality = (
                    first.stage_quality + second.stage_quality + third.stage_quality
                ) / 3.0
                path_score = round(
                    (score12 + score23) / 2.0 * 0.70 + stage_quality * 0.30,
                    2,
                )

                edges = [
                    ReconstructionEdge(
                        source_event_id=first.event.event_id,
                        target_event_id=second.event.event_id,
                        relation="identity-to-sensitive",
                        score=score12,
                        reasons=reasons12,
                    ),
                    ReconstructionEdge(
                        source_event_id=second.event.event_id,
                        target_event_id=third.event.event_id,
                        relation="sensitive-to-exfiltration",
                        score=score23,
                        reasons=reasons23,
                    ),
                ]

                if path_score > best_score:
                    best_score = path_score
                    best_path = [first, second, third]
                    best_edges = edges

    return best_path, best_edges, best_score


def reconstruct(events: list[SecurityEvent]) -> AttackReconstruction:
    ordered = sorted(events, key=lambda event: event.timestamp)
    candidates = _stage_candidates(ordered)
    selected, edges, score = _best_path(candidates)

    selected_ids = {item.event.event_id for item in selected}
    all_candidate_ids = {
        item.event.event_id
        for stage_candidates in candidates.values()
        for item in stage_candidates
    }
    decoys = sorted(all_candidate_ids - selected_ids)

    stage_event_ids = {
        stage: [item.event.event_id for item in selected if item.stage == stage]
        for stage in STAGES
    }

    temporal_valid = len(selected) == 3 and all(
        selected[index].event.timestamp <= selected[index + 1].event.timestamp
        for index in range(len(selected) - 1)
    )

    conflicts = sum(
        not _compatible(left.event, right.event)
        for left, right in zip(selected, selected[1:])
    )

    if not selected:
        explanation = (
            "No temporally ordered, entity-compatible path covers all required attack stages."
        )
    else:
        explanation = (
            "Selected the highest-scoring temporally ordered path covering all required stages. "
            "The reconstruction prefers entity continuity, resource continuity and behavioral "
            "corroboration, while retaining alternate stage candidates as decoys."
        )

    return AttackReconstruction(
        selected_event_ids=[item.event.event_id for item in selected],
        stage_event_ids=stage_event_ids,
        reconstruction_score=score,
        temporal_valid=temporal_valid,
        entity_conflicts=conflicts,
        decoy_event_ids=decoys,
        edges=edges,
        explanation=explanation,
    )
