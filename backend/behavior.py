from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from statistics import median
from typing import Iterable

from .models import SecurityEvent

MIN_BASELINE_EVENTS = 8
ANOMALY_THRESHOLD = 0.50


def _entity_key(event: SecurityEvent) -> str | None:
    if event.user:
        return f"user:{event.user}"
    if event.device:
        return f"device:{event.device}"
    return None


def _hour(event: SecurityEvent) -> int:
    return event.timestamp.hour


def _robust_score(value: float, samples: list[float]) -> float:
    if len(samples) < 3:
        return 0.0
    center = median(samples)
    deviations = [abs(x - center) for x in samples]
    mad = median(deviations)
    scale = max(1.4826 * mad, 1.0)
    z = abs(value - center) / scale
    return min(1.0, z / 4.0)


class BehaviorProfile:
    def __init__(
        self,
        entity: str,
        event_count: int,
        known_ips: set[str],
        known_devices: set[str],
        known_apps: set[str],
        event_types: Counter[str],
        hour_counts: Counter[int],
        daily_counts: list[float],
    ) -> None:
        self.entity = entity
        self.event_count = event_count
        self.known_ips = known_ips
        self.known_devices = known_devices
        self.known_apps = known_apps
        self.event_types = event_types
        self.hour_counts = hour_counts
        self.daily_counts = daily_counts

    @property
    def total_hours(self) -> int:
        return sum(self.hour_counts.values())

    @property
    def known_hours(self) -> set[int]:
        return set(self.hour_counts)

    def hour_probability(self, hour: int) -> float:
        return self.hour_counts.get(hour, 0) / max(1, self.total_hours)


class BehaviorSignal:
    def __init__(
        self,
        event_id: str,
        entity: str | None,
        score: float,
        reasons: list[str],
        anomalous: bool,
    ) -> None:
        self.event_id = event_id
        self.entity = entity
        self.score = round(min(1.0, max(0.0, score)), 2)
        self.reasons = reasons
        self.anomalous = anomalous

    def as_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "entity": self.entity,
            "score": self.score,
            "reasons": self.reasons,
            "anomalous": self.anomalous,
        }


def build_profiles(events: Iterable[SecurityEvent]) -> dict[str, BehaviorProfile]:
    grouped: dict[str, list[SecurityEvent]] = defaultdict(list)
    for event in events:
        key = _entity_key(event)
        if key:
            grouped[key].append(event)

    profiles: dict[str, BehaviorProfile] = {}
    for entity, entity_events in grouped.items():
        day_counter: Counter[str] = Counter()
        known_ips = {e.src_ip for e in entity_events if e.src_ip}
        known_devices = {e.device for e in entity_events if e.device}
        known_apps = {e.application for e in entity_events if e.application}
        event_types = Counter(e.event_type for e in entity_events)
        hour_counts = Counter(_hour(e) for e in entity_events)

        for event in entity_events:
            day_counter[event.timestamp.date().isoformat()] += 1

        profiles[entity] = BehaviorProfile(
            entity=entity,
            event_count=len(entity_events),
            known_ips=known_ips,
            known_devices=known_devices,
            known_apps=known_apps,
            event_types=event_types,
            hour_counts=hour_counts,
            daily_counts=list(day_counter.values()),
        )

    return profiles


def score_event(
    event: SecurityEvent,
    profile: BehaviorProfile | None,
    current_entity_daily_count: int | None = None,
) -> BehaviorSignal:
    entity = _entity_key(event)
    if profile is None or profile.event_count < MIN_BASELINE_EVENTS:
        return BehaviorSignal(
            event.event_id,
            entity,
            0.0,
            ["Insufficient historical baseline; behavior score withheld."],
            False,
        )

    score = 0.0
    reasons: list[str] = []

    if event.src_ip and profile.known_ips and event.src_ip not in profile.known_ips:
        score += 0.45
        reasons.append("Source IP is new for this entity's historical baseline.")

    if event.device and profile.known_devices and event.device not in profile.known_devices:
        score += 0.30
        reasons.append("Device is new for this entity's historical baseline.")

    hour_probability = profile.hour_probability(_hour(event))
    if profile.event_count >= MIN_BASELINE_EVENTS and hour_probability <= 0.05:
        score += 0.15
        reasons.append("Event occurred in a rarely observed activity hour.")

    if event.event_type not in profile.event_types:
        score += 0.15
        reasons.append("Event type is new for this entity's historical behavior.")

    if current_entity_daily_count is not None and len(profile.daily_counts) >= 3:
        burst_score = _robust_score(float(current_entity_daily_count), profile.daily_counts)
        if burst_score >= 0.50:
            score += 0.20 * burst_score
            reasons.append("Current-day activity volume deviates from the historical baseline.")

    if not reasons:
        reasons.append("Event is consistent with the learned entity baseline.")

    return BehaviorSignal(
        event.event_id,
        entity,
        score,
        reasons,
        score >= ANOMALY_THRESHOLD,
    )


def enrich_events(
    historical: Iterable[SecurityEvent],
    current: Iterable[SecurityEvent],
) -> tuple[list[SecurityEvent], list[BehaviorSignal]]:
    historical_events = list(historical)
    current_events = sorted(list(current), key=lambda e: e.timestamp)
    profiles = build_profiles(historical_events)

    current_daily_counts: Counter[tuple[str, str]] = Counter()
    for event in current_events:
        entity = _entity_key(event)
        if entity:
            current_daily_counts[(entity, event.timestamp.date().isoformat())] += 1

    enriched: list[SecurityEvent] = []
    signals: list[BehaviorSignal] = []

    for event in current_events:
        entity = _entity_key(event)
        day_key = (entity, event.timestamp.date().isoformat()) if entity else None
        signal = score_event(
            event,
            profiles.get(entity) if entity else None,
            current_daily_counts.get(day_key) if day_key else None,
        )
        metadata = dict(event.metadata)
        metadata["behavior_score"] = signal.score
        metadata["behavior_anomalous"] = signal.anomalous
        metadata["behavior_reasons"] = signal.reasons

        if (
            event.event_type == "login"
            and event.src_ip
            and entity
            and profiles.get(entity)
            and event.src_ip not in profiles[entity].known_ips
        ):
            metadata["unusual_ip"] = True

        if (
            event.device
            and entity
            and profiles.get(entity)
            and event.device not in profiles[entity].known_devices
        ):
            metadata["new_device"] = True

        enriched.append(event.model_copy(update={"metadata": metadata}))
        signals.append(signal)

    return enriched, signals
