from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .models import AttackTechnique, SecurityEvent

ROOT = Path(__file__).resolve().parent
CATALOG_PATH = ROOT / "data" / "attack_intelligence.json"


def load_catalog() -> dict[str, dict]:
    with CATALOG_PATH.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return {item["technique_id"]: item for item in payload["techniques"]}


def enrich_technique(
    technique_id: str,
    evidence: Iterable[SecurityEvent],
    *,
    rationale: str | None = None,
    mapping_type: str | None = None,
    mapping_confidence: float | None = None,
) -> AttackTechnique | None:
    catalog = load_catalog()
    item = catalog.get(technique_id)
    if not item:
        return None

    evidence_ids = [event.event_id for event in evidence]
    return AttackTechnique(
        technique_id=item["technique_id"],
        name=item["name"],
        tactic=item["tactic"],
        description=item["description"],
        attack_version=item["attack_version"],
        technique_version=item["technique_version"],
        detection_strategy_id=item.get("detection_strategy_id"),
        detection_strategy_name=item.get("detection_strategy_name"),
        analytics=item.get("analytics", []),
        log_sources=item.get("log_sources", []),
        evidence_event_ids=evidence_ids,
        rationale=rationale or item["rationale"],
        mapping_type=mapping_type or item["mapping_type"],
        mapping_confidence=(
            item["mapping_confidence"]
            if mapping_confidence is None
            else mapping_confidence
        ),
    )


def validate_emitted_techniques(technique_ids: Iterable[str]) -> None:
    catalog = load_catalog()
    missing = sorted(set(technique_ids) - set(catalog))
    if missing:
        raise ValueError(f"Unknown ATT&CK technique IDs: {', '.join(missing)}")
