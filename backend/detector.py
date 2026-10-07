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
    "identity": {
        "name": "Initial Access / Identity Anomaly",
        "technique": "T1078",
        "confidence": {"with_login_and_device": 0.88, "without_device": 0.76},
        "reason": "Authentication and device identity differ from the user's expected baseline.",
        "evidence_reasons": {
            "login": "Authentication from an unusual IP.",
            "device": "Previously unseen device associated with the session.",
        },
    },
    "sensitive_access": {
        "name": "Sensitive Data Access",
        "technique": "T1005",
        "confidence": 0.90,
        "reason": "A sensitive resource was accessed by the same correlated identity/device.",
        "evidence_reason": "Sensitive resource accessed after the identity anomaly.",
    },
    "exfiltration": {
        "name": "Collection / Exfiltration",
        "technique": "T1052.001",
        "confidence": {"with_usb_and_copy": 0.96, "with_copy": 0.82, "usb_only": 0.60},
        "reason": "Removable-media presence and/or large-volume transfer provides collection/exfiltration evidence.",
        "evidence_reasons": {
            "usb": "Removable media was mounted during the correlated session.",
            "copy": "Large-volume transfer occurred during the correlated session.",
        },
    },
}
