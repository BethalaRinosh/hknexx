from __future__ import annotations

import csv
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass(frozen=True)
class CERTRecord:
    case_id: str
    activity: str
    resource: str
    timestamp: datetime
    malicious: bool


@dataclass(frozen=True)
class CERTCaseResult:
    case_id: str
    malicious: bool
    stages_present: tuple[str, ...]
    ordered: bool
    chain_compatible: bool


@dataclass(frozen=True)
class CERTBenchmarkResult:
    total_events: int
    total_cases: int
    malicious_cases: int
    benign_cases: int
    compatible_malicious_cases: int
    detected_ordered_malicious_cases: int
    benign_ordered_chain_cases: int
    malicious_stage_recall: float
    benign_chain_rate: float
    status: str
    reason: str


LOGIN_STAGE = "Initial Access / Identity Anomaly"
FILE_STAGE = "Sensitive Data Access"
EXFIL_STAGE = "Collection / Exfiltration"


def _expand_hybrid_row(row: dict[str, str]) -> dict[str, str]:
    expanded = dict(row)
    for key, value in list(row.items()):
        if ";" not in key:
            continue
        left, right = [part.strip() for part in key.split(";", 1)]
        values = (value or "").split(";", 1)
        expanded.pop(key, None)
        expanded[left] = values[0].strip()
        if right:
            expanded[right] = values[1].strip() if len(values) > 1 else ""
    return expanded


def _pick(row: dict[str, str], aliases: tuple[str, ...]) -> str:
    lowered = {str(k).strip().lower(): (v or "") for k, v in row.items()}
    for alias in aliases:
        value = lowered.get(alias.lower(), "")
        if value.strip():
            return value.strip()
    return ""


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y", "malicious", "anomalous", "attack", "bad"}


def _parse_timestamp(value: str) -> datetime:
    text = value.strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%m/%d/%Y %H:%M:%S"):
            try:
                return datetime.strptime(value.strip(), fmt)
            except ValueError:
                continue
        raise


def _parse_row_timestamp(row: dict[str, str]) -> datetime | None:
    preferred = _pick(row, ("timestamp", "time", "datetime", "date", "event_time"))
    candidates = [preferred] + [value for value in row.values() if value and value != preferred]
    for candidate in candidates:
        try:
            return _parse_timestamp(candidate)
        except (TypeError, ValueError):
            continue
    return None


def _activity_kind(activity: str, resource: str) -> set[str]:
    text = f"{activity} {resource}".lower()
    kinds: set[str] = set()

    if re.search(r"\blogon\b|\blogin\b|\bauth", text):
        kinds.add(LOGIN_STAGE)

    if re.search(r"file|read|access|open|write", text):
        kinds.add(FILE_STAGE)

    if re.search(r"usb|removable|device|disconnect|connect", text):
        kinds.add(EXFIL_STAGE)

    if re.search(r"copy|transfer|removable|usb", text):
        kinds.add(EXFIL_STAGE)

    return kinds


def load_cert_records(path: Path) -> list[CERTRecord]:
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        raw_fieldnames = reader.fieldnames or []
        if not raw_fieldnames:
            raise ValueError("CERT benchmark CSV has no header")

        semantic_fields: set[str] = set()
        for field in raw_fieldnames:
            parts = [part.strip().lower() for part in field.split(";")]
            semantic_fields.update(part for part in parts if part)

        required_alias_groups = (
            ("case_id", "case", "caseid", "pc", "resource_id", "user"),
            ("activity", "event", "event_type", "action", "type"),
            ("timestamp", "time", "datetime", "date", "event_time"),
            ("label", "class", "target", "is_malicious", "malicious", "anomaly", "cattivi"),
        )
        for group in required_alias_groups:
            if not any(alias.lower() in semantic_fields for alias in group):
                raise ValueError(
                    f"CERT benchmark CSV missing required semantic column group: {group}"
                )

        records: list[CERTRecord] = []
        for raw_row in reader:
            row = _expand_hybrid_row(raw_row)
            case_id = _pick(row, ("case_id", "case", "caseid", "pc", "resource_id", "user"))
            activity = _pick(row, ("activity", "event", "event_type", "action", "type"))
            resource = _pick(row, ("resource", "filename", "file", "pc", "user"))
            parsed_timestamp = _parse_row_timestamp(row)
            label = _pick(row, ("label", "class", "target", "is_malicious", "malicious", "anomaly", "cattivi"))

            if not case_id or not activity or parsed_timestamp is None:
                continue

            records.append(
                CERTRecord(
                    case_id=case_id,
                    activity=activity,
                    resource=resource,
                    timestamp=parsed_timestamp,
                    malicious=_parse_bool(label),
                )
            )

    return records


def _case_result(case_id: str, records: list[CERTRecord]) -> CERTCaseResult:
    ordered_records = sorted(records, key=lambda item: item.timestamp)
    stage_hits = [
        _activity_kind(item.activity, item.resource)
        for item in ordered_records
    ]
    present = set().union(*stage_hits) if stage_hits else set()

    positions: dict[str, int] = {}
    for index, kinds in enumerate(stage_hits):
        for stage in kinds:
            positions.setdefault(stage, index)

    complete = all(stage in present for stage in (LOGIN_STAGE, FILE_STAGE, EXFIL_STAGE))
    ordered = (
        complete
        and positions[LOGIN_STAGE] < positions[FILE_STAGE] < positions[EXFIL_STAGE]
    )

    return CERTCaseResult(
        case_id=case_id,
        malicious=any(item.malicious for item in records),
        stages_present=tuple(sorted(present)),
        ordered=ordered,
        chain_compatible=complete,
    )


def evaluate_cert(path: Path) -> CERTBenchmarkResult:
    records = load_cert_records(path)
    if not records:
        return CERTBenchmarkResult(0, 0, 0, 0, 0, 0, 0, 0.0, 0.0, "failed", "No usable CERT event records found.")

    grouped: dict[str, list[CERTRecord]] = {}
    for record in records:
        grouped.setdefault(record.case_id, []).append(record)

    cases = [_case_result(case_id, items) for case_id, items in grouped.items()]
    malicious = [case for case in cases if case.malicious]
    benign = [case for case in cases if not case.malicious]
    compatible = [case for case in malicious if case.chain_compatible]
    ordered_malicious = [case for case in compatible if case.ordered]
    benign_ordered = [case for case in benign if case.ordered]

    return CERTBenchmarkResult(
        total_events=len(records),
        total_cases=len(cases),
        malicious_cases=len(malicious),
        benign_cases=len(benign),
        compatible_malicious_cases=len(compatible),
        detected_ordered_malicious_cases=len(ordered_malicious),
        benign_ordered_chain_cases=len(benign_ordered),
        malicious_stage_recall=round(len(ordered_malicious) / len(compatible), 4) if compatible else 0.0,
        benign_chain_rate=round(len(benign_ordered) / len(benign), 4) if benign else 0.0,
        status="validated",
        reason=(
            "CERT-derived labeled event traces were evaluated against the existing "
            "three-stage evidence contract. This metric is a public-data compatibility "
            "benchmark; it does not substitute for raw-source end-to-end detector recall."
        ),
    )
