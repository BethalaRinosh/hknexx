from __future__ import annotations

import csv
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator
from zipfile import ZipFile

from .normalizer import normalize_events
from .models import SecurityEvent


@dataclass(frozen=True)
class PublicDatasetSpec:
    dataset_id: str
    name: str
    source_url: str
    local_path_env: str
    format: str
    description: str
    evaluation_mode: str
    expected_techniques: tuple[str, ...] = ()


@dataclass(frozen=True)
class PublicEvaluationResult:
    dataset_id: str
    available: bool
    source_path: str | None
    total_records: int
    normalized_events: int
    parse_errors: int
    normalization_errors: int
    event_type_counts: dict[str, int]
    source_counts: dict[str, int]
    observed_techniques: list[str]
    status: str
    reason: str


class PublicDatasetError(RuntimeError):
    pass


def load_manifest(path: Path) -> list[PublicDatasetSpec]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return [
        PublicDatasetSpec(
            dataset_id=item["dataset_id"],
            name=item["name"],
            source_url=item["source_url"],
            local_path_env=item["local_path_env"],
            format=item["format"],
            description=item["description"],
            evaluation_mode=item["evaluation_mode"],
            expected_techniques=tuple(item.get("expected_techniques", [])),
        )
        for item in raw["datasets"]
    ]


def _iter_text_file(path: Path) -> Iterator[str]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if line.strip():
                yield line


def _iter_json_lines(lines: Iterator[str]) -> Iterator[dict[str, Any]]:
    for line in lines:
        value = json.loads(line)
        if isinstance(value, dict):
            yield value


def _iter_csv(lines: Iterator[str]) -> Iterator[dict[str, Any]]:
    reader = csv.DictReader(lines)
    for row in reader:
        yield dict(row)


def _iter_json_array(path: Path) -> Iterator[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    if not isinstance(raw, list):
        raise PublicDatasetError("JSON dataset must contain an array")
    for item in raw:
        if isinstance(item, dict):
            yield item


def _iter_path(path: Path, fmt: str) -> Iterator[dict[str, Any]]:
    if path.suffix.lower() == ".zip":
        with ZipFile(path) as archive:
            members = [
                name for name in archive.namelist()
                if not name.endswith("/")
                and (name.lower().endswith(".jsonl")
                     or name.lower().endswith(".json")
                     or name.lower().endswith(".csv"))
            ]
            if not members:
                raise PublicDatasetError("ZIP contains no supported JSON/JSONL/CSV payload")
            for member in members:
                extracted = archive.read(member).decode("utf-8", errors="replace")
                if member.lower().endswith(".jsonl"):
                    yield from _iter_json_lines(iter(extracted.splitlines()))
                elif member.lower().endswith(".csv"):
                    yield from _iter_csv(iter(extracted.splitlines()))
                else:
                    value = json.loads(extracted)
                    if isinstance(value, list):
                        yield from (item for item in value if isinstance(item, dict))
                    elif isinstance(value, dict):
                        yield value
            return

    if fmt == "jsonl":
        yield from _iter_json_lines(_iter_text_file(path))
    elif fmt == "csv":
        yield from _iter_csv(_iter_text_file(path))
    elif fmt == "json":
        yield from _iter_json_array(path)
    else:
        raise PublicDatasetError(f"Unsupported dataset format: {fmt}")


def _observed_techniques(raw: dict[str, Any]) -> list[str]:
    values = []
    for key in ("mitre_technique", "technique", "techniques", "attack_technique"):
        value = raw.get(key)
        if isinstance(value, str):
            values.append(value)
        elif isinstance(value, list):
            values.extend(str(item) for item in value)

    normalized = []
    for value in values:
        value = value.strip()
        if value:
            normalized.append(value.upper())
    return sorted(set(normalized))


def evaluate_public_dataset(spec: PublicDatasetSpec) -> PublicEvaluationResult:
    configured = os.getenv(spec.local_path_env, "").strip()
    if not configured:
        return PublicEvaluationResult(
            dataset_id=spec.dataset_id,
            available=False,
            source_path=None,
            total_records=0,
            normalized_events=0,
            parse_errors=0,
            normalization_errors=0,
            event_type_counts={},
            source_counts={},
            observed_techniques=[],
            status="not_available",
            reason=(
                f"Public dataset is not mounted. Set {spec.local_path_env} to the "
                f"downloaded public artifact. No synthetic fallback is used."
            ),
        )

    path = Path(configured)
    if not path.exists():
        return PublicEvaluationResult(
            dataset_id=spec.dataset_id,
            available=False,
            source_path=str(path),
            total_records=0,
            normalized_events=0,
            parse_errors=0,
            normalization_errors=0,
            event_type_counts={},
            source_counts={},
            observed_techniques=[],
            status="not_available",
            reason=f"Configured public dataset path does not exist: {path}",
        )

    total = 0
    parse_errors = 0
    normalization_errors = 0
    normalized: list[SecurityEvent] = []
    techniques: set[str] = set()

    try:
        iterator = _iter_path(path, spec.format)
        for raw in iterator:
            total += 1
            techniques.update(_observed_techniques(raw))
            try:
                normalized.extend(normalize_events([raw]))
            except Exception:
                normalization_errors += 1
    except Exception:
        parse_errors += 1

    event_type_counts: dict[str, int] = {}
    source_counts: dict[str, int] = {}
    for event in normalized:
        event_type_counts[event.event_type] = event_type_counts.get(event.event_type, 0) + 1
        source_counts[event.source] = source_counts.get(event.source, 0) + 1

    if parse_errors:
        status = "failed"
        reason = "Dataset parsing failed before the full stream could be evaluated."
    elif total == 0:
        status = "failed"
        reason = "Dataset was present but contained no supported records."
    elif not normalized:
        status = "failed"
        reason = "Dataset records were present but none normalized into SecurityEvent."
    else:
        status = "validated"
        reason = (
            "Public records were ingested and normalized. Detection metrics are only "
            "considered complete when an attack-window/ground-truth manifest is available."
        )

    return PublicEvaluationResult(
        dataset_id=spec.dataset_id,
        available=True,
        source_path=str(path),
        total_records=total,
        normalized_events=len(normalized),
        parse_errors=parse_errors,
        normalization_errors=normalization_errors,
        event_type_counts=event_type_counts,
        source_counts=source_counts,
        observed_techniques=sorted(techniques),
        status=status,
        reason=reason,
    )
