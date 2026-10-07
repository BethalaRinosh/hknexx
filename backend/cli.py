from __future__ import annotations

import argparse
import csv
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable

import yaml

from .adapters import (
    normalize_sysmon_event,
    normalize_windows_event,
    normalize_windows_event_xml,
    normalize_zeek_event,
)
from .detector import analyze
from .enrichment import enrich_events
from .models import SecurityEvent
from .normalizer import ALIASES, normalize_events


class PipelineInputError(ValueError):
    pass


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PipelineInputError(f"invalid JSON in {path}: {exc}") from exc


def _records_from_json(path: Path) -> list[dict[str, Any]]:
    payload = _read_json(path)
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    raise PipelineInputError("JSON input must contain an object or a list of objects")


def _records_from_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise PipelineInputError(f"invalid JSONL at line {line_no}: {exc}") from exc
        if not isinstance(value, dict):
            raise PipelineInputError(f"JSONL line {line_no} must contain an object")
        records.append(value)
    return records


def _records_from_csv(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def _schema_map(records: list[dict[str, Any]], schema_path: str | Path | None) -> list[dict[str, Any]]:
    if not schema_path:
        return records
    payload = yaml.safe_load(Path(schema_path).read_text(encoding="utf-8")) or {}
    mapping = payload.get("fields", {})
    if not isinstance(mapping, dict):
        raise PipelineInputError("schema must contain a 'fields' mapping")

    mapped: list[dict[str, Any]] = []
    for record in records:
        output = dict(record)
        for canonical, source in mapping.items():
            if source in record:
                output[canonical] = record[source]
        mapped.append(output)
    return mapped


def _missing_required_fields(records: list[dict[str, Any]]) -> list[str]:
    if not records:
        return ["timestamp", "event_type"]
    columns = set(records[0])
    missing: list[str] = []
    for field in ("timestamp", "event_type"):
        if not any(alias in columns for alias in ALIASES[field]):
            missing.append(field)
    return missing


def _format_error(records: list[dict[str, Any]], missing: list[str]) -> PipelineInputError:
    columns = sorted({key for record in records for key in record})
    expected = sorted({"timestamp", "event_type", "user", "device", "src_ip", "resource", "action"})
    return PipelineInputError(
        "unrecognized input schema. "
        f"Columns found: {columns or ['<none>']}. "
        f"Expected canonical fields or aliases: {expected}"
    )


def detect_format(path: Path, payload: Any | None = None) -> str:
    suffix = path.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        return "jsonl"
    if suffix == ".csv":
        return "csv"
    if suffix == ".xml":
        return "windows"
    if payload is None and suffix == ".json":
        payload = _read_json(path)

    sample = payload[0] if isinstance(payload, list) and payload else payload
    if isinstance(sample, dict):
        keys = set(sample)
        if {"System", "EventData"} & keys:
            return "windows"
        if {"EventID", "UtcTime", "RuleName"} & keys:
            return "sysmon"
        if {"uid", "id.orig_h", "id.resp_h"} & keys:
            return "zeek"
    return "json"


def parse_file(
    path: str | Path,
    format_name: str = "auto",
    schema: str | Path | None = None,
) -> list[SecurityEvent]:
    source = Path(path)
    if not source.exists():
        raise PipelineInputError(f"input file does not exist: {source}")

    if format_name == "auto":
        format_name = detect_format(source)

    if format_name == "json":
        records = _records_from_json(source)
        records = _schema_map(records, schema)
        missing = _missing_required_fields(records)
        if missing:
            raise _format_error(records, missing)
        return normalize_events(records)

    if format_name == "jsonl":
        records = _records_from_jsonl(source)
        records = _schema_map(records, schema)
        missing = _missing_required_fields(records)
        if missing:
            raise _format_error(records, missing)
        return normalize_events(records)

    if format_name == "csv":
        records = _records_from_csv(source)
        records = _schema_map(records, schema)
        missing = _missing_required_fields(records)
        if missing:
            raise _format_error(records, missing)
        return normalize_events(records)

    if format_name == "windows":
        text = source.read_text(encoding="utf-8")
        if text.lstrip().startswith("<"):
            try:
                return [normalize_windows_event_xml(text)]
            except ET.ParseError as exc:
                raise PipelineInputError(f"invalid Windows XML in {source}: {exc}") from exc
        records = _records_from_json(source)
        return [normalize_windows_event(item, index=i) for i, item in enumerate(records)]

    if format_name == "sysmon":
        records = _records_from_json(source)
        return [normalize_sysmon_event(item, index=i) for i, item in enumerate(records)]

    if format_name == "zeek":
        payload = _read_json(source)
        stream = "conn"
        if isinstance(payload, dict):
            stream = str(payload.get("stream") or "conn")
            payload = payload.get("events") or []
        if not isinstance(payload, list):
            raise PipelineInputError("Zeek JSON input must be a list or {stream, events}")
        return [normalize_zeek_event(item, stream=stream, index=i) for i, item in enumerate(payload)]

    raise PipelineInputError(f"unsupported format: {format_name}")


def _write_jsonl(path: Path, events: list[SecurityEvent]) -> None:
    path.write_text(
        "".join(json.dumps(event.model_dump(mode="json"), sort_keys=True) + "\n" for event in events),
        encoding="utf-8",
    )


def _write_report(path: Path, analysis: Any) -> None:
    lines = [
        "# Evidence-First Analysis Report",
        "",
        f"- Events processed: **{analysis.total_events}**",
        f"- Suspicious events: **{analysis.suspicious_events}**",
        f"- Watchlist candidates: **{analysis.watchlist_candidates}**",
        f"- Validated incidents: **{analysis.correlated_incidents}**",
        "",
    ]
    for incident in analysis.incidents:
        lines.extend([
            f"## {incident.incident_id}: {incident.title}",
            "",
            f"- Severity: **{incident.severity}**",
            f"- Risk: **{incident.risk_score}/100**",
            f"- Confidence: **{incident.confidence:.2f}**",
            f"- Entities: {', '.join(incident.entities) or 'None'}",
            "",
            "### Timeline",
            "",
            "| Timestamp | Event ID | Type | User | Device | Resource |",
            "|---|---|---|---|---|---|",
        ])
        for event in incident.timeline:
            lines.append(
                f"| {event.timestamp.isoformat()} | {event.event_id} | {event.event_type} | "
                f"{event.user or ''} | {event.device or ''} | {event.resource or ''} |"
            )
        lines.extend(["", "### Stages", ""])
        for stage in incident.stages:
            evidence = ", ".join(
                f"{item.event_id} ({item.reason})" for item in stage.evidence
            )
            lines.extend([
                f"#### {stage.stage}",
                f"- Confidence: **{stage.confidence:.2f}**",
                f"- Reason: {stage.reason}",
                f"- Evidence: {evidence}",
                "",
            ])
        lines.extend([
            "### Remediation",
            "",
            *[f"- {action}" for action in incident.recommended_actions],
            "",
        ])

    if not analysis.incidents:
        lines.extend(["## Disposition", "", "No validated incident. The evidence did not form a complete attack chain.", ""])
    path.write_text("\n".join(lines), encoding="utf-8")


def run_pipeline(
    path: str | Path,
    out_dir: str | Path,
    format_name: str = "auto",
    config: str | Path | None = None,
    schema: str | Path | None = None,
) -> Any:
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)

    normalized = parse_file(path, format_name=format_name, schema=schema)
    enriched = enrich_events(normalized, config=config)
    analysis = analyze(normalized, config=config)

    _write_jsonl(output / "normalized.jsonl", normalized)
    _write_jsonl(output / "enriched.jsonl", enriched)
    (output / "incidents.json").write_text(
        json.dumps([incident.model_dump(mode="json") for incident in analysis.incidents], indent=2, sort_keys=True),
        encoding="utf-8",
    )
    _write_report(output / "report.md", analysis)

    summary = {
        "input": str(path),
        "format": format_name if format_name != "auto" else detect_format(Path(path)),
        "counts": {
            "input_records": len(normalized),
            "normalized_events": len(normalized),
            "enriched_events": len(enriched),
            "suspicious_events": analysis.suspicious_events,
            "watchlist_candidates": analysis.watchlist_candidates,
            "validated_incidents": analysis.correlated_incidents,
        },
    }
    (output / "run_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return analysis


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m backend.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    command = sub.add_parser("analyze", help="analyze a security-log file")
    command.add_argument("path")
    command.add_argument("--out", required=True)
    command.add_argument("--format", dest="format_name", choices=["auto", "json", "jsonl", "csv", "windows", "sysmon", "zeek"], default="auto")
    command.add_argument("--config", default="config/rules.yml")
    command.add_argument("--schema")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "analyze":
            run_pipeline(args.path, args.out, args.format_name, args.config, args.schema)
            return 0
    except (OSError, PipelineInputError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
