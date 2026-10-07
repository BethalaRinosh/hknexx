from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from math import isfinite

from fastapi import FastAPI, File, HTTPException, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .adapters import normalize_sysmon_event, normalize_windows_event, normalize_windows_event_xml, normalize_zeek_event
from .behavior import build_profiles, enrich_events
from .detector import analyze
from .investigator import investigate
from .cli import parse_file
from .reconstructor import reconstruct
from .evaluator import run_phase2
from .models import AnalysisResponse, BehaviorAnalysisResponse, BehaviorSignalResponse, InvestigationReport, InvestigationRequest, Phase2Report, SecurityEvent
from .normalizer import normalize_events
from .realtime import simulate_event_stream

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "backend" / "data"
FRONTEND = ROOT / "frontend"
SCENARIOS = DATA / "scenarios.json"

app = FastAPI(
    title="Evidence-First Cyber Threat Intelligence",
    version="0.5.0",
    description="Explainable multi-stage attack reconstruction for HNX26PSI03.",
)

app.mount("/static", StaticFiles(directory=FRONTEND), name="static")


def load_events(name: str) -> list[SecurityEvent]:
    with (DATA / name).open("r", encoding="utf-8") as f:
        raw = json.load(f)
    return [SecurityEvent.model_validate(item) for item in raw]


def load_scenarios() -> dict[str, list[SecurityEvent]]:
    with SCENARIOS.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    return {
        name: [SecurityEvent.model_validate(item) for item in events]
        for name, events in raw.items()
    }


@app.get("/")
def index() -> FileResponse:
    return FileResponse(FRONTEND / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "evidence-first-cti"}


@app.get("/api/scenarios")
def scenarios() -> dict[str, list[str]]:
    return {"scenarios": sorted(load_scenarios().keys())}


@app.get("/api/demo/attack", response_model=AnalysisResponse)
def demo_attack() -> AnalysisResponse:
    return analyze(load_events("attack_logs.json"))


@app.get("/api/demo/clean", response_model=AnalysisResponse)
def demo_clean() -> AnalysisResponse:
    return analyze(load_events("clean_logs.json"))


@app.get("/api/demo/{scenario}", response_model=AnalysisResponse)
def demo_scenario(scenario: str) -> AnalysisResponse:
    available = load_scenarios()
    if scenario not in available:
        raise HTTPException(status_code=404, detail=f"unknown scenario: {scenario}")
    return analyze(available[scenario])


@app.websocket("/ws/simulate/{scenario}")
async def simulate_scenario(websocket: WebSocket, scenario: str) -> None:
    await websocket.accept()
    try:
        available = load_scenarios()
        if scenario not in available:
            await websocket.send_json({"type": "error", "message": f"unknown scenario: {scenario}"})
            return

        try:
            delay = float(websocket.query_params.get("delay", "1.0"))
        except (TypeError, ValueError):
            delay = 1.0
        if not isfinite(delay):
            delay = 1.0
        delay = max(0.0, min(delay, 10.0))

        await websocket.send_json({
            "type": "start",
            "scenario": scenario,
            "mode": "simulation",
            "delay_seconds": delay,
            "message": "Simulated telemetry stream started.",
        })

        accumulated: list[SecurityEvent] = []
        async for event in simulate_event_stream(available[scenario], delay_seconds=delay):
            accumulated.append(event)
            analysis = analyze(accumulated)
            await websocket.send_json({
                "type": "event",
                "event": event.model_dump(mode="json"),
                "analysis": analysis.model_dump(mode="json"),
                "event_count": len(accumulated),
            })

        final_analysis = analyze(accumulated)
        await websocket.send_json({
            "type": "complete",
            "scenario": scenario,
            "analysis": final_analysis.model_dump(mode="json"),
            "event_count": len(accumulated),
            "message": "Simulated telemetry stream completed.",
        })
    except WebSocketDisconnect:
        return
    except Exception as exc:
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass
    finally:
        try:
            if websocket.client_state.name != "DISCONNECTED":
                await websocket.close()
        except Exception:
            pass


@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze_logs(events: list[SecurityEvent]) -> AnalysisResponse:
    if not events:
        raise HTTPException(status_code=400, detail="events must not be empty")
    _enforce_event_limit(events, "/api/analyze")
    return analyze(events)


UPLOAD_MAX_BYTES_DEFAULT = 10 * 1024 * 1024
ALLOWED_UPLOAD_SUFFIXES = {".json", ".jsonl", ".ndjson", ".csv", ".xml"}
\nMAX_API_EVENTS_DEFAULT = 5000


def _api_event_limit() -> int:
    raw = os.getenv("HNX_MAX_API_EVENTS", str(MAX_API_EVENTS_DEFAULT)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail="invalid HNX_MAX_API_EVENTS configuration") from exc
    if value <= 0:
        raise HTTPException(status_code=500, detail="HNX_MAX_API_EVENTS must be positive")
    return value


def _enforce_event_limit(events: list[object], endpoint: str) -> None:
    limit = _api_event_limit()
    if len(events) > limit:
        raise HTTPException(
            status_code=413,
            detail=f"{endpoint} accepts at most {limit} events per request",
        )




def _upload_max_bytes() -> int:
    raw = os.getenv("HNX_UPLOAD_MAX_BYTES", str(UPLOAD_MAX_BYTES_DEFAULT)).strip()
    try:
        value = int(raw)
    except ValueError as exc:
        raise HTTPException(status_code=500, detail="invalid HNX_UPLOAD_MAX_BYTES configuration") from exc
    if value <= 0:
        raise HTTPException(status_code=500, detail="HNX_UPLOAD_MAX_BYTES must be positive")
    return value


@app.post("/api/analyze/upload", response_model=AnalysisResponse)
async def analyze_upload(
    file: UploadFile = File(...),
    format_name: str = "auto",
) -> AnalysisResponse:
    if not file.filename:
        raise HTTPException(status_code=400, detail="file must have a filename")

    filename = Path(file.filename).name
    if len(filename) > 255:
        raise HTTPException(status_code=400, detail="filename is too long")

    suffix = Path(filename).suffix.lower()
    if format_name == "auto" and suffix not in ALLOWED_UPLOAD_SUFFIXES:
        allowed = ", ".join(sorted(ALLOWED_UPLOAD_SUFFIXES))
        raise HTTPException(status_code=415, detail=f"unsupported upload extension; allowed: {allowed}")

    max_bytes = _upload_max_bytes()
    temp_path: Path | None = None
    total_bytes = 0

    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as handle:
            temp_path = Path(handle.name)
            while chunk := await file.read(1024 * 1024):
                total_bytes += len(chunk)
                if total_bytes > max_bytes:
                    raise HTTPException(
                        status_code=413,
                        detail=f"uploaded file exceeds the {max_bytes} byte limit",
                    )
                handle.write(chunk)

        events = parse_file(temp_path, format_name=format_name)
        if not events:
            raise HTTPException(status_code=400, detail="file contains no events")
        _enforce_event_limit(events, "/api/analyze/upload")
        return analyze(events)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


@app.post("/api/analyze/raw", response_model=AnalysisResponse)
def analyze_raw_logs(events: list[dict]) -> AnalysisResponse:
    if not events:
        raise HTTPException(status_code=400, detail="events must not be empty")
    _enforce_event_limit(events, "/api/analyze/raw")
    return analyze(normalize_events(events))


@app.post("/api/analyze/windows", response_model=AnalysisResponse)
def analyze_windows(events: list[dict]) -> AnalysisResponse:
    if not events:
        raise HTTPException(status_code=400, detail="events must not be empty")
    _enforce_event_limit(events, "/api/analyze/windows")
    normalized = [normalize_windows_event(event, index=i) for i, event in enumerate(events)]
    return analyze(normalized)


@app.post("/api/analyze/windows/xml", response_model=AnalysisResponse)
def analyze_windows_xml(events: list[str]) -> AnalysisResponse:
    if not events:
        raise HTTPException(status_code=400, detail="events must not be empty")
    _enforce_event_limit(events, "/api/analyze/windows/xml")
    normalized = [normalize_windows_event_xml(event, index=i) for i, event in enumerate(events)]
    return analyze(normalized)


@app.post("/api/analyze/sysmon", response_model=AnalysisResponse)
def analyze_sysmon(events: list[dict]) -> AnalysisResponse:
    if not events:
        raise HTTPException(status_code=400, detail="events must not be empty")
    _enforce_event_limit(events, "/api/analyze/sysmon")
    normalized = [normalize_sysmon_event(event, index=i) for i, event in enumerate(events)]
    return analyze(normalized)


@app.post("/api/analyze/zeek", response_model=AnalysisResponse)
def analyze_zeek(payload: dict) -> AnalysisResponse:
    events = payload.get("events") or []
    stream = str(payload.get("stream") or "conn")
    if not events:
        raise HTTPException(status_code=400, detail="events must not be empty")
    _enforce_event_limit(events, "/api/analyze/zeek")
    normalized = [normalize_zeek_event(event, stream=stream, index=i) for i, event in enumerate(events)]
    return analyze(normalized)


@app.post("/api/investigate", response_model=InvestigationReport)
def investigate_incident(payload: InvestigationRequest) -> InvestigationReport:
    if not payload.events:
        raise HTTPException(status_code=400, detail="events must not be empty")
    _enforce_event_limit(payload.events, "/api/investigate")

    analysis = analyze(payload.events)
    if not analysis.incidents:
        raise HTTPException(
            status_code=422,
            detail="no validated incident is available for grounded investigation",
        )

    incident = next(
        (
            item
            for item in analysis.incidents
            if payload.incident_id is None or item.incident_id == payload.incident_id
        ),
        None,
    )
    if incident is None:
        raise HTTPException(status_code=404, detail="incident_id not found")

    try:
        return investigate(incident, question=payload.question)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@app.post("/api/reconstruct")
def reconstruct_attack(events: list[SecurityEvent]) -> dict:
    if not events:
        raise HTTPException(status_code=400, detail="events must not be empty")
    _enforce_event_limit(events, "/api/reconstruct")
    return reconstruct(events).model_dump(mode="json")


@app.post("/api/analyze/behavior", response_model=BehaviorAnalysisResponse)
def analyze_behavior(payload: dict) -> BehaviorAnalysisResponse:
    baseline = payload.get("baseline") or []
    events = payload.get("events") or []
    if not baseline:
        raise HTTPException(status_code=400, detail="baseline must contain historical events")
    if not events:
        raise HTTPException(status_code=400, detail="events must contain events to score")
    _enforce_event_limit(baseline + events, "/api/analyze/behavior")

    baseline_events = [SecurityEvent.model_validate(item) for item in baseline]
    current_events = [SecurityEvent.model_validate(item) for item in events]
    enriched, signals = enrich_events(baseline_events, current_events)

    analysis = analyze(enriched)
    return BehaviorAnalysisResponse(
        total_events=len(enriched),
        baseline_entities=len(build_profiles(baseline_events)),
        anomalous_events=sum(1 for signal in signals if signal.anomalous),
        signals=[
            BehaviorSignalResponse(
                event_id=signal.event_id,
                entity=signal.entity,
                score=signal.score,
                reasons=signal.reasons,
                anomalous=signal.anomalous,
            )
            for signal in signals
        ],
        analysis=analysis,
    )


@app.get("/api/phase2/report", response_model=Phase2Report)
def phase2_report() -> Phase2Report:
    return run_phase2()


@app.get("/api/incidents", response_model=AnalysisResponse)
def incidents() -> AnalysisResponse:
    return demo_attack()
