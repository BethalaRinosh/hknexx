from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .detector import analyze
from .evaluator import run_phase2
from .models import AnalysisResponse, Phase2Report, SecurityEvent
from .normalizer import normalize_events

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "backend" / "data"
FRONTEND = ROOT / "frontend"
SCENARIOS = DATA / "scenarios.json"

app = FastAPI(
    title="Evidence-First Cyber Threat Intelligence",
    version="0.4.0",
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


@app.get("/api/demo/{scenario}", response_model=AnalysisResponse)
def demo_scenario(scenario: str) -> AnalysisResponse:
    available = load_scenarios()
    if scenario not in available:
        raise HTTPException(status_code=404, detail=f"unknown scenario: {scenario}")
    return analyze(available[scenario])


@app.get("/api/demo/attack", response_model=AnalysisResponse)
def demo_attack() -> AnalysisResponse:
    return analyze(load_events("attack_logs.json"))


@app.get("/api/demo/clean", response_model=AnalysisResponse)
def demo_clean() -> AnalysisResponse:
    return analyze(load_events("clean_logs.json"))


@app.post("/api/analyze", response_model=AnalysisResponse)
def analyze_logs(events: list[SecurityEvent]) -> AnalysisResponse:
    if not events:
        raise HTTPException(status_code=400, detail="events must not be empty")
    return analyze(events)


@app.post("/api/analyze/raw", response_model=AnalysisResponse)
def analyze_raw_logs(events: list[dict]) -> AnalysisResponse:
    if not events:
        raise HTTPException(status_code=400, detail="events must not be empty")
    return analyze(normalize_events(events))


@app.get("/api/phase2/report", response_model=Phase2Report)
def phase2_report() -> Phase2Report:
    return run_phase2()


@app.get("/api/incidents", response_model=AnalysisResponse)
def incidents() -> AnalysisResponse:
    return demo_attack()
