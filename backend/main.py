from __future__ import annotations

import json
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .detector import analyze
from .models import AnalysisResponse, SecurityEvent

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "backend" / "data"
FRONTEND = ROOT / "frontend"

app = FastAPI(
    title="Evidence-First Cyber Threat Intelligence",
    version="0.1.0",
    description="Explainable multi-stage attack reconstruction for HNX26PSI03.",
)

app.mount("/static", StaticFiles(directory=FRONTEND), name="static")


def load_events(name: str) -> list[SecurityEvent]:
    path = DATA / name
    with path.open("r", encoding="utf-8") as f:
        raw = json.load(f)
    return [SecurityEvent.model_validate(item) for item in raw]


@app.get("/")
def index() -> FileResponse:
    return FileResponse(FRONTEND / "index.html")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "evidence-first-cti"}


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


@app.get("/api/incidents", response_model=AnalysisResponse)
def incidents() -> AnalysisResponse:
    return demo_attack()
