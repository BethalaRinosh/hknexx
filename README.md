# Evidence-First Cyber Threat Intelligence

HNX26PSI03 — AI-Powered Cyber Threat Intelligence

A lightweight, explainable attack-reconstruction engine that correlates security events across users, devices, IPs, applications, files and removable media.

## Core idea

The system does **not** raise an incident because one event looks unusual.

It first:

1. normalizes heterogeneous security events;
2. resolves entities;
3. scores individual behavioral anomalies;
4. builds temporal relationships;
5. identifies a multi-stage attack chain;
6. verifies evidence for every stage;
7. calculates incident confidence;
8. stays silent when the evidence is insufficient;
9. produces a human-readable incident story and recommended response.

## Demo attack

Compromised account → unusual login → new device → sensitive file access → USB mount → large data copy.

## Architecture

```
Security Logs
    ↓
Event Normalization
    ↓
Entity Resolution
    ↓
Behavior Signals
    ↓
Temporal / Entity Correlation
    ↓
Attack-Stage Reasoner
    ↓
Evidence Coverage
    ↓
Campaign Confidence
    ↓
Incident / Silent
    ↓
Timeline + Evidence + ATT&CK + Response
```

## Project structure

```
backend/
  main.py              FastAPI API + static dashboard serving
  models.py            Pydantic event/result models
  detector.py          Detection, correlation and evidence engine
  data/
    attack_logs.json   Controlled multi-stage attack
    clean_logs.json    Benign baseline
frontend/
  index.html
  app.js
  style.css
requirements.txt
```

## Run locally

Python 3.10+ is recommended.

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Open http://127.0.0.1:8000

API:
- GET /health
- GET /api/demo/attack
- GET /api/demo/clean
- POST /api/analyze — normalized events
- POST /api/analyze/raw — heterogeneous/raw events
- GET /api/incidents

## Validation scenarios

The dashboard includes repeatable scenarios for full attacks, benign activity, partial chains, entity mismatches, reversed ordering, slow campaigns, and large benign backups. The goal is to demonstrate that the detector does not turn every anomaly into an incident.

See `docs/DETECTION_SPEC.md` for the exact scoring, correlation window, stage requirements and disposition rules.

## Phase 4 — Behavior baseline layer

The system now learns lightweight per-user/device historical baselines for source IPs, devices, applications, event types, activity hours, and daily activity volume.

Behavior anomaly scores are explicitly separated from campaign confidence. A novel IP or device can raise suspicion, but a validated incident still requires the existing multi-stage evidence chain, temporal ordering, entity consistency and corroborating evidence.

The behavior API accepts historical normalized events plus current events at `POST /api/analyze/behavior` and returns per-event scores and human-readable reasons.

See `docs/PHASE4_SPEC.md` for the gate and false-positive policy.

## Current detection philosophy

### Event score
How unusual is the individual event?

### Campaign score
How strongly does the event participate in a coherent attack chain?

An unusual event alone is not an incident.

The MVP requires multiple related events with:
- consistent user/device/entity linkage;
- valid temporal order;
- sufficient attack-stage coverage;
- evidence references for every inferred stage.

## Evidence-first output

Every attack stage contains:
- stage name
- confidence
- supporting event IDs
- involved entities
- reason

The UI can therefore answer **why** an incident was raised instead of presenting a black-box alert.

## Phase 5 — Grounded ATT&CK intelligence
## Phase 6 — Temporal attack reconstruction

Validated incidents now include a deterministic causal reconstruction layer. Candidate stage evidence is converted into an identity- and time-aware graph, feasible paths are scored, and the highest-scoring minimal attack skeleton is retained.

The reconstruction records edge reasons, reconstruction confidence, temporal validity, identity conflicts and non-selected attack-like decoys. The minimal path can therefore explain the causal backbone without pretending every nearby event is part of the attack.

`POST /api/reconstruct` exposes the reconstruction engine directly.

See `docs/PHASE6_SPEC.md` for the path-scoring and adversarial gate.


Validated incidents are now enriched with a pinned **MITRE ATT&CK Enterprise v19.2** catalog. Each mapping includes the technique/sub-technique, tactic, ATT&CK version, Detection Strategy, selected analytics, evidence event IDs, rationale and mapping confidence.

The current demo maps:
- T1078 — Valid Accounts
- T1005 — Data from Local System
- T1052.001 — Exfiltration over USB

ATT&CK remains enrichment only. It cannot create or validate an incident without the evidence-first chain.

See `docs/PHASE5_SPEC.md` and `backend/data/attack_intelligence.json`.

## Threat intelligence enrichment

MITRE ATT&CK technique IDs are attached as enrichment after behavioral detection. The detector is not dependent on ATT&CK rules.

Planned mappings for the demo:
- T1078 — Valid Accounts
- T1083 — File and Directory Discovery
- T1005 — Data from Local System
- T1025 — Data from Removable Media

## Data

The initial demo data is synthetic and intentionally small so the complete chain can be reproduced during a hackathon demonstration.

Research validation can later use public provenance/IDS datasets such as NODLINK/PIDSMaker datasets without changing the normalized event interface.

## Phase 2 validation

The project contains a scenario-based false-positive benchmark in `backend/data/phase2_manifest.json` and an evaluator in `backend/evaluator.py`.

The benchmark intentionally includes benign lookalikes such as:
- authorized administrative transfers;
- large backup operations;
- shared-IP collisions;
- ordinary sensitive-file access;
- standalone USB activity;
- partial chains;
- reversed temporal order.

The detector must produce the expected disposition for every case before Phase 3 begins.

## MVP vs stretch

### MVP
- heterogeneous event normalization
- temporal correlation
- user/device/IP/application linking
- multi-stage attack reconstruction
- evidence coverage
- risk/confidence
- clean-log suppression
- dashboard

### Stretch
- Isolation Forest / lightweight ML anomaly model
- Sigma rule ingestion
- OCSF-native adapters
- public provenance dataset evaluation
- ATT&CK navigator export
- LLM incident summarization grounded strictly in event IDs
- real-time streaming ingestion

## Resource declaration

The project is designed to use:
- Python
- FastAPI
- Pydantic
- Uvicorn
- synthetic security logs for the initial demo
- MITRE ATT&CK identifiers as threat-intelligence enrichment

No proprietary evaluation data is used.
