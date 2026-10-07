# Evidence-First Cyber Threat Intelligence

**HNX26PSI03 — AI-Powered Cyber Threat Intelligence**

An explainable, evidence-first attack reconstruction engine that correlates heterogeneous security telemetry across users, devices, IPs, applications, files and removable media.

> **An anomaly is not an incident. An incident requires a coherent, evidence-backed multi-stage attack chain.**

## What the system does

```
Security Logs → Event Normalization → Entity Resolution → Behavior Signals
→ Temporal / Entity Correlation → Attack-Stage Reasoner → Evidence Coverage
→ Campaign Confidence → Incident / Silent → Timeline + Evidence + ATT&CK + Response
```

The incident-validation boundary is deterministic. ATT&CK is enrichment, and the optional LLM investigator runs only after deterministic validation.

## Demo attack

```
Compromised Account → Unusual Login → New Device → Sensitive File Access
→ USB / Removable Media Mount → Large Data Copy to USB → Validated Incident
```

## Evidence-first security model

- **Event anomaly score:** how unusual is one event?
- **Campaign confidence:** how strongly do related events form a coherent attack?
- **ATT&CK enrichment:** which known technique describes validated behavior?
- **LLM investigation:** how can validated evidence be explained to an analyst?

The LLM cannot create or validate an incident. Every validated stage must contain actual evidence IDs. Telemetry is treated as untrusted data, never as instructions. Entity conflicts, invalid temporal ordering and incomplete chains fail closed.

## Supported telemetry

- Windows Security 4624 / 4663
- Windows XML
- Sysmon 1 / 3 / 11 / 22
- Zeek conn / HTTP / DNS
- Canonical SecurityEvent records

## Current implementation roadmap

| Task | Scope | Status |
|---|---|---|
| Task 1 | Centralized raw-event enrichment and rule-driven behavior signals | Complete |
| Task 2 | File ingestion CLI, normalization/enrichment artifacts, reports, and upload API | Complete |
| Task 3 | Config-driven attack stages and incident response templates | Complete |
| Task 4 | Real CERT evaluation refinement with scenario-level compatibility diagnostics | Complete |
| Task 5 | README and documentation hardening | Ongoing with every change |
| Task 6 | Offline-safe investigator hardening | Complete |
| Task 7 | Smaller defects and cleanup | Planned |

The implementation workflow is tests-first: each task adds or updates regression coverage, runs the full pytest -q suite and CI validation, then is merged only after the relevant gates pass.

## Recent implementation capabilities

### Centralized enrichment

Raw SecurityEvent records are enriched before detection using config/rules.yml. The enrichment layer derives signals such as unusual public IP usage, new-device activity, sensitive-resource access, large transfers, and removable-media destinations without overwriting explicit event metadata.

### File ingestion and reproducible artifacts

backend/cli.py provides file-based ingestion for JSON, JSONL, CSV, Windows, Sysmon, and Zeek telemetry. The pipeline can auto-detect supported formats, validate required fields, normalize records, run enrichment and detection, and emit reproducible artifacts:

- normalized.jsonl
- enriched.jsonl
- incidents.json
- report.md
- run_summary.json

The API also exposes POST /api/analyze/upload for multipart file analysis. config/schema.yml documents the configurable ingestion schema, while Makefile includes install, demo, test, and reproduce targets.

### CERT evaluation diagnostics

The raw CERT evaluator now preserves a result for every malicious scenario and classifies its project compatibility as `compatible`, `missing_identity`, `missing_sensitive_access`, or `missing_exfiltration`. The aggregate result also exposes a compatibility breakdown, making the 70-scenario coverage boundary auditable instead of hiding it behind a single percentage.

This remains a project-specific proxy evaluation. CERT raw telemetry does not directly provide every field used by the production detector, so the benchmark does not claim end-to-end detector recall.

### Config-driven stages and templates

config/rules.yml now controls the display name, ATT&CK technique, confidence values, stage reasons, evidence reasons, incident title, and recommended response actions used by the deterministic detector. The detector retains internal stable stage keys so configuration changes do not alter correlation semantics.

A custom YAML configuration can be passed to backend.detector.analyze(..., config=...), allowing stage presentation and incident response text to change without editing detector logic.

## Validation status

| Phase | Scope | Status |
|---|---|---|
| Phase 1 | Core detection | ✅ Complete |
| Phase 2 | False-positive benchmark | ✅ Complete |
| Phase 3 | Heterogeneous log adapters | ✅ Complete |
| Phase 4 | Behavioral baseline | ✅ Complete |
| Phase 5 | MITRE ATT&CK intelligence | ✅ Complete |
| Phase 6 | Deterministic attack reconstruction | ✅ Complete |
| Phase 7 | Grounded LLM investigator | ✅ Complete |
| Phase 8 | Public + raw CERT validation | ✅ Complete |
| Phase 9 | Judge demo + CI hardening | ✅ Complete |

## Phase 2 — False-positive battle

The scenario benchmark contains 13 cases covering malicious chains and benign lookalikes.

- **0 false positives**
- **0 missed validated attacks**
- All expected dispositions passed

Controls include authorized transfers, large benign backups, shared-IP collisions, ordinary sensitive-file access, standalone USB activity, partial chains, reversed ordering and slow campaigns.

## Phase 4 — Behavioral baseline

The behavior layer tracks historical patterns for source IPs, devices, applications, event types, activity hours and daily volume. Behavior novelty increases suspicion but cannot independently become campaign confidence.

## Phase 5 — MITRE ATT&CK

The project uses a pinned **MITRE ATT&CK Enterprise v19.2** catalog.

Current demo mappings:
- **T1078 — Valid Accounts**
- **T1005 — Data from Local System**
- **T1052.001 — Exfiltration over USB**

ATT&CK is enrichment only. An ATT&CK mapping cannot create or validate an incident.

## Phase 6 — Deterministic attack reconstruction

Validated incidents receive a causal reconstruction containing candidate stage evidence, temporal/entity compatibility, causal edges and reasons, selected event IDs, rejected decoys, reconstruction score, temporal validity and entity conflict count.

## Phase 7 — Grounded LLM investigator

The optional investigator runs **after** deterministic incident validation. Its sealed evidence packet contains the validated incident, reconstruction, ATT&CK enrichment and timeline. Claims must cite real event IDs and are checked by a deterministic validator.

### Offline and provider safety

The investigator fails closed when no provider is configured and can be explicitly disabled with `LLM_OFFLINE=1`. Offline mode rejects the request before any network operation.

When enabled, the provider endpoint must use HTTP or HTTPS. Provider response bodies are bounded by `LLM_MAX_RESPONSE_BYTES`, defaulting to 1 MiB, to prevent an unexpectedly large response from consuming unbounded memory.

Example offline configuration:

```bash
LLM_OFFLINE=1
```

For an active provider, configure `LLM_BASE_URL` and `LLM_MODEL`; optionally set `LLM_API_KEY`, `LLM_PROVIDER`, `LLM_TIMEOUT`, and `LLM_MAX_RESPONSE_BYTES`.

## Phase 8 — Public dataset validation

Phase 8 has two distinct validation tracks.

### Public derived validation

Public security telemetry is normalized and evaluated without committing large raw corpora to Git. The harness reports source coverage and normalization results and fails closed when the expected real artifact is unavailable.

### Raw CERT r4.2 benchmark

The project executed the **raw CERT Insider Threat Test Dataset r4.2** benchmark using raw logon, device and file data plus the official answer-key data.

Verified raw file row counts:

- logon.csv: **854,859**
- device.csv: **405,380**
- file.csv: **445,581**
- insiders.csv: **191**
- malicious scenarios: **70**

Raw benchmark result:

| Metric | Result |
|---|---:|
| Malicious scenarios | 70 |
| Project-compatible scenarios | 3 / 70 |
| Compatibility rate | **4.29%** |
| Identity-stage proxy recall | **100.00%** |
| Sensitive-stage proxy recall | **5.71%** |
| Exfil-stage proxy recall | **4.29%** |
| Ordered-chain proxy recall | **4.29%** |
| Compatible ordered-chain recall | **100.00%** |
| Benign windows sampled | 300 |
| Benign proxy chains | 7 |
| Benign proxy-chain rate | **2.33%** |

**Important:** 4.29% is a dataset/project compatibility rate, not end-to-end detector recall over all 70 malicious scenarios. Only 3 CERT malicious scenarios matched the current identity → sensitive file activity → removable-media evidence contract. All 3 compatible scenarios completed the ordered chain.

Relevant implementation:
- `docs/CERT_RAW_ACQUISITION.md`
- `docs/PHASE8_CERT_RAW_GATE.md`
- `backend/cert_raw_benchmark.py`
- `scripts/run_cert_raw_benchmark.py`
- `scripts/verify_cert_raw_layout.py`

## Phase 9 — Judge demo

The judge dashboard exposes detection, campaign risk, attack timeline, entity graph, stage-by-stage evidence, deterministic reconstruction, selected evidence, rejected decoys, ATT&CK intelligence, response actions, validation status and benign suppression.

The Phase 9 CI gate verifies frontend JavaScript syntax, the full-attack judge contract, clean-control suppression, adversarial partial-chain suppression and the complete pytest regression suite.

Phase 9 hardening was merged after the relevant Phase 2–8 and Phase 9 checks passed.

## Project structure

```
backend/
  main.py
  models.py
  detector.py
  cert_raw_benchmark.py
  evaluator.py
  data/

frontend/
  index.html
  app.js
  style.css

scripts/
  run_cert_raw_benchmark.py
  verify_cert_raw_layout.py

tests/
  phase and regression tests

docs/
  detection and phase specifications
  validation reports
  CERT raw acquisition/gate documentation

.github/workflows/
  phase2.yml ... phase9.yml
  phase8-cert-raw.yml
```

## Run locally

Python 3.10+ is recommended.

### Install

```bash
python -m venv .venv

# Windows
.venv\\Scripts\\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
```

### Start the dashboard

```bash
uvicorn backend.main:app --reload
```

Open `http://127.0.0.1:8000`.

### Reproduce the demo pipeline

The repository includes a Makefile for the reproducible demo and regression flow:

```bash
make install
make demo
make test
make reproduce
```

`make demo` analyzes the committed attack and clean samples and writes artifacts under `out/demo/`. The pipeline emits `normalized.jsonl`, `enriched.jsonl`, `incidents.json`, `report.md`, and `run_summary.json`.

### File-based CLI

Analyze supported telemetry directly without starting the API:

```bash
python -m backend.cli analyze <input-file> --out out/run --format auto --config config/rules.yml
```

Supported formats are JSON, JSONL/NDJSON, CSV, Windows JSON/XML, Sysmon JSON, and Zeek JSON. For generic JSON/JSONL/CSV inputs, `config/schema.yml` can map source column names to canonical `SecurityEvent` fields.

Example:

```bash
python -m backend.cli analyze data/sample/attack.json --out out/attack --config config/rules.yml
```

The CLI fails closed on unsupported schemas and reports the fields it found plus the canonical fields/aliases it expects.


Python 3.10+ is recommended.

```bash
python -m venv .venv

# Windows
.venv\\Scripts\\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
uvicorn backend.main:app --reload
```

Open `http://127.0.0.1:8000`.

### API

- `GET /health`
- `GET /api/demo/attack`
- `GET /api/demo/clean`
- `POST /api/analyze`
- `POST /api/analyze/raw`
- `POST /api/analyze/behavior`
- `POST /api/reconstruct`
- `POST /api/investigate`
- `GET /api/incidents`

## Validation commands

```bash
python -m pytest -q
python -m pytest -q tests/test_phase9_judge_demo.py
node --check frontend/app.js
```

## Data and provenance

Demo scenarios are intentionally small and controlled so the complete attack chain can be reproduced during a hackathon demonstration. Public validation is kept separate from committed demo data, and large raw datasets are not committed to the repository.

Raw CERT r4.2 execution uses externally acquired data and an official answer-key source. The repository contains the acquisition, layout-validation and benchmark logic rather than the raw corpus itself.

## Design constraints

The project intentionally avoids anomaly-only incident generation, ATT&CK-only detection, LLM-generated incidents, synthetic public-dataset validation, unsupported evidence references, entity-conflict incidents and temporally impossible attack chains.

**Evidence first, explanation second.**

## Resource declaration

Core stack: Python, FastAPI, Pydantic, Uvicorn, deterministic correlation/reconstruction, MITRE ATT&CK enrichment, optional grounded LLM investigation, and a JavaScript/HTML/CSS dashboard.

No proprietary evaluation data is committed to the repository.