# Phase 8 — Public Dataset Validation

## Goal

Validate the pipeline against public security telemetry instead of relying only on controlled synthetic scenarios.

## First public corpora

### ATLASv2 EDR
- Windows telemetry;
- ten multi-stage attack scenarios;
- realistic background activity and cross-host behavior;
- available through the public PIDSMaker dataset catalog.

### OTRF Security Datasets
- open malicious and benign datasets;
- explicit dataset metadata;
- Windows/Sysmon-oriented collections;
- technique mappings and portable files.

## Reproducibility contract

Raw public datasets are **not committed to this repository**.

Each dataset has:
- public source URL;
- environment-variable path for the local artifact;
- expected format;
- evaluation mode;
- expected technique labels when the public source provides them.

The evaluator refuses to invent data when the artifact is absent. A missing public artifact is reported as `not_available`, not as a pass.

## Normalization contract

Public records are passed through the existing normalized event interface so the detector and reconstruction engine do not gain dataset-specific logic.

Current evaluator formats:
- JSONL;
- JSON array;
- CSV;
- ZIP containing JSON/JSONL/CSV payloads.

## Metrics

The first harness records:
- total public records;
- normalized events;
- parse errors;
- normalization errors;
- event-type distribution;
- source distribution;
- observed ATT&CK technique labels when supplied by the source.

For attack-window datasets, the next evaluation step is to add the public ground-truth windows and compute:
- attack-window recall;
- false-positive incident count outside attack windows;
- reconstruction validity;
- evidence coverage;
- technique coverage.

## Important status

Phase 8 is **not declared passed by the harness alone**.

CI validates the reproducible evaluator and its fail-closed behavior. The real-data gate remains open until a downloaded public artifact is actually mounted and evaluated, because this repository must not claim metrics that were not run on real data.

## Public research basis

PIDSMaker currently lists ATLASV2_EDR as a Windows dataset with ten attacks and approximately 1 GB of uncompressed data, and provides dataset installation guidance. OTRF Security Datasets describes itself as an open project containing malicious and benign datasets intended for testing and validation of detection analytics.

Sources:
- https://github.com/ubc-provenance/PIDSMaker
- https://github.com/OTRF/Security-Datasets
- https://arxiv.org/abs/2401.01341