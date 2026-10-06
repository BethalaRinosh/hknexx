# Phase 8 — CERT Insider Threat Public Benchmark

## Why CERT

The CERT Insider Threat Test Dataset is a strong match for the evidence model used by this project because it contains logon activity, file activity, removable-device activity and malicious-insider ground truth. The public 2026 Zenodo derivative used here provides a small labeled event-log sample for reproducible CI.

## Benchmark source

- Zenodo record: https://zenodo.org/records/19135764
- Original CERT dataset: https://doi.org/10.1184/R1/12841247.v1
- Public derived file: `cert_preprocessed_ml_comparison.csv`
- Published size: 4,615 events
- Published class distribution: 70% normal / 30% anomalous

## What we measure

The benchmark groups events by case identifier and evaluates the project's declared three-stage evidence contract:

1. Initial Access / Identity Anomaly
2. Sensitive Data Access
3. Collection / Exfiltration

For each case we measure:

- stage presence;
- chronological ordering;
- number of malicious cases structurally compatible with the contract;
- ordered-chain recall among those compatible malicious cases;
- benign ordered-chain rate.

## Important limitation

This derivative dataset is already transformed into a process-mining event representation. It does **not** preserve every raw field from `logon.csv`, `file.csv` and `device.csv`.

Therefore these results are a **public compatibility benchmark**, not the final end-to-end raw-source detector score.

A phase cannot be declared fully passed from this benchmark alone.

## Gate

Phase 8 remains open until:

- the public labeled event sample downloads successfully in CI;
- the schema is parsed without dropping material records;
- malicious compatible cases are measurable;
- ordered-chain recall and benign-chain rate are recorded;
- the benchmark result is reviewed against the raw-source requirements.

The benchmark deliberately reports benign-chain rate instead of silently treating every full-looking benign sequence as harmless.
