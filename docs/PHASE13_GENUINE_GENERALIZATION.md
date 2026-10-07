# Phase 13 — Genuine Generalization Benchmark

## Why this exists

The teammate's Phase 13 idea was useful, but mutation of the canonical `full_attack` fixture is not strong evidence of unseen-attack generalization.

This benchmark deliberately **does not derive malicious cases from `backend/data/scenarios.json`**.

Each malicious campaign is independently authored with different:

- users, devices and IPs;
- applications and resources;
- event ordering and timing;
- stage evidence shape;
- exfiltration representation;
- campaign concurrency.

The benchmark currently covers:

1. new-device identity evidence without a login event;
2. sensitive access followed by removable-copy evidence without a USB mount;
3. a long/slow campaign beyond the normal 30-minute window;
4. two simultaneous campaigns with different identities.

Benign controls cover:

- explicitly authorized removable-media transfer;
- shared-IP identity collision;
- large authorized backup activity.

## Gate

For the independently authored synthetic set:

- malicious validated recall must be **1.0**;
- benign validated false-positive rate must be **0.0**.

This is still a synthetic canonical-schema benchmark. It is stronger evidence of structural generalization than cloning/mutating the demo fixture, but it is **not** evidence of field-wide attack recall.

## Engineering loop

BUILD → BREAK → MEASURE → FIX → REGRESSION → GATE
