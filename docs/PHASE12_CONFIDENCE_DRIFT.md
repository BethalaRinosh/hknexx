# Phase 12 — Confidence Drift + Robustness

## Objective

The detector may now tolerate coherent long/slow campaigns, so confidence must still distinguish complete evidence from partial or contradictory evidence.

The regression gate checks:

- complete attack confidence remains at least 0.10 above the partial campaign hypothesis;
- duplicate telemetry does not create duplicate validated incidents;
- reversed input order remains equivalent to chronological input;
- large benign telemetry haystacks remain silent.

The 90-minute drift horizon is guarded by strong identity continuity plus independent resource or behavior corroboration. A larger window by itself is never sufficient.

## Engineering loop

BUILD → BREAK → MEASURE → FIX → REGRESSION → GATE

This phase is deterministic and synthetic. It does not claim field accuracy or adaptive model performance.
