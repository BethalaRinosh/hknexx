# Phase 11 — Adversarial Detection Benchmark

## Objective

The detector is now measured against the failure modes that matter for an evidence-first campaign system, rather than only replaying the happy-path attack.

The benchmark separates:

- **validated**: the deterministic incident gate passed;
- **watchlist**: suspicious or incomplete evidence without incident validation;
- **suppressed**: no actionable campaign.

Incomplete malicious evidence is therefore not counted as a missed validated incident when it remains a watchlist hypothesis.

## Matrix

| Case | Ground truth | Purpose |
|---|---|---|
| baseline_attack | malicious | Full-chain control |
| noisy_attack | malicious | Benign telemetry interleaved with an attack |
| out_of_order_input | malicious | Input ordering must not change the result |
| decoy_attack | malicious | Distractor evidence must not replace the causal path |
| missing_telemetry | malicious | Partial-evidence boundary |
| clean_control | benign | Basic suppression |
| reversed_order | benign | Temporal causality |
| mismatched_entities | benign | Entity consistency |
| shared_ip_collision | benign | IP-only stitching must not create a campaign |
| authorized_transfer | benign | Explicit authorization |
| benign_usb_lookalike | benign | Attack-shaped but sanctioned workflow |
| benign_backup | benign | Large benign transfer |
| legitimate_sensitive_access | benign | Sensitive access without exfiltration |
| partial_attack | benign/control | Watchlist boundary |

## Metrics

python -m backend.adversarial produces:

- precision
- recall
- F1
- false-positive rate
- false-negative rate
- true/false positive and negative counts
- per-case disposition and reason

Only validated incidents contribute to precision/recall. Watchlist hypotheses are reported separately.

## Current gate

The repository regression requires:

- zero validated false positives;
- no missed complete malicious campaigns;
- every benchmark case passes its declared disposition;
- the existing Phase 2–9 suite remains green.

This is a deterministic synthetic benchmark, not a claim of production-world recall.

## Engineering loop

BUILD → BREAK → MEASURE → FIX → REGRESSION → GATE
