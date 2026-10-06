# Phase 4 — Explainable Behavior Baselines

## Goal

Add a lightweight behavioral layer that learns per-entity historical behavior and produces explainable anomaly signals without turning anomalies directly into incidents.

Pipeline:

Historical events
→ entity profile
→ baseline features
→ behavior anomaly score
→ enriched normalized events
→ existing evidence-first detector
→ campaign confidence

## Baseline scope

The first implementation is deterministic and dependency-light.

Per user (or device when user is absent), the profile tracks:
- known source IPs;
- known devices;
- known applications;
- observed event types;
- activity-hour distribution;
- daily activity counts.

Behavior signals include:
- novel source IP;
- novel device;
- rarely observed activity hour;
- previously unseen event type;
- historical-vs-current daily activity burst when enough history exists.

Scores are bounded to [0, 1] and include human-readable reasons.

## Critical design rule

**Behavior anomaly score is not attack confidence.**

A single anomalous event may be suspicious, but it cannot create a validated incident.

The existing detector still requires:
- multi-stage evidence;
- temporal ordering;
- entity consistency;
- sufficient corroboration;
- evidence attached to each stage.

Behavior signals only provide supporting context and can help infer existing unusual_ip / new_device flags.

## False-positive controls

The baseline layer must:
- withhold a score when the historical baseline is too small;
- avoid claiming novelty without historical evidence;
- remain silent on a lone anomaly;
- preserve all original event fields;
- never override explicit enterprise authorization suppression;
- never replace the evidence-first campaign confidence calculation.

## API

POST /api/analyze/behavior

Request:
{"baseline": [ ...historical normalized events... ], "events": [ ...current normalized events... ]}

Response contains:
- number of baseline entities;
- number of anomalous events;
- per-event behavior score and reasons;
- the normal Phase 2/3 analysis result over behavior-enriched events.

## Phase 4 gate

The phase passes only when all of these hold:
1. historical entity identity is learned correctly;
2. novel IP/device behavior is detected;
3. known behavior stays benign;
4. insufficient history does not create a fabricated anomaly;
5. a behavior anomaly alone cannot create an incident;
6. a full attack still validates after enrichment;
7. all Phase 1–3 regression tests remain green;
8. behavior score remains distinct from campaign confidence.

## Research boundary

Commercial security platforms already use entity analytics, behavioral anomaly detection and risk scoring. Our implementation is deliberately smaller and open, while the project differentiator remains evidence-first cross-source attack-chain verification rather than anomaly detection alone.

MITRE ATT&CK detection strategies also describe behavioral correlations such as removable-drive insertion followed by unusual file access or staging, reinforcing the need to treat behavioral signals as context inside a broader evidence chain.