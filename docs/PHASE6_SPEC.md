# Phase 6 — Temporal Attack Reconstruction

## Goal

Move from stage matching to explicit attack-path reconstruction.

The reconstruction engine treats candidate evidence as a temporal graph and searches for the highest-scoring path that satisfies:
- required stage coverage;
- temporal ordering;
- user/device/session compatibility;
- resource or removable-media continuity when available;
- correlation-window constraints.

## Reconstruction pipeline

Candidate events
→ typed stage candidates
→ temporal/entity-compatible edges
→ feasible 3-stage paths
→ path scoring
→ best causal path
→ minimal attack footprint + decoy evidence

## Edge semantics

Each edge records:
- source event;
- target event;
- relation type;
- continuity score;
- human-readable reasons.

Continuity rewards:
- shared user/device/source IP/session;
- matching applications;
- matching resources;
- USB mount → USB copy continuity;
- independent behavior-baseline support.

Contradictory user/device/session identities block an edge.

## Skeleton vs supporting evidence

The reconstructed path is a minimal causal skeleton. It is not required to contain every supporting telemetry event.

For the demo, the causal skeleton is:

unusual login → sensitive file access → large copy to USB

A nearby USB-mount event can remain attached to the incident as corroborating evidence while the reconstruction identifies the file-copy event as the strongest terminal action.

## Decoy handling

When multiple stage candidates exist, the engine ranks feasible paths instead of selecting the first matching event.

Non-selected but attack-like candidates are returned as decoy_event_ids, making investigator review explicit.

## Phase 6 gate

The phase passes only when:
1. the full attack produces one coherent path;
2. path ordering is valid;
3. entity conflicts are zero;
4. mismatched-entity chains produce no complete path;
5. reversed-order chains produce no complete path;
6. slow attacks outside the window produce no complete path;
7. decoy evidence is retained but excluded from the minimal path;
8. the existing Phase 1–5 regression suites remain green;
9. validated incidents include reconstruction metadata.

## Research basis

KAIROS frames attack reconstruction as distilling attack activity from large provenance graphs into compact summary graphs. Newer temporal-graph work similarly focuses on preserving causal reachability while filtering redundant provenance before reconstructing coherent attack processes. Our MVP implements the same conceptual direction with a deterministic, auditable search rather than a GNN, keeping the critical decision path explainable and hackathon-friendly.