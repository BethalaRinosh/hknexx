# Phase 9 — Judge Demo

## Goal

Turn the validated detection engine into a judge-facing investigation console without changing the deterministic detection boundary.

The demo must make one question easy to answer:

> Why did the system call this an attack?

## Judge flow

1. Detection — heterogeneous events are normalized and correlated.
2. Timeline — the analyst sees the event order.
3. Entity graph — user, device, IP, application and resource links are visible.
4. Attack stages — each required stage shows its supporting event IDs.
5. Reconstruction — the minimal causal backbone is shown separately from decoy events.
6. ATT&CK — deterministic mappings enrich the validated chain.
7. Response — recommended containment/triage actions are shown.
8. Benign control — running clean or adversarial partial scenarios demonstrates that anomaly does not automatically become an incident.

## Demo scenario

The primary full_attack scenario is:

Unusual login → new device → sensitive finance file access → removable USB mount → large copy to USB

The UI should emphasize the event IDs that support each stage.

## Why the UI does not call the LLM automatically

The grounded investigator remains an optional post-validation investigator. The live demo must not depend on external model configuration to establish whether an attack exists.

This preserves the architecture:

Deterministic detection → Attack reconstruction → Evidence + ATT&CK → Optional grounded investigation

## Phase 9 acceptance gate

The judge surface is ready when:

- full attack produces a validated incident;
- clean scenario remains silent;
- attack stages display evidence event IDs;
- reconstruction displays selected events and rejected decoys;
- ATT&CK enrichment is visible;
- response actions are visible;
- Phase 2 validation status is visible;
- frontend JavaScript parses successfully;
- backend regression and Phase 2–8 workflows remain green.

## Raw CERT boundary

The Phase 8 raw CERT benchmark remains independent. No synthetic or derived dataset result is presented as raw CERT recall.

The official raw benchmark must still be executed before a raw-data recall claim is made.