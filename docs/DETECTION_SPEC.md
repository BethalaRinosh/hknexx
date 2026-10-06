# Detection Specification

## 1. Design goal

The detector optimizes for **high-confidence campaign detection**, not maximum alert volume.

A single unusual event is a signal, not an incident.

## 2. Event scoring

The current lightweight event scorer uses explainable indicators:

| Signal | Weight |
|---|---:|
| Unusual login IP | +0.45 |
| New device | +0.20 |
| Sensitive file access | +0.35 |
| Removable-media mount | +0.12 |
| Large copy >= 1 GB | +0.50 |
| High/critical severity context | +0.04 / +0.05 |

Two thresholds are deliberately separated:

- **Candidate threshold = 0.10** — event may participate in correlation.
- **Strong signal threshold = 0.25** — event is counted as suspicious in the dashboard.

This prevents weak contextual events such as a normal USB mount from inflating the alert headline.

## 3. Campaign stages

The MVP has three mandatory stages:

1. Initial Access / Identity Anomaly
2. Sensitive Data Access
3. Collection / Exfiltration

Every stage must contain at least one evidence event.

## 4. Entity consistency

Events are linked using:

- user
- device
- source IP

A direct contradiction in known user or device identity blocks correlation.

Example:

`user=alice, device=DEV-07`
cannot be merged with
`user=alice, device=DEV-99`.

## 5. Temporal consistency

All campaign evidence must fall inside a 30-minute correlation window.

The stage order must be:

`Identity Anomaly → Sensitive Access → Collection/Exfiltration`

A chain with reversed stage order is retained as a watchlist candidate rather than a validated incident.

## 6. Confidence

Campaign confidence combines:

- chain completeness
- evidence corroboration
- temporal consistency
- entity consistency

A complete chain is not automatically enough: identity contradictions or invalid ordering can still prevent validation.

## 7. Dispositions

### Validated incident

Raised only when all three mandatory stages exist, ordering is valid, entity consistency is sufficient, and campaign confidence clears the validation threshold.

### Watchlist candidate

A partial or suspiciously structured chain that needs investigation but does not have enough evidence for an incident.

### Suppressed

Events that do not form a supported attack chain remain quiet.

Explicitly sanctioned activity can also be suppressed when at least two independent authorization/context signals are present alongside a removable-media transfer. This is intentionally stricter than treating authorization as a single-event allow rule.

## 10. Exfiltration evidence gate

A large file copy is not considered removable-media exfiltration solely because its size is large.

For the MVP, collection/exfiltration evidence requires a large transfer plus at least one removable-media indicator:
- USB/removable destination;
- copy-to-USB/removable action; or
- explicit removable-destination metadata.

This prevents ordinary backup jobs from becoming exfiltration evidence.

## 11. Phase 2 pass gate

Phase 2 is passed only when the scenario evaluator reports:

- **0 false-positive validated incidents**
- **0 missed validated attacks**
- every scenario matches its expected disposition
- full attack remains validated
- partial/reversed chains remain watchlisted
- benign lookalikes remain suppressed

The evaluator is available through `/api/phase2/report`.

## 8. Demo validation matrix

| Scenario | Expected result |
|---|---|
| Full multi-stage chain | Validated incident |
| Login anomaly only | Suppressed |
| Legitimate sensitive access | Suppressed |
| USB insertion only | Suppressed |
| Mismatched user/device chain | Suppressed |
| Partial chain | Watchlist |
| Reversed stage order | Watchlist |
| Slow chain outside 30 min | Suppressed |
| Large benign backup | Suppressed |

## 9. Why this architecture

The detector intentionally avoids a large model in the critical decision path.

The competition asks for accurate entity linking, evidence for every stage, correct ordering, explainability and low false positives. A deterministic evidence layer therefore provides a transparent foundation that can later be augmented with lightweight ML or an LLM without making the final decision opaque.


## 12. ATT&CK enrichment

Validated incidents may be enriched with a pinned ATT&CK Enterprise v19.2 mapping catalog.

ATT&CK is descriptive enrichment only. Technique labels never create an incident or override the evidence-first campaign decision.

Each emitted technique mapping carries:
- technique/sub-technique ID and name;
- tactic;
- Detection Strategy and selected Analytics;
- evidence event IDs;
- rationale;
- mapping confidence.

The current demo uses T1078 for the identity-anomaly stage, T1005 for sensitive local data collection, and T1052.001 for USB exfiltration.
