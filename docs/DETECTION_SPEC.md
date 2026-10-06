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
