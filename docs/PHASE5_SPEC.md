# Phase 5 — Grounded ATT&CK Intelligence

## Goal

Attach current MITRE ATT&CK intelligence to validated incidents without turning ATT&CK labels into the detection engine.

Current pinned Enterprise ATT&CK catalog: **v19.2**.

## Intelligence contract

Each emitted mapping contains:

- ATT&CK technique or sub-technique ID;
- technique name;
- tactic;
- concise technique description;
- ATT&CK release version;
- technique version;
- Detection Strategy ID and name when available;
- selected Analytics IDs;
- relevant log-source context;
- evidence event IDs;
- explicit rationale;
- mapping type;
- mapping confidence.

## Current MVP mappings

| Stage | ATT&CK | Detection Strategy |
|---|---|---|
| Identity anomaly | T1078 — Valid Accounts | DET0560 |
| Sensitive local data access | T1005 — Data from Local System | DET0380 |
| USB exfiltration | T1052.001 — Exfiltration over USB | DET0220 |

The USB mapping corrects an earlier MVP label. T1025 is **Data from Removable Media**, which describes collecting data from removable media; copying sensitive local data to USB is better represented by T1052.001, Exfiltration over USB.

## Grounding rule

ATT&CK is enrichment, not evidence.

The system must never validate an incident merely because an event has a technique label.

Technique mappings must reference one or more actual evidence events. A mapping may be marked as behavioral inference when the evidence is consistent with a technique but does not prove the adversary's mechanism, such as credential theft behind a valid-account login.

## Versioning rule

The Phase 5 catalog is pinned to a known ATT&CK release. Unknown technique IDs fail validation rather than silently passing through.

Updating ATT&CK later must be an explicit catalog update with regression tests.

## Phase 5 gate

The phase passes only when:

1. full attack receives all expected ATT&CK mappings;
2. every mapping contains evidence IDs;
3. every mapping references a known pinned technique;
4. every mapped technique has its expected Detection Strategy;
5. USB exfiltration is mapped to T1052.001, not T1025;
6. unknown technique IDs are rejected;
7. Phase 1–4 regression tests remain green;
8. ATT&CK remains enrichment-only and cannot independently create an incident.

## Current official basis

MITRE ATT&CK v19.2 is the current catalog in the repository at the time this phase was researched. MITRE now uses Detection Strategies and Analytics as the modern detection-content representation; the older Data Sources construct was deprecated in ATT&CK v18.

Official sources used for this phase:

- https://attack.mitre.org/resources/versions/
- https://attack.mitre.org/resources/attack-data-and-tools/
- https://attack.mitre.org/techniques/T1078/
- https://attack.mitre.org/detectionstrategies/DET0560/
- https://attack.mitre.org/techniques/T1005/
- https://attack.mitre.org/detectionstrategies/DET0380/
- https://attack.mitre.org/techniques/T1052/001/
- https://attack.mitre.org/detectionstrategies/DET0220/
