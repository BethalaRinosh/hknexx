# Phase 8 — Raw CERT r4.2 Chain Gate

## Why this gate exists

The compact public Zenodo derivative contains 4,615 events across 64 cases, but none of its 20 malicious cases contains the project's complete three-stage chain. It is therefore useful for parser/schema validation, but it cannot produce a legitimate end-to-end chain-recall score.

The raw CERT r4.2 source has the actual multi-source structure:

- `logon.csv`
- `device.csv`
- `file.csv`
- `insiders.csv`

Public documentation for CERT r4.2 identifies logon events, removable-device connect/disconnect events, and file activity, while `insiders.csv` supplies scenario start/end windows. citeturn527412search13turn551540search0

## Evaluation contract

For each ground-truth r4.2 scenario window:

1. Identity stage = a `Logon` event for the ground-truth user.
2. Sensitive-data stage = file activity after the login.
3. Exfiltration stage = file activity occurring while the same user/PC has an active removable-device connection.
4. Every transition must preserve chronology and stay within the 30-minute reconstruction window.

This intentionally uses a **CERT-specific exfiltration proxy** rather than claiming that every file event is malicious exfiltration.

Metrics:

- identity-stage recall;
- sensitive-stage recall;
- exfil-stage recall;
- complete ordered-chain recall;
- sampled benign ordered-chain rate.

## Data availability

The official CERT raw archive is several GB and is not included in public Git repositories. Public CERT implementations consistently instruct users to obtain r4.2 and the separate answers archive from Carnegie Mellon. citeturn527412search0turn105977search0

Therefore this gate is **opt-in/local** until the raw artifact is available. No synthetic substitution is permitted.

## Phase 8 pass condition

The raw gate can be marked passed only when:

- all four source files are present;
- all malicious scenarios have been parsed;
- stage recalls are computed;
- ordered-chain recall is computed;
- benign-chain sampling is reported;
- the results are reviewed against the evidence contract.

The compact Zenodo derivative alone cannot satisfy this gate.
