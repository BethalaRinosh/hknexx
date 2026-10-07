# Phase 8 — Raw CERT r4.2 Chain Gate

## Status

**PASS: raw CERT r4.2 acquisition, exact corpus verification, benchmark execution, and result artifact publication completed successfully.**

Canonical source: CERT Insider Threat Test Dataset r4.2, Carnegie Mellon University / Software Engineering Institute, DOI 10.1184/R1/12841247.v1.

The GitHub Actions runner executed the benchmark against a public mirror of the raw r4.2 corpus because the historical CMU FTP hostname was not resolvable from the runner. The mirror exposed the raw source files and answer key used for this execution. Published CERT r4.2 statistics independently match the downloaded row counts.

## Raw source verification

| File | Verified rows |
|---|---:|
| logon.csv | 854,859 |
| device.csv | 405,380 |
| file.csv | 445,581 |
| insiders.csv | 191 data rows |
| r4.2 malicious scenario rows | 70 |

The downloaded counts match independently published CERT r4.2 statistics for logon, device and file activity.

## Evaluation contract

For each r4.2 malicious scenario window:

1. Identity = a Logon event for the ground-truth user.
2. Sensitive-data proxy = file activity after the login.
3. Exfiltration proxy = file activity while the same user/PC has an active removable-device Connect event.
4. Ordered chain = all three chronologically within the 30-minute reconstruction window.

This is a **project-specific raw-data compatibility proxy**. It is not end-to-end detector recall because CERT does not directly encode the project's `src_ip`, `new_device`, or sensitive-resource metadata semantics.

## Final benchmark

| Metric | Result |
|---|---:|
| Malicious scenarios | 70 |
| Project-compatible scenarios | 3 |
| Compatibility rate | 4.29% |
| Identity-stage proxy recall | 100.00% |
| Sensitive-stage proxy recall | 5.71% |
| Exfil-stage proxy recall | 4.29% |
| Ordered-chain proxy recall | 4.29% |
| Ordered-chain recall within compatible subset | 100.00% |
| Benign windows sampled | 300 |
| Benign proxy-chain windows | 7 |
| Benign proxy-chain rate | 2.33% |

## Interpretation

The **4.29% ordered-chain value must not be presented as detector recall**.

It means only 3 of the 70 r4.2 malicious scenario windows are directly compatible with the MVP's current removable-media evidence contract. All 3 compatible cases satisfy the required temporal ordering.

The sampled benign proxy-chain rate is 2.33%, which is also not a campaign false-positive rate.

This result therefore closes the **raw-data execution gate** while exposing a real **coverage boundary** in the current MVP threat model.

## CI evidence

- Raw execution workflow run: **37574902964**
- Raw result artifact: **phase8-cert-raw-result**
- Artifact ID: **11462541036**
- Checked-in result: `docs/results/phase8_cert_raw_result.json`

## Engineering decision

Do not weaken the detector to manufacture CERT compatibility.

The next coverage evolution should add source-specific normalization/evidence mappings for additional CERT threat scenarios while preserving the evidence-first attack contract.
