# Phase 8 — Raw CERT r4.2 Gate

## Outcome

**Raw-data acquisition and benchmark execution: PASS.**

The gate was executed on the real CERT r4.2 source layout: logon.csv, device.csv, file.csv, and the official CMU/CERT insiders.csv answer-key data.

The CMU Software Engineering Institute describes the CERT Insider Threat Test Dataset as synthetic background plus malicious-actor data, and states that answers.tar.bz2 contains the malicious scenarios and the synthetic users involved. See: https://www.sei.cmu.edu/library/insider-threat-test-dataset/

The raw log CSVs were acquired from a public mirror of the CERT r4.2 files because the historical CMU FTP hostname was not resolvable from the GitHub Actions runner. The answer key was downloaded from the CMU/KiltHub artifact endpoint.

## Raw data verified

| File | Rows | Approx. size |
|---|---:|---:|
| logon.csv | 854,859 | 58.5 MB |
| device.csv | 405,380 | 29.0 MB |
| file.csv | 445,581 | 193.1 MB |
| insiders.csv | 190 data rows | 13.8 KB |

The answer key contains 70 r4.2 malicious scenario rows.

## Benchmark contract

The benchmark intentionally uses a project-specific compatibility proxy, not a claim of full CERT attack detection.

For each malicious scenario window:

1. Identity = a Logon event for the ground-truth user.
2. Sensitive-data proxy = file activity after the login.
3. Exfiltration proxy = file activity occurring while the same user/PC has an active removable-device Connect event.
4. Ordered chain = all three in chronological order.

This mirrors the project's MVP chain semantics. It does not label every CERT file event as sensitive or every device event as malicious.

## Final result

| Metric | Result |
|---|---:|
| Malicious scenarios evaluated | 70 |
| Project-compatible malicious scenarios | 3 / 70 |
| Compatibility rate | **4.29%** |
| Identity-stage proxy recall | **100.00%** |
| Sensitive-stage proxy recall | **5.71%** |
| Exfil-stage proxy recall | **4.29%** |
| Ordered-chain proxy recall | **4.29%** |
| Ordered-chain recall within compatible subset | **100.00%** |
| Benign windows sampled | 300 |
| Benign proxy-chain windows | 7 |
| Benign proxy-chain rate | **2.33%** |

### Correct interpretation

The most important number is **4.29% compatibility coverage**, not 4.29% detector accuracy.

Only 3 of the 70 malicious CERT scenario windows contain the exact semantic pattern represented by this MVP benchmark: identity anomaly → file activity → removable-media transfer context.

Therefore:

- the raw dataset gate is complete;
- the parser/integrity path is exercised on real data;
- the project-specific chain works on all 3 compatible malicious cases;
- the benchmark exposes that the current MVP chain does not represent most CERT malicious scenarios;
- the 2.33% benign proxy-chain rate shows that the proxy itself is not a standalone maliciousness label.

This is a coverage limitation, not a justification to inflate the score.

## Validation performed

The successful GitHub Actions raw gate completed all of:

- raw source acquisition;
- semantic CSV schema verification;
- official answer-key acquisition;
- raw layout verification;
- raw benchmark;
- raw benchmark unit tests;
- complete repository regression suite;
- benchmark result artifact upload.

Raw benchmark workflow run: 37516637334.

## Boundary

No raw CERT files are committed to Git.

The checked-in result is a reproducible benchmark specification and result summary. The workflow re-acquires the source artifacts when explicitly dispatched.

## Next engineering implication

The benchmark proves that the MVP is correctly exercised on compatible CERT chains, but it also identifies the next research gap: expand the normalized evidence model and detection stages so that additional CERT behaviors—especially non-removable-media collection/exfiltration patterns—can be represented without weakening the evidence-first contract.