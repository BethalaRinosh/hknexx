# Phase 8 — Raw CERT r4.2 Chain Gate

## Status

**PASS: raw CERT acquisition, parsing, benchmark execution, unit tests, and full regression completed successfully.**

The successful raw gate used:

- logon.csv
- device.csv
- file.csv
- insiders.csv from the CERT/CMU answer key

The CMU Software Engineering Institute documents the CERT Insider Threat Test Dataset and states that the answer key contains malicious-activity scenario descriptions and the synthetic users involved:
https://www.sei.cmu.edu/library/insider-threat-test-dataset/

The raw event CSVs were obtained from a public mirror of the CERT r4.2 files because the historical CMU FTP hostname was not resolvable from the GitHub Actions runner. The answer key was downloaded from the CMU/KiltHub artifact endpoint.

## Raw source verification

- logon.csv: 854,859 rows
- device.csv: 405,380 rows
- file.csv: 445,581 rows
- insiders.csv: 190 data rows
- r4.2 malicious scenario rows in insiders.csv: 70

The workflow verifies CSV headers semantically before the benchmark runs.

## Evaluation contract

For each r4.2 malicious scenario window:

1. Identity = a Logon event for the ground-truth user.
2. Sensitive-data proxy = file activity after the login.
3. Exfiltration proxy = file activity while the same user/PC has an active removable-device Connect event.
4. Ordered chain = all three chronologically.

This is a **project-specific compatibility proxy**. It is not a claim that every CERT malicious scenario is represented by the MVP chain, and it is not overall CERT detector recall.

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

### Interpretation

The **4.29% value is semantic compatibility coverage**, not detector accuracy.

Only 3 of the 70 malicious CERT scenario windows match the current MVP's exact identity → file activity → removable-media semantics. All 3 compatible cases satisfy the ordered proxy chain.

The sampled benign rate of 2.33% also shows why the proxy must not be presented as a standalone maliciousness classifier.

The benchmark therefore passes the **raw-data validation gate** while exposing a real **coverage limitation** in the current MVP threat model.

## Validation evidence

Successful raw workflow run:

- Run ID: 37516637334
- All workflow steps: PASS
- Raw benchmark tests: PASS
- Full regression suite: PASS
- Result artifact uploaded by GitHub Actions

The exact result is checked into:

docs/results/PHASE8_CERT_RAW_RESULT.md
docs/results/phase8_cert_raw_result.json

## Gate boundary

Raw CERT files are not committed to Git.

The workflow re-acquires the source artifacts when explicitly dispatched. The checked-in artifacts contain the reproducible benchmark definition and reviewed results only.

## Engineering implication

The next coverage task is to extend the normalized evidence model beyond the removable-media chain so that other CERT malicious behaviors can be represented without weakening the evidence-first contract.
