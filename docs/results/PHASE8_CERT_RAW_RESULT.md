# Phase 8 — Raw CERT r4.2 Gate Result

## Outcome

**PASS — actual raw CERT r4.2 files were downloaded, verified, processed, benchmarked, and archived by CI.**

The canonical provenance is the CMU/SEI CERT Insider Threat Test Dataset r4.2 (DOI 10.1184/R1/12841247.v1). The execution mirror was the public Kaggle dataset `andrihjonior/cert-insider-threat-dataset-r4-2`.

## Raw corpus

| File | Rows | Bytes |
|---|---:|---:|
| logon.csv | 854,859 | 58,514,706 |
| device.csv | 405,380 | 28,982,749 |
| file.csv | 445,581 | 193,055,265 |
| insiders.csv | 191 data rows | 13,792 |

The r4.2 answer file contains 70 malicious scenario rows for dataset 4.2.

## Measured benchmark

| Metric | Result |
|---|---:|
| Malicious scenarios | 70 |
| Project-compatible scenarios | 3 |
| Compatibility rate | 4.29% |
| Identity-stage proxy recall | 100.00% |
| Sensitive-stage proxy recall | 5.71% |
| Exfil-stage proxy recall | 4.29% |
| Ordered-chain proxy recall | 4.29% |
| Compatible ordered-chain recall | 100.00% |
| Benign sampled windows | 300 |
| Benign proxy-chain windows | 7 |
| Benign proxy-chain rate | 2.33% |

## Correct interpretation

This is **not** a claim that our detector has 4.29% CERT recall.

CERT r4.2 does not directly provide the same `src_ip`, `new_device`, and sensitive-resource semantics used by the MVP detector. The benchmark therefore asks a narrower, defensible question:

> How many real CERT malicious scenario windows can be represented by our current identity → file activity → removable-media evidence contract?

Answer: **3/70 (4.29%)**.

All three compatible windows satisfy the ordered proxy chain.

## CI evidence

Workflow run: **37574902964**  
Artifact: **phase8-cert-raw-result**  
Artifact ID: **11462541036**

The machine-readable result is in `docs/results/phase8_cert_raw_result.json`.
