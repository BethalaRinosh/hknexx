# Phase 8 CERT Public Benchmark Result

## Executed public sample

Source: Zenodo record 19135764, file `cert_preprocessed_ml_comparison.csv`.

The CI run successfully downloaded and parsed the public file.

Observed result:

| Metric | Result |
|---|---:|
| Events | 4,615 |
| Cases | 64 |
| Malicious cases | 20 |
| Benign cases | 44 |
| Malicious cases with all 3 project stages | 0 |
| Ordered malicious chains | 0 |
| Ordered benign chains | 0 |

## Interpretation

This is **not** a 0% detector recall claim.

The zero is a **dataset compatibility result**: the compact public derivative does not preserve a malicious trace containing all three stages required by this project's current evidence contract.

Therefore the sample is valid for:

- public-data download reproducibility;
- schema/format validation;
- event-trace parser testing.

It is not valid for claiming:

- end-to-end attack-chain recall;
- reconstruction recall;
- false-positive campaign rate for the three-stage chain.

The raw CERT gate remains open until the original multi-source r4.2 logs and ground-truth scenario windows are available.

Source documentation for CERT r4.2 confirms the underlying dataset has logon, device, file and other enterprise activity logs and scenario ground truth. citeturn527412search13turn551540search0
