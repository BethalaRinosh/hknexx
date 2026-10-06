# CERT r4.2 Raw Data Acquisition

## Official source

Carnegie Mellon / Software Engineering Institute publishes the CERT Insider Threat Test Dataset and its answer key. The SEI dataset page points to DOI 10.1184/R1/12841247.v1, and the answer key contains malicious-scenario descriptions and identifiers. citeturn157831view1

A reproducible public CERT implementation documents the raw r4.2 archive as approximately 4.5 GB and identifies the required source files as `logon.csv`, `device.csv`, `file.csv`, plus the separate answers archive containing `insiders.csv`. citeturn337246search0turn337246search2

A public CERT feature-extraction implementation also references the SEI FTP endpoint:

```text
ftp://ftp.sei.cmu.edu/pub/cert-data/r4.2.tar.bz2
```

and downloads the public answer archive from:

```text
https://kilthub.cmu.edu/ndownloader/files/24857828
```

The answer archive is extracted to obtain `answers/insiders.csv`. citeturn846159search5turn636570search0

## Recommended local layout

Do not commit the raw dataset to Git.

```text
external/cert_raw/
  logon.csv
  device.csv
  file.csv
  insiders.csv
```

The full raw archive is large, so HTTP/FTP acquisition should happen outside normal Git pushes.

## Verify the files

```bash
python scripts/verify_cert_raw_layout.py --data-dir external/cert_raw
```

## Run the raw benchmark

```bash
python scripts/run_cert_raw_benchmark.py \
  --data-dir external/cert_raw \
  --json-out docs/results/phase8_cert_raw_result.json
```

## Important benchmark boundary

The raw benchmark is intentionally separate from the compact Zenodo compatibility sample.

The compact sample successfully downloaded in CI and contains 4,615 events, 64 cases, 20 malicious cases and 44 benign cases, but zero malicious cases contain the project's complete three-stage chain. That result is a compatibility finding, not end-to-end detector recall.

The raw benchmark is the only path that can produce a defensible chain-recall result because it preserves the multi-source CERT structure and scenario windows.

## Why this is not automated in normal CI

The official r4.2 raw archive is multi-gigabyte. Normal pull-request CI should not silently spend gigabytes of bandwidth for every commit.

Once the raw files are available in an approved runner/storage environment, the benchmark can be run explicitly and its JSON result committed as a reviewed artifact.

## Current status

`raw data acquisition: external`
`parser: implemented`
`raw benchmark: implemented`
`actual raw execution: pending`
`Phase 8 final gate: pending`
