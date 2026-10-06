from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path

from backend.cert_raw_benchmark import evaluate_raw_cert


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the raw CERT r4.2 chain benchmark.")
    parser.add_argument(
        "--data-dir",
        type=Path,
        required=True,
        help="Directory containing logon.csv, device.csv, file.csv, and insiders.csv.",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional JSON output path.",
    )
    parser.add_argument(
        "--benign-user-limit",
        type=int,
        default=100,
        help="Maximum number of benign users sampled for false-positive smoke testing.",
    )
    args = parser.parse_args()

    result = evaluate_raw_cert(args.data_dir, benign_user_limit=args.benign_user_limit)
    payload = asdict(result)
    print(json.dumps(payload, indent=2, default=str))

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, indent=2, default=str) + "\n", encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
