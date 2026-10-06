from __future__ import annotations

import argparse
from pathlib import Path


REQUIRED = (
    "logon.csv",
    "device.csv",
    "file.csv",
    "insiders.csv",
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify raw CERT r4.2 benchmark layout.")
    parser.add_argument("--data-dir", type=Path, required=True)
    args = parser.parse_args()

    missing = [name for name in REQUIRED if not (args.data_dir / name).is_file()]
    if missing:
        print("Missing required CERT files:")
        for name in missing:
            print(f"  - {name}")
        return 2

    sizes = {name: (args.data_dir / name).stat().st_size for name in REQUIRED}
    for name, size in sizes.items():
        if size <= 0:
            print(f"ERROR: {name} is empty")
            return 3

    print("CERT raw layout OK")
    for name, size in sizes.items():
        print(f"  {name}: {size:,} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
