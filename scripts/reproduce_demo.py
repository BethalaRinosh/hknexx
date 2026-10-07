from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "out" / "demo"


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> int:
    shutil.rmtree(OUT, ignore_errors=True)
    (OUT / "attack").mkdir(parents=True, exist_ok=True)
    (OUT / "clean").mkdir(parents=True, exist_ok=True)

    for name in ("attack", "clean"):
        run([
            sys.executable,
            "-m",
            "backend.cli",
            "analyze",
            f"data/sample/{name}.json",
            "--out",
            str(OUT / name),
            "--config",
            "config/rules.yml",
        ])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
