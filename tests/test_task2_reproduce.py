import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_make_reproduce_matches_checked_in_expected_summaries():
    result = subprocess.run(["make", "demo"], cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr

    for name in ("attack", "clean"):
        actual = json.loads((ROOT / "out" / "demo" / name / "run_summary.json").read_text(encoding="utf-8"))
        expected = json.loads(
            (ROOT / "data" / "sample" / "expected" / f"{name}.run_summary.json").read_text(encoding="utf-8")
        )
        assert actual["counts"] == expected["counts"]
