import json
import subprocess
import sys
from pathlib import Path

from fastapi.testclient import TestClient


ROOT = Path(__file__).resolve().parents[1]


def test_cli_json_pipeline_writes_required_artifacts(tmp_path):
    source = tmp_path / "events.json"
    source.write_text(
        json.dumps([
            {
                "id": "CLI-1",
                "timestamp": "2026-10-07T09:00:00Z",
                "type": "authentication",
                "username": "alice",
                "hostname": "WS-1",
                "source_ip": "185.10.10.10",
                "log_source": "auth",
            },
            {
                "id": "CLI-2",
                "timestamp": "2026-10-07T09:04:00Z",
                "type": "file_read",
                "username": "alice",
                "hostname": "WS-1",
                "path": "/finance/report.pdf",
                "log_source": "files",
            },
        ]),
        encoding="utf-8",
    )
    out = tmp_path / "out"

    result = subprocess.run(
        [sys.executable, "-m", "backend.cli", "analyze", str(source), "--out", str(out)],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    for name in ("normalized.jsonl", "enriched.jsonl", "incidents.json", "report.md", "run_summary.json"):
        assert (out / name).exists(), name


def test_cli_unknown_schema_fails_with_columns_and_expected_fields(tmp_path):
    source = tmp_path / "events.csv"
    source.write_text("when,who,where\n2026-10-07T09:00:00Z,alice,WS-1\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "backend.cli",
            "analyze",
            str(source),
            "--out",
            str(tmp_path / "out"),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    message = result.stderr + result.stdout
    assert "when" in message
    assert "timestamp" in message
    assert "event_type" in message


def test_upload_endpoint_uses_file_pipeline(tmp_path):
    from backend.main import app

    client = TestClient(app)
    response = client.post(
        "/api/analyze/upload",
        files={
            "file": (
                "events.json",
                json.dumps([
                    {
                        "id": "UPLOAD-1",
                        "timestamp": "2026-10-07T09:00:00Z",
                        "type": "authentication",
                        "username": "alice",
                        "hostname": "WS-1",
                        "source_ip": "185.10.10.10",
                        "log_source": "auth",
                    }
                ]),
                "application/json",
            )
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["total_events"] == 1
