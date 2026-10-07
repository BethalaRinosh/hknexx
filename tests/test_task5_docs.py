from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_readme_documents_current_cli_pipeline():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "backend/cli.py" in readme
    assert "python -m backend.cli analyze" in readme
    assert "normalized.jsonl" in readme
    assert "enriched.jsonl" in readme
    assert "incidents.json" in readme
    assert "run_summary.json" in readme


def test_readme_documents_upload_endpoint_and_schema():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "POST /api/analyze/upload" in readme
    assert "config/schema.yml" in readme
    assert "JSONL" in readme
    assert "Sysmon" in readme
    assert "Zeek" in readme


def test_readme_documents_cert_diagnostic_contract():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for label in (
        "compatible",
        "missing_identity",
        "missing_sensitive_access",
        "missing_exfiltration",
    ):
        assert label in readme
    assert "project-specific proxy evaluation" in readme


def test_readme_documents_reproduction_commands():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "make demo" in readme
    assert "make reproduce" in readme
    assert "python -m pytest -q" in readme
