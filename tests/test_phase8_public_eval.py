import json
from pathlib import Path

from backend.public_eval import evaluate_public_dataset, load_manifest


ROOT = Path(__file__).resolve().parents[1]


def test_public_manifest_contains_reproducible_sources():
    manifest = load_manifest(ROOT / 'backend' / 'data' / 'public_dataset_manifest.json')
    ids = {item.dataset_id for item in manifest}
    assert 'ATLASV2_EDR' in ids
    assert 'OTRF_SDWIN_190301125905' in ids
    assert all(item.source_url.startswith('https://') for item in manifest)
    assert all(item.local_path_env.startswith('IMW_') for item in manifest)


def test_public_dataset_evaluator_fails_closed_when_artifact_is_missing(monkeypatch):
    monkeypatch.delenv('IMW_ATLASV2_PATH', raising=False)
    spec = next(item for item in load_manifest(ROOT / 'backend' / 'data' / 'public_dataset_manifest.json') if item.dataset_id == 'ATLASV2_EDR')
    result = evaluate_public_dataset(spec)
    assert result.available is False
    assert result.status == 'not_available'
    assert 'No synthetic fallback' in result.reason


def test_public_dataset_evaluator_normalizes_a_local_public_style_stream(tmp_path, monkeypatch):
    path = tmp_path / 'sample.jsonl'
    records = [
        {
            'id': 'PUB-001',
            '@timestamp': '2026-10-06T09:00:00Z',
            'type': 'authentication',
            'username': 'alice',
            'hostname': 'WS-01',
            'source_ip': '203.0.113.10',
            'log_source': 'public-test',
            'level': 'medium',
            'mitre_technique': 'T1222.001',
        },
        {
            'id': 'PUB-002',
            'timestamp': '2026-10-06T09:01:00Z',
            'event': 'file_read',
            'account': 'alice',
            'host': 'WS-01',
            'source': 'public-test',
            'severity': 'high',
            'mitre_technique': ['T1222.001'],
        },
    ]
    path.write_text('\n'.join(json.dumps(item) for item in records) + '\n', encoding='utf-8')
    monkeypatch.setenv('IMW_OTRF_SDWIN_PATH', str(path))
    spec = next(item for item in load_manifest(ROOT / 'backend' / 'data' / 'public_dataset_manifest.json') if item.dataset_id == 'OTRF_SDWIN_190301125905')
    from dataclasses import replace
    spec = replace(spec, format='jsonl')
    result = evaluate_public_dataset(spec)
    assert result.available is True
    assert result.status == 'validated'
    assert result.total_records == 2
    assert result.normalized_events == 2
    assert result.parse_errors == 0
    assert result.normalization_errors == 0
    assert result.observed_techniques == ['T1222.001']

def test_public_sysmon_xml_stream_normalizes_existing_xml_adapter(tmp_path, monkeypatch):
    path = tmp_path / "windows-sysmon.log"
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><TimeCreated SystemTime="2026-10-06T09:00:00.000Z"/><Computer>WS-01</Computer></System><EventData><Data Name="UtcTime">2026-10-06 09:00:00.000</Data><Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data><Data Name="User">alice</Data><Data Name="ProcessId">1234</Data><Data Name="ParentImage">C:\\Windows\\explorer.exe</Data></EventData></Event>"""
    path.write_text(xml + "\n" + xml.replace("<EventID>1</EventID>", "<EventID>3</EventID>"), encoding="utf-8")
    monkeypatch.setenv("IMW_SPLUNK_T1070_SYSMON_PATH", str(path))
    spec = next(
        item for item in load_manifest(ROOT / "backend" / "data" / "public_dataset_manifest.json")
        if item.dataset_id == "SPLUNK_ATTACK_DATA_T1070_SYSMON"
    )
    result = evaluate_public_dataset(spec)
    assert result.status == "validated"
    assert result.total_records == 2
    assert result.normalized_events == 2
    assert result.normalization_errors == 0
