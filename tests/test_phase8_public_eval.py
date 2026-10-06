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
    result = evaluate_public_dataset(spec)
    assert result.available is True
    assert result.status == 'validated'
    assert result.total_records == 2
    assert result.normalized_events == 2
    assert result.parse_errors == 0
    assert result.normalization_errors == 0
    assert result.observed_techniques == ['T1222.001']
