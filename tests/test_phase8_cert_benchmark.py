from pathlib import Path
from backend.cert_benchmark import evaluate_cert


def test_cert_benchmark_orders_three_stage_case(tmp_path):
    path = tmp_path / "cert.csv"
    path.write_text(
        "case_id,activity,resource,timestamp,label\n"
        "u1,logon,WS1,2026-01-01T09:00:00+00:00,anomalous\n"
        "u1,file_access,secret.docx,2026-01-01T09:05:00+00:00,anomalous\n"
        "u1,copy_to_usb,USB01,2026-01-01T09:10:00+00:00,anomalous\n"
        "u2,logon,WS2,2026-01-01T09:00:00+00:00,normal\n"
        "u2,file_access,notes.txt,2026-01-01T09:05:00+00:00,normal\n"
        "u2,copy_to_usb,USB02,2026-01-01T09:10:00+00:00,normal\n",
        encoding="utf-8",
    )
    result = evaluate_cert(path)
    assert result.total_events == 6
    assert result.total_cases == 2
    assert result.compatible_malicious_cases == 1
    assert result.detected_ordered_malicious_cases == 1
    assert result.malicious_stage_recall == 1.0
    assert result.benign_ordered_chain_cases == 1
    assert result.benign_chain_rate == 1.0


def test_cert_benchmark_marks_reversed_chain_as_not_ordered(tmp_path):
    path = tmp_path / "cert.csv"
    path.write_text(
        "case_id,activity,resource,timestamp,label\n"
        "u1,copy_to_usb,USB01,2026-01-01T09:00:00+00:00,anomalous\n"
        "u1,file_access,secret.docx,2026-01-01T09:05:00+00:00,anomalous\n"
        "u1,logon,WS1,2026-01-01T09:10:00+00:00,anomalous\n",
        encoding="utf-8",
    )
    result = evaluate_cert(path)
    assert result.compatible_malicious_cases == 1
    assert result.detected_ordered_malicious_cases == 0
