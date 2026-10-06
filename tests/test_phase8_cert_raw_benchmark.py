from pathlib import Path

from backend.cert_raw_benchmark import evaluate_raw_cert


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def test_raw_cert_three_stage_chain(tmp_path):
    _write(
        tmp_path / "insiders.csv",
        "dataset,scenario,details,user,start,end\n"
        "4.2,1,test,U1,01/01/2026 09:00:00,01/01/2026 09:20:00\n",
    )
    _write(
        tmp_path / "logon.csv",
        "user,pc,date,activity\n"
        "U1,PC1,01/01/2026 09:00:00,Logon\n",
    )
    _write(
        tmp_path / "device.csv",
        "user,pc,date,activity\n"
        "U1,PC1,01/01/2026 09:07:00,Connect\n",
    )
    _write(
        tmp_path / "file.csv",
        "user,pc,date,filename\n"
        "U1,PC1,01/01/2026 09:05:00,secret.txt\n"
        "U1,PC1,01/01/2026 09:10:00,secret.txt\n",
    )

    result = evaluate_raw_cert(tmp_path)
    assert result.malicious_scenarios == 1
    assert result.identity_recall == 1.0
    assert result.sensitive_recall == 1.0
    assert result.exfil_recall == 1.0
    assert result.ordered_chain_recall == 1.0


def test_raw_cert_missing_stage(tmp_path):
    _write(
        tmp_path / "insiders.csv",
        "dataset,scenario,details,user,start,end\n"
        "4.2,1,test,U1,01/01/2026 09:00:00,01/01/2026 09:20:00\n",
    )
    _write(
        tmp_path / "logon.csv",
        "user,pc,date,activity\n"
        "U1,PC1,01/01/2026 09:00:00,Logon\n",
    )
    _write(
        tmp_path / "device.csv",
        "user,pc,date,activity\n"
        "U1,PC1,01/01/2026 09:07:00,Connect\n",
    )
    _write(
        tmp_path / "file.csv",
        "user,pc,date,filename\n"
        "U1,PC1,01/01/2026 10:00:00,secret.txt\n",
    )

    result = evaluate_raw_cert(tmp_path)
    assert result.sensitive_recall == 0.0
    assert result.exfil_recall == 0.0
    assert result.ordered_chain_recall == 0.0
