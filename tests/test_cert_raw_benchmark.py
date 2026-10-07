from pathlib import Path

from backend.cert_raw_benchmark import evaluate_raw_cert


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def _base_dataset(tmp_path: Path, file_rows: str) -> None:
    _write(
        tmp_path / "insiders.csv",
        "dataset,scenario,details,user,start,end\n"
        "4.2,1,test,U1,01/01/2026 09:00:00,01/01/2026 09:20:00\n"
        "4.2,2,test,U2,01/01/2026 10:00:00,01/01/2026 10:20:00\n"
        "4.2,3,test,U3,01/01/2026 11:00:00,01/01/2026 11:20:00\n",
    )
    _write(
        tmp_path / "logon.csv",
        "user,pc,date,activity\n"
        "U1,PC1,01/01/2026 09:00:00,Logon\n"
        "U2,PC2,01/01/2026 10:00:00,Logon\n"
        "U3,PC3,01/01/2026 11:00:00,Logon\n"
        "BENIGN,PC9,01/01/2026 12:00:00,Logon\n",
    )
    _write(
        tmp_path / "device.csv",
        "user,pc,date,activity\n"
        "U1,PC1,01/01/2026 09:07:00,Connect\n"
        "U2,PC2,01/01/2026 10:07:00,Connect\n",
    )
    _write(tmp_path / "file.csv", "user,pc,date,filename\n" + file_rows)


def test_raw_cert_reports_per_scenario_compatibility_class(tmp_path):
    _base_dataset(
        tmp_path,
        "U1,PC1,01/01/2026 09:05:00,secret.txt\n"
        "U1,PC1,01/01/2026 09:10:00,secret.txt\n"
        "U2,PC2,01/01/2026 10:05:00,secret.txt\n"
        "U3,PC3,01/01/2026 11:05:00,secret.txt\n",
    )

    result = evaluate_raw_cert(tmp_path)

    assert [item.compatibility_class for item in result.scenario_results] == [
        "compatible",
        "missing_exfiltration",
        "missing_exfiltration",
    ]
    assert result.compatibility_breakdown == {
        "compatible": 1,
        "missing_exfiltration": 2,
    }


def test_raw_cert_classifies_missing_identity_without_inflating_compatibility(tmp_path):
    _base_dataset(
        tmp_path,
        "U1,PC1,01/01/2026 09:05:00,secret.txt\n"
        "U1,PC1,01/01/2026 09:10:00,secret.txt\n"
        "U2,PC2,01/01/2026 10:05:00,secret.txt\n"
        "U3,PC3,01/01/2026 11:05:00,secret.txt\n",
    )
    (tmp_path / "logon.csv").write_text(
        "user,pc,date,activity\n"
        "U1,PC1,01/01/2026 09:00:00,Logout\n"
        "U2,PC2,01/01/2026 10:00:00,Logout\n"
        "U3,PC3,01/01/2026 11:00:00,Logout\n",
        encoding="utf-8",
    )

    result = evaluate_raw_cert(tmp_path)

    assert all(item.compatibility_class == "missing_identity" for item in result.scenario_results)
    assert result.compatible_malicious_scenarios == 0
    assert result.compatibility_breakdown == {"missing_identity": 3}
