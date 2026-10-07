from backend.adversarial import run_phase11


def test_phase11_adversarial_benchmark_passes():
    report = run_phase11()

    assert report.failed_cases == 0
    assert report.false_positives == 0
    assert report.precision == 1.0
    assert report.recall == 0.8
    assert report.false_positive_rate == 0.0
    assert report.false_negative_rate == 0.2


def test_phase11_tracks_hypotheses_separately_from_validated_incidents():
    report = run_phase11()
    missing = next(case for case in report.cases if case.scenario == "missing_telemetry")

    assert missing.ground_truth == "malicious"
    assert missing.actual == "watchlist"
    assert report.true_positives == 4
    assert report.false_negatives == 1
