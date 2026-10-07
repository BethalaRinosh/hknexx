from __future__ import annotations

import json
from pathlib import Path

from .detector import analyze
from .models import AdversarialCase, AdversarialReport, SecurityEvent


DATA = Path(__file__).resolve().parent / "data"


def _load(name: str) -> list[SecurityEvent]:
    with (DATA / "scenarios.json").open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    return [SecurityEvent.model_validate(item) for item in raw[name]]


def _actual(result) -> str:
    if result.correlated_incidents > 0:
        return "validated"
    if result.watchlist_candidates > 0:
        return "watchlist"
    return "suppressed"


def _case(
    name: str,
    ground_truth: str,
    expected: str,
    events: list[SecurityEvent],
) -> AdversarialCase:
    result = analyze(events)
    actual = _actual(result)
    return AdversarialCase(
        scenario=name,
        ground_truth=ground_truth,
        expected=expected,
        actual=actual,
        passed=expected == actual,
        incidents=result.correlated_incidents,
        watchlist_candidates=result.watchlist_candidates,
        reason=(
            "Expected disposition matched detector disposition."
            if expected == actual
            else f"Expected {expected}, detector produced {actual}."
        ),
    )


def _build_cases() -> list[AdversarialCase]:
    baseline = _load("full_attack")
    clean = _load("clean")

    noisy = baseline + clean
    out_of_order = list(reversed(baseline))

    decoy = baseline + [
        SecurityEvent(
            event_id="ADV-DECOY-001",
            timestamp="2026-10-06T09:16:30Z",
            event_type="file_access",
            user="decoy-user",
            device="DECOY-01",
            src_ip="10.99.0.10",
            application="FileServer",
            resource="/finance/payroll.xlsx",
            action="read",
            source="file_server",
            severity="high",
            metadata={"sensitive": True},
        )
    ]

    missing_telemetry = [
        event
        for event in baseline
        if event.event_id not in {"ATTACK-001", "ATTACK-002"}
    ]

    return [
        _case("baseline_attack", "malicious", "validated", baseline),
        _case("noisy_attack", "malicious", "validated", noisy),
        _case("out_of_order_input", "malicious", "validated", out_of_order),
        _case("decoy_attack", "malicious", "validated", decoy),
        _case("missing_telemetry", "malicious", "watchlist", missing_telemetry),
        _case("clean_control", "benign", "suppressed", clean),
        _case("reversed_order", "benign", "watchlist", _load("reversed_order")),
        _case("mismatched_entities", "benign", "suppressed", _load("mismatched_entities")),
        _case("shared_ip_collision", "benign", "watchlist", _load("shared_ip_collision")),
        _case("authorized_transfer", "benign", "suppressed", _load("authorized_transfer")),
        _case("benign_usb_lookalike", "benign", "suppressed", _load("authorized_transfer")),
        _case("benign_backup", "benign", "suppressed", _load("benign_backup")),
        _case(
            "legitimate_sensitive_access",
            "benign",
            "suppressed",
            _load("legitimate_sensitive_access"),
        ),
        _case("partial_attack", "benign", "watchlist", _load("partial_attack")),
    ]


def run_phase11() -> AdversarialReport:
    cases = _build_cases()

    malicious = [case for case in cases if case.ground_truth == "malicious"]
    benign = [case for case in cases if case.ground_truth == "benign"]

    true_positives = sum(
        case.ground_truth == "malicious" and case.actual == "validated"
        for case in cases
    )
    false_positives = sum(
        case.ground_truth == "benign" and case.actual == "validated"
        for case in cases
    )
    false_negatives = len(malicious) - true_positives
    true_negatives = len(benign) - false_positives

    precision = (
        true_positives / (true_positives + false_positives)
        if true_positives + false_positives
        else 1.0
    )
    recall = true_positives / len(malicious) if malicious else 1.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    false_positive_rate = false_positives / len(benign) if benign else 0.0
    false_negative_rate = false_negatives / len(malicious) if malicious else 0.0

    passed = sum(case.passed for case in cases)
    return AdversarialReport(
        total_cases=len(cases),
        passed_cases=passed,
        failed_cases=len(cases) - passed,
        true_positives=true_positives,
        false_positives=false_positives,
        true_negatives=true_negatives,
        false_negatives=false_negatives,
        precision=round(precision, 3),
        recall=round(recall, 3),
        f1=round(f1, 3),
        false_positive_rate=round(false_positive_rate, 3),
        false_negative_rate=round(false_negative_rate, 3),
        cases=cases,
    )


if __name__ == "__main__":
    print(run_phase11().model_dump_json(indent=2))
