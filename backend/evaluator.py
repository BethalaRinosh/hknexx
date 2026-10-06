from __future__ import annotations

import json
from pathlib import Path

from .detector import analyze
from .models import EvaluationCase, Phase2Report


ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"


def _load_scenarios() -> dict:
    with (DATA / "scenarios.json").open("r", encoding="utf-8") as f:
        return json.load(f)


def _load_manifest() -> dict[str, str]:
    with (DATA / "phase2_manifest.json").open("r", encoding="utf-8") as f:
        return json.load(f)


def _load_events(items: list[dict]):
    from .models import SecurityEvent

    return [SecurityEvent.model_validate(item) for item in items]


def _actual(result) -> str:
    if result.correlated_incidents > 0:
        return "validated"
    if result.watchlist_candidates > 0:
        return "watchlist"
    return "suppressed"


def _reason(expected: str, actual: str) -> str:
    if expected == actual:
        return "Expected disposition matched detector disposition."
    return f"Expected {expected}, detector produced {actual}."


def run_phase2() -> Phase2Report:
    scenarios = _load_scenarios()
    manifest = _load_manifest()
    cases: list[EvaluationCase] = []

    for name, expected in manifest.items():
        if name not in scenarios:
            cases.append(
                EvaluationCase(
                    scenario=name,
                    expected=expected,
                    actual="suppressed",
                    passed=False,
                    incidents=0,
                    watchlist_candidates=0,
                    suspicious_events=0,
                    reason="Scenario listed in manifest is missing.",
                )
            )
            continue

        result = analyze(_load_events(scenarios[name]))
        actual = _actual(result)
        cases.append(
            EvaluationCase(
                scenario=name,
                expected=expected,
                actual=actual,
                passed=expected == actual,
                incidents=result.correlated_incidents,
                watchlist_candidates=result.watchlist_candidates,
                suspicious_events=result.suspicious_events,
                reason=_reason(expected, actual),
            )
        )

    passed = sum(1 for case in cases if case.passed)
    validated_cases = sum(1 for case in cases if case.actual == "validated")
    false_positive_cases = sum(
        1 for case in cases
        if case.expected != "validated" and case.actual == "validated"
    )
    missed_attack_cases = sum(
        1 for case in cases
        if case.expected == "validated" and case.actual != "validated"
    )
    watchlist_cases = sum(1 for case in cases if case.actual == "watchlist")

    accuracy = round(passed / len(cases), 3) if cases else 1.0

    return Phase2Report(
        total_cases=len(cases),
        passed_cases=passed,
        failed_cases=len(cases) - passed,
        accuracy=accuracy,
        validated_cases=validated_cases,
        false_positive_cases=false_positive_cases,
        missed_attack_cases=missed_attack_cases,
        watchlist_cases=watchlist_cases,
        cases=cases,
    )
