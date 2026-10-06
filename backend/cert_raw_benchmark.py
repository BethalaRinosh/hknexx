from __future__ import annotations

import csv
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path


CHAIN_WINDOW = timedelta(minutes=30)
DATASET_VERSION = "4.2"


@dataclass(frozen=True)
class ScenarioWindow:
    user: str
    start: datetime
    end: datetime
    scenario: str
    details: str


@dataclass(frozen=True)
class CERTEvent:
    user: str
    pc: str
    timestamp: datetime
    source: str
    activity: str
    resource: str = ""


@dataclass(frozen=True)
class RawCERTCaseResult:
    user: str
    scenario: str
    stage_identity: bool
    stage_sensitive: bool
    stage_exfil: bool
    ordered_chain: bool
    first_event_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class RawCERTBenchmarkResult:
    malicious_scenarios: int
    compatible_malicious_scenarios: int
    compatibility_rate: float
    complete_malicious_scenarios: int
    ordered_malicious_scenarios: int
    identity_recall: float
    sensitive_recall: float
    exfil_recall: float
    ordered_chain_recall: float
    compatible_ordered_chain_recall: float
    benign_windows_sampled: int
    benign_ordered_chains: int
    benign_chain_rate: float
    status: str
    reason: str


def _norm(value: str | None) -> str:
    return (value or "").strip()


def _parse_datetime(value: str) -> datetime:
    for fmt in (
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
    ):
        try:
            return datetime.strptime(_norm(value), fmt)
        except ValueError:
            continue
    return datetime.fromisoformat(_norm(value).replace("Z", "+00:00"))


def _csv_dicts(path: Path):
    with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        yield from csv.DictReader(handle)


def load_scenarios(answers_path: Path) -> list[ScenarioWindow]:
    scenarios: list[ScenarioWindow] = []
    for row in _csv_dicts(answers_path):
        dataset = _norm(row.get("dataset"))
        if dataset not in {DATASET_VERSION, f"{DATASET_VERSION}.0"}:
            continue
        user = _norm(row.get("user"))
        start = _parse_datetime(row.get("start", ""))
        end = _parse_datetime(row.get("end", ""))
        if not user or end < start:
            continue
        scenarios.append(
            ScenarioWindow(
                user=user,
                start=start,
                end=end,
                scenario=_norm(row.get("scenario")) or "unknown",
                details=_norm(row.get("details")),
            )
        )
    return scenarios


def load_events(path: Path, source: str) -> list[CERTEvent]:
    events: list[CERTEvent] = []
    for row in _csv_dicts(path):
        user = _norm(row.get("user"))
        timestamp_value = row.get("date") or row.get("timestamp") or ""
        if not user or not timestamp_value:
            continue
        timestamp = _parse_datetime(timestamp_value)
        pc = _norm(row.get("pc"))
        activity = _norm(row.get("activity"))
        resource = _norm(row.get("filename") or row.get("resource"))
        events.append(
            CERTEvent(
                user=user,
                pc=pc,
                timestamp=timestamp,
                source=source,
                activity=activity,
                resource=resource,
            )
        )
    return sorted(events, key=lambda event: (event.user, event.timestamp, event.pc))


def _within(start: datetime, end: datetime, value: datetime) -> bool:
    return start <= value <= end


def _case_chain(window: ScenarioWindow, events: list[CERTEvent]) -> RawCERTCaseResult:
    scoped = [
        event
        for event in events
        if event.user == window.user and _within(window.start, window.end, event.timestamp)
    ]

    logons = [
        event for event in scoped
        if event.source == "logon" and event.activity.lower() == "logon"
    ]
    files = [event for event in scoped if event.source == "file"]
    devices = [event for event in scoped if event.source == "device"]

    identity = logons[0] if logons else None
    sensitive = None
    exfil = None

    if identity:
        for event in files:
            if event.timestamp >= identity.timestamp and event.timestamp - identity.timestamp <= CHAIN_WINDOW:
                sensitive = event
                break

    if sensitive:
        connects_by_pc: dict[str, list[CERTEvent]] = {}
        for device in devices:
            connects_by_pc.setdefault(device.pc, []).append(device)

        for event in files:
            if event.timestamp < sensitive.timestamp:
                continue
            if event.timestamp - sensitive.timestamp > CHAIN_WINDOW:
                break

            for device in connects_by_pc.get(event.pc, []):
                if device.activity.lower() != "connect":
                    continue
                if device.timestamp <= event.timestamp <= device.timestamp + CHAIN_WINDOW:
                    exfil = event
                    break
            if exfil:
                break

    stage_identity = identity is not None
    stage_sensitive = sensitive is not None
    stage_exfil = exfil is not None
    ordered = stage_identity and stage_sensitive and stage_exfil

    evidence = tuple(
        event.timestamp.isoformat()
        for event in (identity, sensitive, exfil)
        if event is not None
    )

    return RawCERTCaseResult(
        user=window.user,
        scenario=window.scenario,
        stage_identity=stage_identity,
        stage_sensitive=stage_sensitive,
        stage_exfil=stage_exfil,
        ordered_chain=ordered,
        first_event_ids=evidence,
    )


def evaluate_raw_cert(
    data_dir: Path,
    benign_user_limit: int = 100,
) -> RawCERTBenchmarkResult:
    answers = data_dir / "insiders.csv"
    if not answers.exists():
        raise FileNotFoundError(f"Missing CERT ground truth: {answers}")

    for name in ("logon.csv", "device.csv", "file.csv"):
        if not (data_dir / name).exists():
            raise FileNotFoundError(f"Missing CERT source log: {data_dir / name}")

    scenarios = load_scenarios(answers)
    if not scenarios:
        raise ValueError("No CERT r4.2 malicious scenarios found in insiders.csv")

    relevant_users = {scenario.user for scenario in scenarios}
    logons = load_events(data_dir / "logon.csv", "logon")
    devices = load_events(data_dir / "device.csv", "device")
    files = load_events(data_dir / "file.csv", "file")

    all_event_pool = sorted(logons + devices + files, key=lambda event: (event.user, event.timestamp, event.pc))
    events_by_user: dict[str, list[CERTEvent]] = defaultdict(list)
    for event in all_event_pool:
        events_by_user[event.user].append(event)

    malicious_results = [
        _case_chain(scenario, events_by_user.get(scenario.user, []))
        for scenario in scenarios
    ]

    malicious_n = len(malicious_results)
    identity_hits = sum(item.stage_identity for item in malicious_results)
    sensitive_hits = sum(item.stage_sensitive for item in malicious_results)
    exfil_hits = sum(item.stage_exfil for item in malicious_results)
    ordered_hits = sum(item.ordered_chain for item in malicious_results)

    # Deterministic benign smoke sample: users absent from the malicious ground truth,
    # limited for tractable local runs. This is a sampled FP estimate, not a census.
    malicious_users = relevant_users
    benign_users = sorted(set(events_by_user) - malicious_users)[:benign_user_limit]
    benign_windows = []
    for user in benign_users:
        user_logons = [
            event
            for event in events_by_user[user]
            if event.source == "logon" and event.activity.lower() == "logon"
        ]
        for login in user_logons[:3]:
            benign_windows.append(
                ScenarioWindow(
                    user=user,
                    start=login.timestamp,
                    end=login.timestamp + CHAIN_WINDOW,
                    scenario="benign_sample",
                    details="sampled non-malicious user window",
                )
            )

    benign_results = [
        _case_chain(window, events_by_user.get(window.user, []))
        for window in benign_windows
    ]
    benign_chain_hits = sum(item.ordered_chain for item in benign_results)
    compatible_malicious = ordered_hits
    compatible_rate = round(compatible_malicious / malicious_n, 4)
    compatible_ordered_recall = (
        round(ordered_hits / compatible_malicious, 4) if compatible_malicious else 0.0
    )

    return RawCERTBenchmarkResult(
        malicious_scenarios=malicious_n,
        compatible_malicious_scenarios=compatible_malicious,
        compatibility_rate=compatible_rate,
        complete_malicious_scenarios=ordered_hits,
        ordered_malicious_scenarios=ordered_hits,
        identity_recall=round(identity_hits / malicious_n, 4),
        sensitive_recall=round(sensitive_hits / malicious_n, 4),
        exfil_recall=round(exfil_hits / malicious_n, 4),
        ordered_chain_recall=round(ordered_hits / malicious_n, 4),
        compatible_ordered_chain_recall=compatible_ordered_recall,
        benign_windows_sampled=len(benign_results),
        benign_ordered_chains=benign_chain_hits,
        benign_chain_rate=round(benign_chain_hits / len(benign_results), 4) if benign_results else 0.0,
        status="validated",
        reason=(
            "Raw CERT r4.2 source logs and insiders.csv were evaluated directly. "
            "Identity/sensitive/exfil/ordered values are project-specific proxy metrics across "
            "all malicious scenarios, while compatibility_rate reports how many malicious "
            "scenarios actually fit the project's removable-media chain semantics. "
            "compatible_ordered_chain_recall measures ordered-chain coverage within that compatible subset. "
            "The benign result is a sampled non-malicious-user window rate, not a census."
        ),
    )
