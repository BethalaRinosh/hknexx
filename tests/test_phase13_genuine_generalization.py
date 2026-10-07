from __future__ import annotations

from datetime import datetime, timedelta, timezone

from backend.detector import analyze
from backend.models import SecurityEvent


BASE = datetime(2026, 10, 7, 9, 0, tzinfo=timezone.utc)


def event(
    event_id: str,
    minutes: int,
    event_type: str,
    *,
    user: str,
    device: str,
    src_ip: str,
    application: str,
    resource: str | None = None,
    action: str | None = None,
    severity: str = "medium",
    metadata: dict | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        event_id=event_id,
        timestamp=BASE + timedelta(minutes=minutes),
        event_type=event_type,
        user=user,
        device=device,
        src_ip=src_ip,
        application=application,
        resource=resource,
        action=action,
        source="generalization-fixture",
        severity=severity,
        metadata=metadata or {},
    )


def disposition(result) -> str:
    if result.correlated_incidents:
        return "validated"
    if result.campaign_hypotheses:
        return "hypothesis"
    if result.watchlist_candidates:
        return "watchlist"
    return "suppressed"


def family_new_device_no_login() -> list[SecurityEvent]:
    # Deliberately does not reuse the demo login -> enroll -> access shape.
    return [
        event(
            "GEN-A-01", 0, "device_enroll",
            user="nora", device="LAPTOP-441", src_ip="198.51.100.41",
            application="DeviceTrust", metadata={"new_device": True},
        ),
        event(
            "GEN-A-02", 9, "file_access",
            user="nora", device="LAPTOP-441", src_ip="198.51.100.41",
            application="DocsPortal", resource="/legal/merger-plan.docx",
            action="read", severity="high", metadata={"sensitive": True},
        ),
        event(
            "GEN-A-03", 13, "file_copy",
            user="nora", device="LAPTOP-441", src_ip="198.51.100.41",
            application="ArchiveTool", resource="/legal/merger-plan.docx",
            action="copy_to_usb", severity="critical",
            metadata={"bytes": 1_600_000_000, "destination": "REM-441"},
        ),
    ]


def family_login_copy_without_mount() -> list[SecurityEvent]:
    # Exfiltration is evidenced by the copy itself. No USB mount event is supplied.
    return [
        event(
            "GEN-B-01", 0, "login",
            user="omar", device="WS-882", src_ip="203.0.113.82",
            application="SSO-Gateway", metadata={"unusual_ip": True},
        ),
        event(
            "GEN-B-02", 4, "device_enroll",
            user="omar", device="WS-882", src_ip="203.0.113.82",
            application="MDM-Core", metadata={"new_device": True},
        ),
        event(
            "GEN-B-03", 8, "file_access",
            user="omar", device="WS-882", src_ip="203.0.113.82",
            application="RecordsAPI", resource="/customers/export.csv",
            action="read", severity="high", metadata={"sensitive": True},
        ),
        event(
            "GEN-B-04", 12, "file_copy",
            user="omar", device="WS-882", src_ip="203.0.113.82",
            application="TransferAgent", resource="/customers/export.csv",
            action="copy_to_removable", severity="critical",
            metadata={"bytes": 1_900_000_000, "destination": "EXT-882"},
        ),
    ]


def family_slow_campaign() -> list[SecurityEvent]:
    # Independently authored long-spacing campaign. Resource and identity continuity
    # are retained, while the stage spacing exceeds the normal 30-minute window.
    return [
        event(
            "GEN-C-01", 0, "login",
            user="priya", device="ENG-771", src_ip="198.51.100.71",
            application="AuthHub", metadata={"unusual_ip": True, "new_device": True},
        ),
        event(
            "GEN-C-02", 28, "file_access",
            user="priya", device="ENG-771", src_ip="198.51.100.71",
            application="KnowledgeStore", resource="/rnd/launch-plan.pdf",
            action="read", severity="high",
            metadata={"sensitive": True, "behavior_score": 0.75},
        ),
        event(
            "GEN-C-03", 54, "file_copy",
            user="priya", device="ENG-771", src_ip="198.51.100.71",
            application="FileManager", resource="/rnd/launch-plan.pdf",
            action="copy_to_removable", severity="critical",
            metadata={"bytes": 2_100_000_000, "destination": "MEDIA-771"},
        ),
    ]


def family_simultaneous_campaigns() -> list[SecurityEvent]:
    return [
        *[
            event(
                "GEN-D-A1", 0, "login",
                user="ravi", device="FIN-101", src_ip="198.51.100.101",
                application="CloudSSO", metadata={"unusual_ip": True, "new_device": True},
            ),
            event(
                "GEN-D-A2", 6, "file_access",
                user="ravi", device="FIN-101", src_ip="198.51.100.101",
                application="Ledger", resource="/finance/q4.xlsx",
                action="read", severity="high", metadata={"sensitive": True},
            ),
            event(
                "GEN-D-A3", 11, "file_copy",
                user="ravi", device="FIN-101", src_ip="198.51.100.101",
                application="CopyService", resource="/finance/q4.xlsx",
                action="copy_to_usb", severity="critical",
                metadata={"bytes": 1_500_000_000, "destination": "USB-F101"},
            ),
        ],
        *[
            event(
                "GEN-D-B1", 2, "login",
                user="sana", device="HR-202", src_ip="203.0.113.202",
                application="IdentityBroker", metadata={"unusual_ip": True, "new_device": True},
            ),
            event(
                "GEN-D-B2", 7, "file_access",
                user="sana", device="HR-202", src_ip="203.0.113.202",
                application="HRVault", resource="/hr/compensation.csv",
                action="read", severity="high", metadata={"sensitive": True},
            ),
            event(
                "GEN-D-B3", 14, "usb_mount",
                user="sana", device="HR-202", src_ip="203.0.113.202",
                application="DeviceControl", resource="MEDIA-H202",
                action="mount", severity="high", metadata={"removable": True},
            ),
            event(
                "GEN-D-B4", 15, "file_copy",
                user="sana", device="HR-202", src_ip="203.0.113.202",
                application="FileMover", resource="/hr/compensation.csv",
                action="copy_to_removable", severity="critical",
                metadata={"bytes": 1_700_000_000, "destination": "MEDIA-H202"},
            ),
        ],
    ]


def benign_authorized_workflow() -> list[SecurityEvent]:
    return [
        event(
            "BEN-A-01", 0, "login",
            user="ops-admin", device="OPS-9", src_ip="10.40.0.9",
            application="AdminSSO", metadata={"unusual_ip": True, "new_device": True, "authorized_activity": True},
        ),
        event(
            "BEN-A-02", 5, "file_access",
            user="ops-admin", device="OPS-9", src_ip="10.40.0.9",
            application="Records", resource="/finance/archive.zip",
            action="read", severity="high", metadata={"sensitive": True, "authorized_activity": True},
        ),
        event(
            "BEN-A-03", 9, "usb_mount",
            user="ops-admin", device="OPS-9", src_ip="10.40.0.9",
            application="DeviceControl", resource="APPROVED-USB",
            action="mount", metadata={"removable": True, "sanctioned_usb": True, "authorized_activity": True},
        ),
        event(
            "BEN-A-04", 10, "file_copy",
            user="ops-admin", device="OPS-9", src_ip="10.40.0.9",
            application="BackupTool", resource="/finance/archive.zip",
            action="copy_to_usb", severity="high",
            metadata={"bytes": 1_800_000_000, "destination": "APPROVED-USB", "approved_transfer": True},
        ),
    ]


def benign_identity_collision() -> list[SecurityEvent]:
    return [
        event(
            "BEN-B-01", 0, "login",
            user="user-one", device="LAP-1", src_ip="203.0.113.50",
            application="SSO", metadata={"unusual_ip": True, "new_device": True},
        ),
        event(
            "BEN-B-02", 4, "file_access",
            user="user-two", device="LAP-2", src_ip="203.0.113.50",
            application="Docs", resource="/finance/budget.xlsx",
            action="read", severity="high", metadata={"sensitive": True},
        ),
        event(
            "BEN-B-03", 8, "usb_mount",
            user="user-two", device="LAP-2", src_ip="203.0.113.50",
            application="DeviceControl", resource="USB-2",
            action="mount", metadata={"removable": True},
        ),
        event(
            "BEN-B-04", 9, "file_copy",
            user="user-two", device="LAP-2", src_ip="203.0.113.50",
            application="FileMover", resource="/finance/budget.xlsx",
            action="copy_to_usb", severity="critical",
            metadata={"bytes": 1_400_000_000, "destination": "USB-2"},
        ),
    ]


def benign_large_backup() -> list[SecurityEvent]:
    return [
        event(
            "BEN-C-01", 0, "login",
            user="backup-agent", device="BKP-3", src_ip="10.50.0.3",
            application="ServiceAuth", metadata={"unusual_ip": False, "new_device": False},
        ),
        event(
            "BEN-C-02", 6, "file_access",
            user="backup-agent", device="BKP-3", src_ip="10.50.0.3",
            application="ArchiveFS", resource="/finance/",
            action="read", metadata={"sensitive": True, "authorized_activity": True},
        ),
        event(
            "BEN-C-03", 12, "file_copy",
            user="backup-agent", device="BKP-3", src_ip="10.50.0.3",
            application="BackupEngine", resource="/finance/",
            action="backup", severity="critical",
            metadata={"bytes": 12_000_000_000, "destination": "backup-cluster", "authorized_activity": True},
        ),
    ]


def test_phase13_genuine_generalization_gate() -> None:
    malicious = [
        ("new_device_no_login", family_new_device_no_login()),
        ("login_copy_without_mount", family_login_copy_without_mount()),
        ("slow_campaign", family_slow_campaign()),
        ("simultaneous_campaigns", family_simultaneous_campaigns()),
    ]
    benign = [
        ("authorized_workflow", benign_authorized_workflow()),
        ("identity_collision", benign_identity_collision()),
        ("large_backup", benign_large_backup()),
    ]

    observations = []
    for name, events in [*malicious, *benign]:
        result = analyze(events)
        observations.append({
            "case": name,
            "expected": "validated" if name in {x[0] for x in malicious} else "suppressed",
            "actual": disposition(result),
            "incidents": result.correlated_incidents,
            "hypotheses": len(result.campaign_hypotheses),
        })

    malicious_results = observations[:len(malicious)]
    benign_results = observations[len(malicious):]
    recall = sum(item["actual"] == "validated" for item in malicious_results) / len(malicious_results)
    fpr = sum(item["actual"] == "validated" for item in benign_results) / len(benign_results)

    assert recall == 1.0, observations
    assert fpr == 0.0, observations
