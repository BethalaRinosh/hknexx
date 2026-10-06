# Phase 3 — Real Heterogeneous Log Ingestion

## Goal

Accept representative real-world security telemetry from multiple sources and convert it into one canonical event model without changing the Phase 2 detection decision logic.

## Research basis

The canonical model is **OCSF-aligned**, not claimed to be a full OCSF implementation. OCSF is an open cybersecurity event normalization standard designed to provide implementation-agnostic common representations. The current public schema release is v1.9.0 (August 2026).

The first adapters target:
- Windows Security Event 4624 — successful logon context
- Windows Security Event 4663 — object/file/removable-storage access
- Sysmon — process/network/file telemetry
- Zeek JSON — network/HTTP/DNS telemetry

Sigma correlation concepts also support the architecture: grouping fields, timespans, temporal correlation and temporal-ordered correlation are standard constructs.

## Canonical event contract

The normalized event contains:

- event_id
- timestamp
- event_type
- user
- device
- src_ip
- dst_ip
- application
- process
- pid
- parent_process
- session_id
- resource
- action
- source
- severity
- metadata

Unknown source-specific fields are retained inside metadata rather than silently discarded.

## Adapter responsibilities

### Windows Security

4624:
- user from TargetUserName / SubjectUserName
- device from Computer
- source IP from IpAddress
- logon/session identity from TargetLogonId / SubjectLogonId

4663:
- user from SubjectUserName
- file/object resource from ObjectName
- process from ProcessName
- session identity from SubjectLogonId
- event type becomes file_access when ObjectType is File

### Sysmon

Initial mappings:
- Event ID 1 → process_create
- Event ID 3 → network_connection
- Event ID 11 → file_create
- Event ID 22 → dns_query

Important fields such as Image, ProcessId, ParentImage, SourceIp and DestinationIp are preserved.

### Zeek

Initial mappings:
- conn → network_connection
- http → http_request
- dns → dns_query

Network fields such as origination IP, responder IP, UID, method, host, URI and protocol/service are preserved.

## Phase 3 gate

We do not advance until:

1. Windows 4624 adapter passes.
2. Windows 4663 adapter passes.
3. Windows XML input passes.
4. Sysmon JSON passes.
5. Zeek JSON passes.
6. Expanded canonical fields are preserved.
7. Existing Phase 2 test suite still passes.
8. No adapter silently drops required identity/timestamp fields.

## Scope boundary

Phase 3 is an ingestion/normalization phase.

We intentionally do NOT:
- add a new ML model;
- expand attack logic based on raw source-specific fields;
- claim full OCSF compliance;
- ingest giant public datasets yet.

Those are later phases after the normalized interface is proven.
