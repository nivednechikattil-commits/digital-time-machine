"""
Ghost Evidence Detector for Digital Time Machine.
Identifies potential evidence gaps, missing artifact sequences, and timestamp inconsistencies.
Maintains forensic neutrality: does not assume intentional anti-forensics or log deletion.
"""

from datetime import datetime, timedelta
import json

def parse_iso(ts_str: str) -> datetime:
    """Parses standard ISO timestamp string."""
    return datetime.fromisoformat(ts_str)

def detect_ghost_evidence(events: list[dict], case_id: str = "CASE-2026-001") -> list[dict]:
    """
    Analyzes event sequence for evidence anomalies, gaps, and missing expected records.
    Returns list of ghost evidence findings.
    """
    findings = []
    sorted_events = sorted(events, key=lambda x: x["timestamp"])
    
    if not sorted_events:
        return findings

    # Helper to calculate seconds between timestamps
    def time_diff_sec(t1_str: str, t2_str: str) -> float:
        return abs((parse_iso(t2_str) - parse_iso(t1_str)).total_seconds())

    # 1. Detect Suspicious Browser History Temporal Gaps (> 30 mins during active session)
    browser_events = [e for e in sorted_events if e.get("source") == "browser"]
    login_events = [e for e in sorted_events if e.get("source") == "login" and e.get("event_type") == "LOGIN_SUCCESS"]

    for i in range(len(browser_events) - 1):
        e1 = browser_events[i]
        e2 = browser_events[i + 1]
        gap_sec = time_diff_sec(e1["timestamp"], e2["timestamp"])
        
        # If gap is between 30 minutes (1800s) and 4 hours (14400s) during what appears to be an active session
        if 1800 <= gap_sec <= 14400:
            finding_id = f"GHOST-GAP-{len(findings) + 1:02d}"
            findings.append({
                "id": finding_id,
                "case_id": case_id,
                "anomaly_type": "TEMPORAL_COVERAGE_GAP",
                "severity": "medium",
                "title": f"Unrecorded Browser Navigation Window ({int(gap_sec / 60)} minutes)",
                "observed": f"Browser activity stopped at {e1['timestamp']} ('{e1['object']}') and resumed at {e2['timestamp']} ('{e2['object']}').",
                "missing": "No browser history, HTTP requests, or cache artifacts recorded during this interval.",
                "potential_benign_causes": [
                    "User was working in non-browser applications or offline.",
                    "User stepped away from workstation (break, lunch, meeting).",
                    "Browser history was not configured to record session cookies/cache."
                ],
                "investigative_significance": "A lack of recorded browsing during an active session could indicate private browsing (incognito) usage or selective clearing, but requires disk triage to confirm.",
                "supporting_event_ids": [e1["id"], e2["id"]],
                "recommended_evidence": "Inspect browser WebCache/SQLite free lists, Volume Shadow Copies (VSS), and proxy logs."
            })

    # 2. File Copy Without Prior Read/Access Event
    file_copies = [e for e in sorted_events if e.get("source") == "file" and e.get("event_type") in ("FILE_COPY", "FILE_COPIED")]
    file_accesses = [e for e in sorted_events if e.get("source") == "file" and e.get("event_type") in ("FILE_ACCESS", "FILE_READ", "FILE_OPEN")]

    for cp in file_copies:
        target_file = cp.get("object")
        # Check if there is an access event for this file within 30 min before copy
        prior_accesses = [
            acc for acc in file_accesses
            if acc.get("object") == target_file and acc["timestamp"] <= cp["timestamp"]
            and time_diff_sec(acc["timestamp"], cp["timestamp"]) <= 1800
        ]
        if not prior_accesses:
            finding_id = f"GHOST-MISSING-READ-{len(findings) + 1:02d}"
            findings.append({
                "id": finding_id,
                "case_id": case_id,
                "anomaly_type": "MISSING_PRECURSOR_ARTIFACT",
                "severity": "medium",
                "title": f"File Copy Without Prior Read/Open Event for '{target_file}'",
                "observed": f"File copy event {cp['id']} was recorded at {cp['timestamp']} targeting '{target_file}'.",
                "missing": "No corresponding FILE_READ or FILE_OPEN audit event preceded the copy operation.",
                "potential_benign_causes": [
                    "Object Access Auditing (SACL) was configured for write/copy events only, omitting read audits to reduce log volume.",
                    "File was copied via low-level Volume Shadow Service or script that bypassed standard shell open handles."
                ],
                "investigative_significance": "Suggests incomplete audit policy or rapid scripted extraction without interactive user opening.",
                "supporting_event_ids": [cp["id"]],
                "recommended_evidence": "Review Windows Security Event Log audit configuration and Sysmon FileCreate/FileAccess rules."
            })

    # 3. USB Connection Without Subsequent Disconnect or Unmount
    usb_connects = [e for e in sorted_events if e.get("source") == "usb" and e.get("event_type") in ("DEVICE_CONNECT", "USB_INSERT", "DEVICE_MOUNT")]
    usb_disconnects = [e for e in sorted_events if e.get("source") == "usb" and e.get("event_type") in ("DEVICE_DISCONNECT", "USB_REMOVE", "DEVICE_UNMOUNT")]

    for conn in usb_connects:
        dev_id = conn.get("object")
        later_disconns = [
            dis for dis in usb_disconnects
            if dis.get("object") == dev_id and dis["timestamp"] >= conn["timestamp"]
        ]
        if not later_disconns:
            finding_id = f"GHOST-UNCLOSED-DEVICE-{len(findings) + 1:02d}"
            findings.append({
                "id": finding_id,
                "case_id": case_id,
                "anomaly_type": "UNCLOSED_ARTIFACT_LIFECYCLE",
                "severity": "low",
                "title": f"Removable Device '{dev_id}' Connected Without Recorded Removal",
                "observed": f"Device was connected at {conn['timestamp']} by '{conn['actor']}'.",
                "missing": "No corresponding DEVICE_DISCONNECT or unmount log exists in the collected dataset.",
                "potential_benign_causes": [
                    "Device remained physically connected at the time log collection was performed.",
                    "Workstation was shut down abruptly or ungracefully removed without triggering driver disconnect events.",
                    "Collection time window ended prior to device removal."
                ],
                "investigative_significance": "Device may still be mounted or was pulled without safe removal.",
                "supporting_event_ids": [conn["id"]],
                "recommended_evidence": "Verify system shutdown logs (Event ID 6006/6008) or check physical hardware triage records."
            })

    # 4. Outbound Network Exfiltration Without Corresponding Process Identity
    net_events = [e for e in sorted_events if e.get("source") == "network"]
    for net in net_events:
        details = net.get("details", {})
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception:
                details = {}
        process = details.get("process_name") or details.get("process")
        if not process:
            finding_id = f"GHOST-UNATTRIBUTED-NET-{len(findings) + 1:02d}"
            findings.append({
                "id": finding_id,
                "case_id": case_id,
                "anomaly_type": "UNATTRIBUTED_NETWORK_FLOW",
                "severity": "medium",
                "title": f"Network Flow to {net.get('object')} Lacks Process Attribution",
                "observed": f"Outbound flow recorded at {net['timestamp']} to '{net['object']}'.",
                "missing": "PID and executable binary name are not populated in the network telemetry.",
                "potential_benign_causes": [
                    "Flow telemetry originated from perimeter firewall or NetFlow rather than endpoint agent (EDR).",
                    "Process terminated immediately after transmission before socket mapping could resolve."
                ],
                "investigative_significance": "Prevents direct programmatic correlation to downloaded tools without supplemental host triage.",
                "supporting_event_ids": [net["id"]],
                "recommended_evidence": "Correlate with endpoint Sysmon Event ID 3 (NetworkConnect) or firewall state tables."
            })

    return findings

