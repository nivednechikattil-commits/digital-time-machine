"""
Evidence Correlation Engine for Digital Time Machine.
Implements rule-based, explainable cybersecurity correlation without machine learning.
Distinguishes observed sequences from inferred conclusions.
"""

from datetime import datetime, timedelta
import json

def parse_iso(ts_str: str) -> datetime:
    """Parses standard ISO timestamp string."""
    return datetime.fromisoformat(ts_str)

def run_correlation_engine(events: list[dict], case_id: str = "CASE-2026-001") -> list[dict]:
    """
    Evaluates correlation rules over chronologically sorted events.
    Returns list of correlation findings.
    """
    findings = []
    # Ensure events are sorted chronologically
    sorted_events = sorted(events, key=lambda x: x["timestamp"])

    # Index events by source and event_type
    events_by_id = {e["id"]: e for e in sorted_events}

    # Helper to calculate seconds between timestamps
    def time_diff_sec(t1_str: str, t2_str: str) -> float:
        return abs((parse_iso(t2_str) - parse_iso(t1_str)).total_seconds())

    # --- Rule A: Suspicious website visit followed by download (window: 900s / 15m) ---
    browser_navs = [
        e for e in sorted_events
        if e.get("source") == "browser" and e.get("event_type") in ("BROWSER_NAVIGATE", "HTTP_REQUEST")
    ]
    downloads = [
        e for e in sorted_events
        if e.get("event_type") in ("FILE_DOWNLOAD", "DOWNLOAD") or
        (e.get("source") == "file" and "download" in e.get("description", "").lower())
    ]

    for nav in browser_navs:
        url = nav.get("object", "").lower()
        is_suspicious_url = any(k in url for k in ["training-domain", "internal-demo", "phish", "cdn-payload", "unknown", "update-pkg"])
        
        for dl in downloads:
            if dl["timestamp"] >= nav["timestamp"]:
                diff = time_diff_sec(nav["timestamp"], dl["timestamp"])
                if diff <= 900:  # 15 minutes
                    finding_id = f"FIND-A-{len(findings) + 1:02d}"
                    findings.append({
                        "id": finding_id,
                        "case_id": case_id,
                        "rule_id": "RULE_A",
                        "rule_name": "Suspicious Website Visit Preceding File Download",
                        "severity": "high" if is_suspicious_url else "medium",
                        "supporting_event_ids": [nav["id"], dl["id"]],
                        "explanation": (
                            f"A browser navigation to '{nav['object']}' at {nav['timestamp']} was followed {int(diff)}s later "
                            f"by file download '{dl['object']}' (Event {dl['id']})."
                        ),
                        "start_time": nav["timestamp"],
                        "end_time": dl["timestamp"],
                        "confidence": "observed_correlation",
                        "limitations": (
                            "Temporal sequence does not prove the download originated from the visited URL or that "
                            "the payload is malicious. Correlation is based on chronological proximity."
                        ),
                        "recommended_action": (
                            "Verify web browser download history artifacts, cache entries, and calculate payload cryptographic hashes."
                        )
                    })

    # --- Rule B: Recorded file access followed by recorded file-copy event (window: 900s / 15m) ---
    file_accesses = [
        e for e in sorted_events
        if e.get("source") == "file" and e.get("event_type") in ("FILE_ACCESS", "FILE_READ", "FILE_OPEN")
    ]
    file_copies = [
        e for e in sorted_events
        if e.get("source") == "file" and e.get("event_type") in ("FILE_COPY", "FILE_COPIED")
    ]

    for acc in file_accesses:
        acc_file = acc.get("object")
        for cp in file_copies:
            cp_file = cp.get("object")
            if acc_file == cp_file and cp["timestamp"] >= acc["timestamp"]:
                diff = time_diff_sec(acc["timestamp"], cp["timestamp"])
                if diff <= 900:
                    finding_id = f"FIND-B-{len(findings) + 1:02d}"
                    findings.append({
                        "id": finding_id,
                        "case_id": case_id,
                        "rule_id": "RULE_B",
                        "rule_name": "File Access Followed by Local File-Copy Event",
                        "severity": "high",
                        "supporting_event_ids": [acc["id"], cp["id"]],
                        "explanation": (
                            f"Sensitive file '{acc_file}' was accessed at {acc['timestamp']} by '{acc['actor']}' "
                            f"and subsequently copied {int(diff)}s later (Event {cp['id']})."
                        ),
                        "start_time": acc["timestamp"],
                        "end_time": cp["timestamp"],
                        "confidence": "observed_correlation",
                        "limitations": (
                            "Access followed by copy can be part of legitimate user archiving or backup workflows. "
                            "Authorization records must be reviewed."
                        ),
                        "recommended_action": (
                            "Inspect destination volume metadata, USB storage serial numbers, and employee data access authorization."
                        )
                    })

    # --- Rule C: Recorded device connection near recorded file-copy event (window: 600s / 10m) ---
    usb_events = [
        e for e in sorted_events
        if e.get("source") == "usb" and e.get("event_type") in ("DEVICE_CONNECT", "USB_INSERT", "DEVICE_MOUNT")
    ]

    for usb in usb_events:
        for cp in file_copies:
            diff = time_diff_sec(usb["timestamp"], cp["timestamp"])
            if diff <= 600:
                earliest = min(usb["timestamp"], cp["timestamp"])
                latest = max(usb["timestamp"], cp["timestamp"])
                finding_id = f"FIND-C-{len(findings) + 1:02d}"
                findings.append({
                    "id": finding_id,
                    "case_id": case_id,
                    "rule_id": "RULE_C",
                    "rule_name": "Removable Device Attachment Proximate to File-Copy",
                    "severity": "critical",
                    "supporting_event_ids": [usb["id"], cp["id"]],
                    "explanation": (
                        f"Removable USB storage device '{usb['object']}' connected at {usb['timestamp']} by '{usb['actor']}' "
                        f"occurred within {int(diff)}s of file-copy event for '{cp['object']}' (Event {cp['id']})."
                    ),
                    "start_time": earliest,
                    "end_time": latest,
                    "confidence": "observed_correlation",
                    "limitations": (
                        "Proximity between device insertion and file write strongly suggests possible external transfer, "
                        "but filesystem write artifacts and volume drive letters must confirm destination."
                    ),
                    "recommended_action": (
                        "Cross-reference USB serial with organizational inventory and examine shellbags / setupapi.dev.log."
                    )
                })

    # --- Rule D: Multiple failed logins followed by successful login for same account (window: 1800s / 30m) ---
    login_events = [e for e in sorted_events if e.get("source") == "login"]
    user_failed_logins = {}
    
    for log_ev in login_events:
        actor = log_ev.get("actor", "").lower()
        etype = log_ev.get("event_type", "").upper()
        
        if etype in ("LOGIN_FAILED", "AUTH_FAILURE"):
            user_failed_logins.setdefault(actor, []).append(log_ev)
        elif etype in ("LOGIN_SUCCESS", "LOGON"):
            if actor in user_failed_logins and len(user_failed_logins[actor]) >= 2:
                # Check timeframe
                failures = [f for f in user_failed_logins[actor] if time_diff_sec(f["timestamp"], log_ev["timestamp"]) <= 1800]
                if len(failures) >= 2:
                    supp_ids = [f["id"] for f in failures] + [log_ev["id"]]
                    start_ts = failures[0]["timestamp"]
                    end_ts = log_ev["timestamp"]
                    finding_id = f"FIND-D-{len(findings) + 1:02d}"
                    findings.append({
                        "id": finding_id,
                        "case_id": case_id,
                        "rule_id": "RULE_D",
                        "rule_name": "Repeated Failed Logins Followed by Successful Authentication",
                        "severity": "high",
                        "supporting_event_ids": supp_ids,
                        "explanation": (
                            f"Account '{actor}' experienced {len(failures)} failed authentication attempts prior to a successful "
                            f"logon at {log_ev['timestamp']} within {int(time_diff_sec(start_ts, end_ts))} seconds."
                        ),
                        "start_time": start_ts,
                        "end_time": end_ts,
                        "confidence": "observed_correlation",
                        "limitations": (
                            "Repeated failed logins may stem from mistyped passwords or expired credentials rather than credential brute-forcing."
                        ),
                        "recommended_action": (
                            "Check source IP addresses and authentication failure status codes (e.g. Event ID 4625 substatus)."
                        )
                    })
                    # Reset after finding to avoid duplicate firing
                    user_failed_logins[actor] = []

    # --- Rule E: Download followed by file access and external network connection (window: 1800s / 30m) ---
    net_connections = [
        e for e in sorted_events
        if e.get("source") == "network" and e.get("event_type") in ("NETWORK_CONNECTION", "NETWORK_TRANSFER", "TCP_CONNECT")
    ]

    for dl in downloads:
        for acc in file_accesses:
            if acc["timestamp"] >= dl["timestamp"] and time_diff_sec(dl["timestamp"], acc["timestamp"]) <= 1800:
                for net in net_connections:
                    if net["timestamp"] >= acc["timestamp"] and time_diff_sec(acc["timestamp"], net["timestamp"]) <= 1800:
                        finding_id = f"FIND-E-{len(findings) + 1:02d}"
                        findings.append({
                            "id": finding_id,
                            "case_id": case_id,
                            "rule_id": "RULE_E",
                            "rule_name": "Download Followed by File Access and External Network Activity",
                            "severity": "critical",
                            "supporting_event_ids": [dl["id"], acc["id"], net["id"]],
                            "explanation": (
                                f"A tool download '{dl['object']}' ({dl['timestamp']}) was followed by access to '{acc['object']}' "
                                f"and subsequent outbound network traffic to '{net['object']}' ({net['timestamp']})."
                            ),
                            "start_time": dl["timestamp"],
                            "end_time": net["timestamp"],
                            "confidence": "heuristic_sequence",
                            "limitations": (
                                "Does not establish process lineage connecting the downloaded binary to the outbound connection. "
                                "Requires Sysmon or EDR process creation tree evidence."
                            ),
                            "recommended_action": (
                                "Obtain process execution trees (Event ID 4688 / Sysmon 1) to verify parent-child process relationships."
                            )
                        })

    # --- Rule F: Missing or inconsistent evidence in an expected sequence ---
    # Example: A file-copy event without preceding mount event in the same session,
    # or an external download without corresponding browser navigation entry in browser history
    for dl in downloads:
        prior_navs = [
            nav for nav in browser_navs
            if nav["timestamp"] <= dl["timestamp"] and time_diff_sec(nav["timestamp"], dl["timestamp"]) <= 900
        ]
        if not prior_navs:
            finding_id = f"FIND-F-{len(findings) + 1:02d}"
            findings.append({
                "id": finding_id,
                "case_id": case_id,
                "rule_id": "RULE_F",
                "rule_name": "File Download Artifact Lacking Preceding Browser Navigation Record",
                "severity": "medium",
                "supporting_event_ids": [dl["id"]],
                "explanation": (
                    f"File download '{dl['object']}' recorded at {dl['timestamp']} has no recorded HTTP navigation event "
                    f"in the ingested browser history within 15 minutes."
                ),
                "start_time": dl["timestamp"],
                "end_time": dl["timestamp"],
                "confidence": "inferred_gap",
                "limitations": (
                    "Could be caused by browser history pruning, private browsing mode, alternative user-agent (e.g. curl/powershell), "
                    "or incomplete log collection."
                ),
                "recommended_action": (
                    "Collect web proxy logs, DNS resolver caches, and browser SQLite history databases."
                )
            })

    return findings

