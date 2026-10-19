"""
Conclusion Stress Tester Engine for Digital Time Machine.
Evaluates whether incident findings and investigator conclusions are
adequately corroborated by recorded digital evidence.
Applies deterministic, testable forensic rules without external AI.
"""

import json
from datetime import datetime
from database.db import get_db_connection, query_one, query_all
from engine.evidence_dna import parse_event_ids
from engine.ghost_evidence import detect_ghost_evidence
from engine.correlator import run_correlation_engine
from config import Config

STATUS_SUPPORTED = "Supported by available evidence"
STATUS_PARTIALLY_SUPPORTED = "Partially supported"
STATUS_CONTRADICTORY = "Contradictory evidence found"
STATUS_INSUFFICIENT = "Insufficient evidence"
STATUS_REQUIRES_REVIEW = "Requires investigator review"


def parse_iso(ts_str: str) -> datetime | None:
    """Safely parse ISO timestamp string."""
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str)
    except Exception:
        return None


def stress_test_finding(case_id: str, finding: dict, all_case_events: list[dict] = None) -> dict:
    """
    Stress-tests a single correlation finding or investigator hypothesis.
    
    Identifies:
    1. Supporting evidence records with real database links
    2. Contradictory records
    3. Missing evidence relevant to conclusion
    4. Timestamp inconsistencies
    5. Duplicate records that do not count as independent corroboration
    6. Claims that exceed what recorded evidence establishes
    """
    conn = get_db_connection(Config.DATABASE_PATH)
    actual_case_id = case_id or Config.DEMO_CASE_ID

    # Fetch all case events if not provided
    if all_case_events is None:
        all_case_events = query_all(
            conn,
            "SELECT * FROM events WHERE case_id = ? ORDER BY timestamp ASC",
            (actual_case_id,)
        )
    events_by_id = {e["id"]: e for e in all_case_events}

    raw_event_ids = finding.get("supporting_event_ids")
    event_ids = parse_event_ids(raw_event_ids)

    # 1. Resolve and verify event IDs against database
    supporting_events = []
    unresolved_event_ids = []
    warnings = []

    for eid in event_ids:
        if eid in events_by_id:
            ev = dict(events_by_id[eid])
            ev["timeline_url"] = f"/timeline?case_id={actual_case_id}&event_id={eid}"
            ev["evidence_explorer_url"] = f"/evidence?case_id={actual_case_id}&file={ev.get('evidence_ref', '')}"
            supporting_events.append(ev)
        else:
            # Check DB directly in case it's not in all_case_events
            ev_db = query_one(conn, "SELECT * FROM events WHERE case_id = ? AND id = ?", (actual_case_id, eid))
            if ev_db:
                ev = dict(ev_db)
                ev["timeline_url"] = f"/timeline?case_id={actual_case_id}&event_id={eid}"
                ev["evidence_explorer_url"] = f"/evidence?case_id={actual_case_id}&file={ev.get('evidence_ref', '')}"
                supporting_events.append(ev)
            else:
                unresolved_event_ids.append(eid)

    # Warning for missing event references
    if unresolved_event_ids:
        warnings.append({
            "rule_triggered": "RULE_UNRESOLVED_EVENT_REF",
            "warning_title": "Unresolved Evidence References",
            "severity": "high",
            "explanation": (
                f"Finding references event ID(s) {unresolved_event_ids}, but no corresponding "
                f"records exist in the case evidence database."
            ),
            "supporting_event_ids": [e["id"] for e in supporting_events],
            "contradictory_event_ids": [],
            "additional_evidence_needed": (
                "Re-import the original evidence file containing these events or verify event ID indexing."
            )
        })

    # 2. Check for duplicate records
    dup_warnings = []
    # 2a. Duplicate IDs in the supporting list
    if len(event_ids) != len(set(event_ids)):
        dup_ids = [eid for eid in set(event_ids) if event_ids.count(eid) > 1]
        dup_warnings.append(
            f"Event ID(s) {dup_ids} are referenced multiple times in the finding's supporting list."
        )

    # 2b. Distinct events with identical payload (timestamp, source, event_type, object, actor)
    seen_signatures = {}
    content_dups = []
    for ev in supporting_events:
        sig = (ev.get("timestamp"), ev.get("source"), ev.get("event_type"), ev.get("object"), ev.get("actor"))
        if sig in seen_signatures:
            content_dups.append((seen_signatures[sig], ev["id"]))
        else:
            seen_signatures[sig] = ev["id"]

    if content_dups:
        dup_warnings.append(
            f"Identical telemetry recorded under multiple event IDs: " +
            ", ".join([f"({e1} and {e2})" for e1, e2 in content_dups]) +
            ". These reflect duplicate ingestion of the same observation and do not provide independent corroboration."
        )

    if dup_warnings:
        warnings.append({
            "rule_triggered": "RULE_DUPLICATE_CORROBORATION",
            "warning_title": "Duplicate Evidence Records Detected",
            "severity": "medium",
            "explanation": " ".join(dup_warnings),
            "supporting_event_ids": [e["id"] for e in supporting_events],
            "contradictory_event_ids": [],
            "additional_evidence_needed": (
                "Seek independent corroboration from a distinct telemetry stream (e.g. cross-check host file logs against network flows)."
            )
        })

    # 3. Check for timestamp inconsistencies
    start_dt = parse_iso(finding.get("start_time"))
    end_dt = parse_iso(finding.get("end_time"))
    if start_dt and end_dt and end_dt < start_dt:
        warnings.append({
            "rule_triggered": "RULE_CHRONOLOGICAL_INVERSION",
            "warning_title": "Finding Timeframe Chronologically Inverted",
            "severity": "high",
            "explanation": (
                f"Finding start timestamp ({finding.get('start_time')}) is later than end timestamp "
                f"({finding.get('end_time')})."
            ),
            "supporting_event_ids": [e["id"] for e in supporting_events],
            "contradictory_event_ids": [],
            "additional_evidence_needed": "Correct temporal boundaries or verify time zone normalization."
        })

    # Check order of supporting events if sequential rule
    if len(supporting_events) >= 2:
        for i in range(len(supporting_events) - 1):
            t1 = parse_iso(supporting_events[i].get("timestamp"))
            t2 = parse_iso(supporting_events[i + 1].get("timestamp"))
            if t1 and t2 and t2 < t1:
                warnings.append({
                    "rule_triggered": "RULE_OUT_OF_ORDER_SEQUENCE",
                    "warning_title": "Supporting Events Out of Chronological Order",
                    "severity": "medium",
                    "explanation": (
                        f"Event {supporting_events[i+1]['id']} ({supporting_events[i+1]['timestamp']}) is recorded "
                        f"before precursor Event {supporting_events[i]['id']} ({supporting_events[i]['timestamp']})."
                    ),
                    "supporting_event_ids": [supporting_events[i]["id"], supporting_events[i+1]["id"]],
                    "contradictory_event_ids": [],
                    "additional_evidence_needed": "Verify host system clocks and time synchronization across endpoints."
                })
                break

    # 4. Check Claims Exceeding Evidence (Over-Claim Analysis)
    finding_text = (
        (finding.get("explanation") or "") + " " +
        (finding.get("rule_name") or "") + " " +
        (finding.get("title") or "")
    ).lower()

    # 4a. Example Scenario D: USB Database Copy Claim
    is_usb_copy_claim = any(phrase in finding_text for phrase in [
        "copied to a usb", "copied to usb", "transferred to usb",
        "database was copied to a usb", "exfiltrated via usb",
        "removable device attachment proximate to file-copy"
    ])

    if is_usb_copy_claim:
        has_usb = any(e.get("source") == "usb" or "usb" in e.get("object", "").lower() for e in supporting_events)
        has_db_access = any(
            e.get("source") == "file" and ("database" in e.get("object", "").lower() or "db" in e.get("object", "").lower())
            for e in supporting_events
        )
        has_file_copy = any(
            e.get("event_type") in ("FILE_COPY", "FILE_COPIED") or "copy" in e.get("description", "").lower()
            for e in supporting_events
        )

        # If USB was connected and file was accessed, but no verified file copy to USB exists
        if has_usb and has_db_access and not has_file_copy:
            warnings.append({
                "rule_triggered": "RULE_USB_COPY_OVERCLAIM",
                "warning_title": "Conclusion Exceeds Recorded Evidence (Unverified USB Copy)",
                "severity": "high",
                "explanation": (
                    "The finding asserts or implies that the customer database was copied to a USB device, "
                    "but available evidence records only that a USB device was connected and a database file was accessed. "
                    "No file-copy record or filesystem write to the removable volume exists in the collected evidence."
                ),
                "supporting_event_ids": [e["id"] for e in supporting_events],
                "contradictory_event_ids": [],
                "additional_evidence_needed": (
                    "Collect removable drive filesystem artifacts (USN Journal, Volume Shadow Copies, Shellbags, "
                    "LNK files, or setupapi.dev.log) or acquire a forensic image of the physical USB device to confirm destination."
                )
            })

    # 4b. Missing Process Lineage (Rule E style network correlations)
    if any(e.get("source") == "network" for e in supporting_events) and any(e.get("source") in ("file", "browser") for e in supporting_events):
        has_process_event = any(e.get("source") in ("process", "edr") or "process" in e.get("event_type", "").lower() for e in supporting_events)
        if not has_process_event:
            warnings.append({
                "rule_triggered": "RULE_UNVERIFIED_PROCESS_LINEAGE",
                "warning_title": "Unverified Process Lineage Connecting File to Network",
                "severity": "medium",
                "explanation": (
                    "The correlation links file or download activity to external network connections based on temporal proximity. "
                    "However, no process execution telemetry (e.g. Sysmon Event ID 1 / Event ID 3) exists in evidence to establish "
                    "that the downloaded executable or accessed file initiated the network connection."
                ),
                "supporting_event_ids": [e["id"] for e in supporting_events],
                "contradictory_event_ids": [],
                "additional_evidence_needed": (
                    "Acquire EDR or Sysmon process creation logs linking process IDs (PID) to outbound network socket handles."
                )
            })

    # 4c. Malicious intent / brute force claim without sufficient attempts
    if "failed logins" in finding_text or finding.get("rule_id") == "RULE_D":
        failed_logins = [e for e in supporting_events if e.get("event_type") in ("LOGIN_FAILED", "AUTH_FAILURE")]
        if len(failed_logins) < 5:
            warnings.append({
                "rule_triggered": "RULE_INSUFFICIENT_BRUTEFORCE_GROUNDS",
                "warning_title": "Ambiguous Authentication Failure Count",
                "severity": "low",
                "explanation": (
                    f"Finding records {len(failed_logins)} failed login attempts prior to success. "
                    f"A low failure count frequently stems from user typo or expired password caching rather than brute-force attacks."
                ),
                "supporting_event_ids": [e["id"] for e in supporting_events],
                "contradictory_event_ids": [],
                "additional_evidence_needed": (
                    "Examine source workstation IP addresses, authentication sub-status codes (NTSTATUS 0xC000006A vs 0xC0000234), "
                    "and user interview logs."
                )
            })

    # 5. Check Contradictory Records in Case Telemetry
    contradictory_events = []
    
    # 5a. Check actor activity during recorded logout state
    finding_actors = list(set([e.get("actor") for e in supporting_events if e.get("actor") and e.get("actor") != "SYSTEM"]))
    for actor in finding_actors:
        actor_logins = [
            e for e in all_case_events 
            if e.get("actor", "").lower() == actor.lower() and e.get("event_type") in ("LOGIN_SUCCESS", "LOGON")
        ]
        actor_logouts = [
            e for e in all_case_events 
            if e.get("actor", "").lower() == actor.lower() and e.get("event_type") in ("LOGOUT", "LOGOFF")
        ]
        # For each supporting event of this actor, verify they weren't logged out
        for ev in supporting_events:
            if ev.get("actor", "").lower() == actor.lower():
                ev_time = ev.get("timestamp")
                # Look for logout between latest login and this event
                prior_logouts = [lo for lo in actor_logouts if lo["timestamp"] < ev_time]
                if prior_logouts:
                    latest_logout = max(prior_logouts, key=lambda x: x["timestamp"])
                    prior_logins = [li for li in actor_logins if latest_logout["timestamp"] < li["timestamp"] < ev_time]
                    if not prior_logins and latest_logout["timestamp"] < ev_time:
                        contradictory_events.append(latest_logout)
                        warnings.append({
                            "rule_triggered": "RULE_CONTRADICTORY_SESSION_STATE",
                            "warning_title": "Activity Recorded While Actor In Logged-Out State",
                            "severity": "critical",
                            "explanation": (
                                f"Event {ev['id']} ({ev['timestamp']}) attributes action to '{actor}', but prior Event "
                                f"{latest_logout['id']} recorded actor '{actor}' logging out at {latest_logout['timestamp']} "
                                f"with no subsequent logon observed."
                            ),
                            "supporting_event_ids": [ev["id"]],
                            "contradictory_event_ids": [latest_logout["id"]],
                            "additional_evidence_needed": (
                                "Inspect interactive session tokens, SSH keys, or secondary service account impersonation logs."
                            )
                        })
                        break

    # 5b. Cross-reference Ghost Evidence Anomalies
    ghost_anomalies = detect_ghost_evidence(all_case_events, case_id=actual_case_id)
    for g in ghost_anomalies:
        # Check temporal coverage gaps overlapping finding window
        if g.get("anomaly_type") == "TEMPORAL_COVERAGE_GAP":
            if any(e.get("source") == "browser" for e in supporting_events):
                warnings.append({
                    "rule_triggered": "RULE_GHOST_EVIDENCE_GAP",
                    "warning_title": f"Telemetry Gap Overlaps Finding Window ({g.get('title')})",
                    "severity": "medium",
                    "explanation": (
                        f"A recorded ghost evidence gap was detected in the case dataset: {g.get('observed')}. "
                        f"{g.get('missing')}"
                    ),
                    "supporting_event_ids": [e["id"] for e in supporting_events],
                    "contradictory_event_ids": [],
                    "additional_evidence_needed": "Collect proxy logs, DNS cache, and local browser cache databases."
                })
                break

    conn.close()

    # 6. Determine Result Category Status
    # Order of evaluation:
    # Contradictory -> Insufficient -> Requires Review -> Partially Supported -> Supported
    has_contradictions = len(contradictory_events) > 0 or any(w.get("severity") == "critical" for w in warnings)
    has_unresolved_refs = len(unresolved_event_ids) > 0
    has_zero_evidence = len(supporting_events) == 0
    has_overclaim = any(w.get("rule_triggered") in ("RULE_USB_COPY_OVERCLAIM", "RULE_ZERO_SUPPORTING_EVIDENCE") for w in warnings)
    high_severity_warnings = [w for w in warnings if w.get("severity") in ("high", "critical")]

    if has_contradictions:
        status = STATUS_CONTRADICTORY
        status_reason = "Directly contradictory telemetry was identified in the case dataset."
    elif has_zero_evidence or (has_overclaim and len(supporting_events) <= 2):
        status = STATUS_INSUFFICIENT
        status_reason = "Available digital evidence does not substantiate the core conclusion claims."
    elif has_unresolved_refs or high_severity_warnings:
        status = STATUS_REQUIRES_REVIEW
        status_reason = "Identified critical ambiguities, over-claims, or uncorroborated event references."
    elif len(warnings) > 0:
        status = STATUS_PARTIALLY_SUPPORTED
        status_reason = "Finding is partially corroborated by recorded evidence, with analytical caveats noted."
    else:
        status = STATUS_SUPPORTED
        status_reason = "All claimed sequence stages are corroborated by verified independent evidence records."

    return {
        "finding_id": finding.get("id", "CUSTOM-CONCLUSION"),
        "rule_id": finding.get("rule_id", "CUSTOM_HYPOTHESIS"),
        "rule_name": finding.get("rule_name", "Forensic Conclusion Evaluation"),
        "status": status,
        "status_reason": status_reason,
        "explanation": finding.get("explanation", ""),
        "supporting_events": supporting_events,
        "supporting_event_count": len(supporting_events),
        "unresolved_event_ids": unresolved_event_ids,
        "contradictory_events": contradictory_events,
        "warnings": warnings,
        "warning_count": len(warnings),
        "case_id": actual_case_id
    }


def stress_test_custom_conclusion(case_id: str, conclusion_text: str, event_ids: list[str]) -> dict:
    """
    Stress-tests an ad-hoc investigator hypothesis against specified event IDs.
    """
    finding = {
        "id": "CUSTOM-HYPOTHESIS",
        "rule_id": "INVESTIGATOR_HYPOTHESIS",
        "rule_name": "Custom Investigator Hypothesis",
        "explanation": conclusion_text,
        "supporting_event_ids": event_ids,
        "start_time": "",
        "end_time": ""
    }
    return stress_test_finding(case_id, finding)


def stress_test_case(case_id: str) -> dict:
    """
    Evaluates stress test across all correlation findings for a given case.
    """
    conn = get_db_connection(Config.DATABASE_PATH)
    actual_case_id = case_id or Config.DEMO_CASE_ID
    
    # Retrieve findings from DB or dynamic correlation
    findings = query_all(
        conn,
        "SELECT * FROM correlation_findings WHERE case_id = ? ORDER BY id ASC",
        (actual_case_id,)
    )
    all_events = query_all(
        conn,
        "SELECT * FROM events WHERE case_id = ? ORDER BY timestamp ASC",
        (actual_case_id,)
    )

    if not findings:
        findings = run_correlation_engine(all_events, case_id=actual_case_id)

    conn.close()

    evaluations = []
    status_summary = {
        STATUS_SUPPORTED: 0,
        STATUS_PARTIALLY_SUPPORTED: 0,
        STATUS_CONTRADICTORY: 0,
        STATUS_INSUFFICIENT: 0,
        STATUS_REQUIRES_REVIEW: 0
    }

    for f in findings:
        res = stress_test_finding(actual_case_id, f, all_case_events=all_events)
        evaluations.append(res)
        st = res["status"]
        if st in status_summary:
            status_summary[st] += 1

    return {
        "case_id": actual_case_id,
        "total_findings_evaluated": len(evaluations),
        "status_summary": status_summary,
        "evaluations": evaluations
    }

