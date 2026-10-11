"""
Evidence DNA Engine for Digital Time Machine.
Implements deep forensic lineage, linking incident correlation findings directly
to underlying immutable event records, plain-language trigger rationales,
recorded facts vs. inferred deductions, and dataset-supported contradiction/gap analysis.
"""

import json
from datetime import datetime
from database.db import get_db_connection, query_one, query_all
from engine.ghost_evidence import detect_ghost_evidence
from engine.correlator import run_correlation_engine
from config import Config


def parse_event_ids(raw_ids) -> list[str]:
    """Safely parses supporting event IDs from string, JSON array, or list."""
    if not raw_ids:
        return []
    if isinstance(raw_ids, list):
        return [str(i) for i in raw_ids if str(i).strip()]
    if isinstance(raw_ids, str):
        raw_ids = raw_ids.strip()
        if not raw_ids or raw_ids in ("[]", "null", "None"):
            return []
        try:
            parsed = json.loads(raw_ids)
            if isinstance(parsed, list):
                return [str(i) for i in parsed if str(i).strip()]
        except Exception:
            pass
        # Fallback delimiter split
        cleaned = raw_ids.strip("[]()\"' ")
        return [s.strip(" \"'") for s in cleaned.split(",") if s.strip(" \"'")]
    return []


def get_evidence_dna(case_id: str, finding_id: str) -> dict | None:
    """
    Constructs the Evidence DNA profile for an incident finding.
    
    Adheres to strict forensic principles:
    1. Extracts actual supporting events from SQLite without inventing telemetry.
    2. Explains in plain language why events triggered the rule.
    3. Clearly segregates Observed Facts from Inferred Conclusions.
    4. Evaluates contradictory or missing evidence only when the dataset supports it.
    5. Marks findings with no linked events as 'unavailable'.
    """
    conn = get_db_connection(Config.DATABASE_PATH)

    actual_case_id = case_id
    if actual_case_id in (getattr(Config, "LEGACY_DEMO_CASE_ID", "CASE-2026-001"), "CASE-2026-001"):
        exists = query_one(conn, "SELECT id FROM cases WHERE id = ?", (actual_case_id,))
        if not exists:
            actual_case_id = Config.DEMO_CASE_ID

    # 1. Retrieve finding from database
    finding = query_one(
        conn,
        "SELECT * FROM correlation_findings WHERE case_id = ? AND id = ?",
        (actual_case_id, finding_id)
    )

    # Fallback to dynamic correlation engine if not found in table
    if not finding:
        events = query_all(
            conn,
            "SELECT * FROM events WHERE case_id = ? ORDER BY timestamp ASC",
            (actual_case_id,)
        )
        all_findings = run_correlation_engine(events, case_id=actual_case_id)
        for f in all_findings:
            if f.get("id") == finding_id:
                finding = f
                break

    if not finding:
        conn.close()
        return None

    # 2. Extract and parse supporting event IDs
    raw_event_ids = finding.get("supporting_event_ids")
    event_ids = parse_event_ids(raw_event_ids)

    # 3. Retrieve actual event records from database
    supporting_events = []
    unresolved_event_ids = []

    for eid in event_ids:
        ev = query_one(
            conn,
            "SELECT * FROM events WHERE case_id = ? AND id = ?",
            (actual_case_id, eid)
        )
        if ev:
            ev_dict = dict(ev)
            # Parse details JSON if present
            if isinstance(ev_dict.get("details"), str):
                try:
                    ev_dict["details"] = json.loads(ev_dict["details"])
                except Exception:
                    pass
            # Attach direct navigation links
            ev_dict["timeline_url"] = f"/timeline?case_id={actual_case_id}&event_id={eid}"
            ev_dict["evidence_explorer_url"] = f"/evidence?case_id={actual_case_id}&file={ev_dict.get('evidence_ref', '')}"
            supporting_events.append(ev_dict)
        else:
            unresolved_event_ids.append(eid)

    # 4. Determine Evidence Status
    has_evidence = len(supporting_events) > 0
    if has_evidence:
        evidence_status = "available"
        status_message = f"Verified {len(supporting_events)} recorded supporting event(s) across telemetry sources."
    else:
        evidence_status = "unavailable"
        status_message = (
            "Supporting evidence is unavailable for this finding. "
            "No recorded event telemetry is linked in the database."
        )

    # 5. Build Recorded Facts (Observed Telemetry)
    recorded_facts = []
    for ev in supporting_events:
        recorded_facts.append({
            "event_id": ev["id"],
            "timestamp": ev["timestamp"],
            "source": ev["source"],
            "event_type": ev["event_type"],
            "actor": ev["actor"],
            "target_object": ev["object"],
            "severity": ev["severity"],
            "evidence_ref": ev["evidence_ref"],
            "confidence": ev.get("confidence", "observed"),
            "description": ev["description"],
            "timeline_url": ev["timeline_url"],
            "evidence_explorer_url": ev["evidence_explorer_url"]
        })

    # 6. Build Inferred Conclusions (Rule Deductions)
    inferred_conclusions = {
        "rule_id": finding.get("rule_id", "UNKNOWN_RULE"),
        "rule_name": finding.get("rule_name", "Forensic Correlation Finding"),
        "severity": finding.get("severity", "medium"),
        "confidence": finding.get("confidence", "observed_correlation"),
        "explanation": finding.get("explanation", ""),
        "start_time": finding.get("start_time", ""),
        "end_time": finding.get("end_time", ""),
        "limitations": finding.get(
            "limitations",
            "Correlation is based on chronological proximity. Temporal sequence does not constitute proof of malice or unauthorized intent."
        ),
        "recommended_action": finding.get(
            "recommended_action",
            "Verify raw forensic artifacts and consult authorized user interview logs."
        )
    }

    # 7. Evaluate Contradictory or Missing Evidence (Dataset Gap Analysis)
    contradictory_or_missing = []

    # Check 7a: Unresolved event IDs in finding metadata
    for missing_id in unresolved_event_ids:
        contradictory_or_missing.append({
            "type": "MISSING_ARTIFACT_RECORD",
            "title": f"Unresolved Event Reference: {missing_id}",
            "description": f"Finding references event ID '{missing_id}', but no matching record exists in the database.",
            "severity": "high"
        })

    # Check 7b: Cross-reference dataset ghost evidence anomalies
    all_events = query_all(
        conn,
        "SELECT * FROM events WHERE case_id = ? ORDER BY timestamp ASC",
        (actual_case_id,)
    )
    ghost_findings = detect_ghost_evidence(all_events, case_id=actual_case_id)

    # Cross-reference USB lifecycle anomalies
    rule_id = finding.get("rule_id", "")
    if rule_id in ("RULE_C", "RULE_B") or any(e["source"] == "usb" for e in supporting_events):
        for g in ghost_findings:
            if g.get("anomaly_type") == "UNCLOSED_ARTIFACT_LIFECYCLE":
                contradictory_or_missing.append({
                    "type": "UNCLOSED_ARTIFACT_LIFECYCLE",
                    "title": g.get("title", "Unclosed Removable Storage Lifecycle"),
                    "description": (
                        "The removable storage device connected proximate to this activity "
                        "was never recorded as safely disconnected or unmounted in recorded telemetry."
                    ),
                    "severity": g.get("severity", "medium"),
                    "anomaly_id": g.get("id")
                })
                break

    # Cross-reference temporal coverage gaps proximate to this finding's window
    f_end_time = finding.get("end_time", "")
    for g in ghost_findings:
        if g.get("anomaly_type") == "TEMPORAL_COVERAGE_GAP":
            # If gap observed starts at finding end_time or finding is in browser domain
            if (f_end_time and f_end_time in g.get("observed", "")) or any(e["source"] == "browser" for e in supporting_events):
                contradictory_or_missing.append({
                    "type": "TEMPORAL_COVERAGE_GAP",
                    "title": g.get("title", "Recorded Telemetry Gap"),
                    "description": g.get("observed", "") + " " + g.get("missing", ""),
                    "severity": g.get("severity", "medium"),
                    "anomaly_id": g.get("id")
                })
                break

    conn.close()

    has_contradictions = len(contradictory_or_missing) > 0

    return {
        "finding_id": finding["id"],
        "case_id": case_id,
        "evidence_status": evidence_status,
        "status_message": status_message,
        "has_supporting_evidence": has_evidence,
        "supporting_event_count": len(supporting_events),
        "finding": dict(finding),
        "supporting_events": supporting_events,
        "recorded_facts": recorded_facts,
        "inferred_conclusions": inferred_conclusions,
        "contradictory_or_missing": contradictory_or_missing,
        "has_contradictions_or_gaps": has_contradictions,
        "dataset_gap_note": (
            f"Detected {len(contradictory_or_missing)} dataset anomaly/gap distinction(s) linked to this activity window."
            if has_contradictions else
            "No contradictory telemetry or missing precursor artifacts detected in the current dataset for this finding."
        )
    }

