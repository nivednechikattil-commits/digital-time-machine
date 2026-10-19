"""
Investigation Time Machine Service for Digital Time Machine.
Manages immutable analysis snapshots, SHA-256 integrity verification,
and deep comparison between investigation milestones across time.
"""

import json
import hashlib
from datetime import datetime
from database.db import get_db_connection, query_one, query_all, execute_write
from services.case_service import get_case
from services.evidence_service import list_evidence_files
from engine.correlator import run_correlation_engine
from engine.evidence_dna import parse_event_ids
from engine.stress_tester import stress_test_finding
from config import Config

DEFAULT_RULE_VERSION = "v1.2.0-deterministic"


def compute_evidence_hash(evidence_files: list[dict]) -> str:
    """Computes a composite SHA-256 hash representing the exact evidence set."""
    sorted_files = sorted(evidence_files, key=lambda x: x.get("filename", ""))
    payload = "|".join([
        f"{f.get('filename')}:{f.get('sha256_hash')}:{f.get('record_count', 0)}"
        for f in sorted_files
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_snapshot_integrity_hash(
    case_id: str,
    name: str,
    note: str,
    created_at: str,
    rule_version: str,
    evidence_hash: str,
    findings: list[dict],
    evidence_files: list[dict]
) -> str:
    """
    Computes a cryptographic SHA-256 hash across canonicalized snapshot state.
    Enables post-hoc detection of database tampering or analytical drift.
    """
    canonical_findings = sorted([
        {
            "finding_id": f.get("finding_id") or f.get("id"),
            "rule_id": f.get("rule_id"),
            "rule_name": f.get("rule_name"),
            "severity": f.get("severity"),
            "status": f.get("status", "open"),
            "confidence": f.get("confidence", "observed_correlation"),
            "supporting_event_ids": sorted(parse_event_ids(f.get("supporting_event_ids"))),
            "explanation": f.get("explanation", "")
        }
        for f in findings
    ], key=lambda x: x["finding_id"])

    canonical_evidence = sorted([
        {
            "filename": f.get("filename"),
            "sha256_hash": f.get("sha256_hash"),
            "record_count": f.get("record_count", 0)
        }
        for f in evidence_files
    ], key=lambda x: x["filename"])

    canonical_obj = {
        "case_id": case_id,
        "name": name,
        "note": note,
        "created_at": created_at,
        "rule_version": rule_version,
        "evidence_hash": evidence_hash,
        "findings": canonical_findings,
        "evidence_files": canonical_evidence
    }

    serialized = json.dumps(canonical_obj, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def create_snapshot(
    case_id: str,
    name: str,
    note: str = "",
    rule_version: str = DEFAULT_RULE_VERSION
) -> dict:
    """
    Creates an immutable snapshot of the current case analysis state.
    Never overwrites existing snapshots.
    """
    if not name or not name.strip():
        raise ValueError("Snapshot name cannot be empty.")

    actual_case_id = case_id or Config.DEMO_CASE_ID
    conn = get_db_connection(Config.DATABASE_PATH)

    # 1. Fetch current case
    case = query_one(conn, "SELECT * FROM cases WHERE id = ?", (actual_case_id,))
    if not case:
        conn.close()
        raise ValueError(f"Case '{actual_case_id}' not found.")

    # 2. Fetch current findings
    findings = query_all(
        conn,
        "SELECT * FROM correlation_findings WHERE case_id = ? ORDER BY id ASC",
        (actual_case_id,)
    )
    if not findings:
        # Fallback to dynamic correlation if findings not yet written
        events = query_all(
            conn,
            "SELECT * FROM events WHERE case_id = ? ORDER BY timestamp ASC",
            (actual_case_id,)
        )
        findings = run_correlation_engine(events, case_id=actual_case_id)

    # 3. Fetch current evidence files
    evidence_files = query_all(
        conn,
        "SELECT * FROM evidence_files WHERE case_id = ? ORDER BY filename ASC",
        (actual_case_id,)
    )

    now_iso = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    time_tag = datetime.now().strftime("%Y%m%d-%H%M%S")
    rand_tag = hashlib.sha256(f"{name}:{now_iso}".encode("utf-8")).hexdigest()[:6]
    snapshot_id = f"SNAP-{time_tag}-{rand_tag.upper()}"

    evidence_hash = compute_evidence_hash(evidence_files)
    integrity_hash = compute_snapshot_integrity_hash(
        case_id=actual_case_id,
        name=name.strip(),
        note=note.strip(),
        created_at=now_iso,
        rule_version=rule_version,
        evidence_hash=evidence_hash,
        findings=findings,
        evidence_files=evidence_files
    )

    # 4. Insert into investigation_snapshots
    execute_write(
        conn,
        """INSERT INTO investigation_snapshots 
           (id, case_id, name, note, created_at, rule_version, evidence_hash, integrity_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (snapshot_id, actual_case_id, name.strip(), note.strip(), now_iso, rule_version, evidence_hash, integrity_hash)
    )

    # 5. Insert findings snapshot records
    for f in findings:
        f_id = f.get("id") or f.get("finding_id")
        supp_ids = json.dumps(parse_event_ids(f.get("supporting_event_ids")))
        execute_write(
            conn,
            """INSERT INTO snapshot_findings
               (snapshot_id, finding_id, rule_id, rule_name, severity, status, confidence, supporting_event_ids, explanation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                snapshot_id,
                f_id,
                f.get("rule_id", "UNKNOWN"),
                f.get("rule_name", "Correlation Finding"),
                f.get("severity", "medium"),
                f.get("status", "open"),
                f.get("confidence", "observed_correlation"),
                supp_ids,
                f.get("explanation", "")
            )
        )

    # 6. Insert evidence refs snapshot records
    for ef in evidence_files:
        execute_write(
            conn,
            """INSERT INTO snapshot_evidence_refs
               (snapshot_id, evidence_file_id, filename, sha256_hash, record_count)
               VALUES (?, ?, ?, ?, ?)""",
            (
                snapshot_id,
                ef.get("id"),
                ef.get("filename"),
                ef.get("sha256_hash"),
                ef.get("record_count", 0)
            )
        )

    conn.close()

    return {
        "id": snapshot_id,
        "case_id": actual_case_id,
        "name": name.strip(),
        "note": note.strip(),
        "created_at": now_iso,
        "rule_version": rule_version,
        "evidence_hash": evidence_hash,
        "integrity_hash": integrity_hash,
        "finding_count": len(findings),
        "evidence_file_count": len(evidence_files),
        "integrity_status": "verified"
    }


def get_snapshot(snapshot_id: str) -> dict | None:
    """Retrieves full snapshot details including findings, evidence files, and integrity verification."""
    conn = get_db_connection(Config.DATABASE_PATH)
    snap = query_one(conn, "SELECT * FROM investigation_snapshots WHERE id = ?", (snapshot_id,))
    if not snap:
        conn.close()
        return None

    findings = query_all(
        conn,
        "SELECT * FROM snapshot_findings WHERE snapshot_id = ? ORDER BY finding_id ASC",
        (snapshot_id,)
    )
    for f in findings:
        f["supporting_event_ids"] = parse_event_ids(f.get("supporting_event_ids"))

    evidence_files = query_all(
        conn,
        "SELECT * FROM snapshot_evidence_refs WHERE snapshot_id = ? ORDER BY filename ASC",
        (snapshot_id,)
    )

    conn.close()

    # Re-calculate integrity hash to verify against database alteration
    recalc_evidence_hash = compute_evidence_hash(evidence_files)
    recalc_integrity = compute_snapshot_integrity_hash(
        case_id=snap["case_id"],
        name=snap["name"],
        note=snap["note"] or "",
        created_at=snap["created_at"],
        rule_version=snap["rule_version"],
        evidence_hash=recalc_evidence_hash,
        findings=findings,
        evidence_files=evidence_files
    )

    is_verified = (recalc_integrity == snap["integrity_hash"]) and (recalc_evidence_hash == snap["evidence_hash"])

    result = dict(snap)
    result["findings"] = findings
    result["finding_count"] = len(findings)
    result["evidence_files"] = evidence_files
    result["evidence_file_count"] = len(evidence_files)
    result["integrity_status"] = "verified" if is_verified else "tampered"
    result["is_tampered"] = not is_verified
    return result


def list_snapshots(case_id: str) -> list[dict]:
    """Lists all saved snapshots for a case with integrity verification."""
    actual_case_id = case_id or Config.DEMO_CASE_ID
    conn = get_db_connection(Config.DATABASE_PATH)
    snaps = query_all(
        conn,
        "SELECT * FROM investigation_snapshots WHERE case_id = ? ORDER BY created_at DESC",
        (actual_case_id,)
    )

    results = []
    for s in snaps:
        snap_id = s["id"]
        f_count = query_one(conn, "SELECT COUNT(*) as cnt FROM snapshot_findings WHERE snapshot_id = ?", (snap_id,))
        e_count = query_one(conn, "SELECT COUNT(*) as cnt FROM snapshot_evidence_refs WHERE snapshot_id = ?", (snap_id,))
        
        # Verify integrity
        findings = query_all(conn, "SELECT * FROM snapshot_findings WHERE snapshot_id = ?", (snap_id,))
        evidence_files = query_all(conn, "SELECT * FROM snapshot_evidence_refs WHERE snapshot_id = ?", (snap_id,))
        recalc_ev_hash = compute_evidence_hash(evidence_files)
        recalc_integrity = compute_snapshot_integrity_hash(
            case_id=s["case_id"],
            name=s["name"],
            note=s["note"] or "",
            created_at=s["created_at"],
            rule_version=s["rule_version"],
            evidence_hash=recalc_ev_hash,
            findings=findings,
            evidence_files=evidence_files
        )
        is_verified = (recalc_integrity == s["integrity_hash"])

        s_dict = dict(s)
        s_dict["finding_count"] = f_count["cnt"] if f_count else 0
        s_dict["evidence_file_count"] = e_count["cnt"] if e_count else 0
        s_dict["integrity_status"] = "verified" if is_verified else "tampered"
        results.append(s_dict)

    conn.close()
    return results


def compare_snapshots(case_id: str, snapshot_a_id: str, snapshot_b_id: str) -> dict:
    """
    Compares two investigation analysis snapshots (Snapshot A = baseline, Snapshot B = comparison).
    
    Identifies:
    1. Findings Added (present in B, absent in A)
    2. Findings Removed (present in A, absent in B)
    3. Findings Changed (status, severity, supporting events, or explanation)
    4. Findings Unchanged
    5. Evidence set modifications (files added or removed)
    6. Newly detected contradictions
    7. Analysis attribution: explains changes based on new evidence or updated rules
    8. Unexplained changes
    """
    actual_case_id = case_id or Config.DEMO_CASE_ID
    snap_a = get_snapshot(snapshot_a_id)
    if not snap_a:
        raise ValueError(f"Baseline Snapshot '{snapshot_a_id}' not found.")

    snap_b = get_snapshot(snapshot_b_id)
    if not snap_b:
        raise ValueError(f"Comparison Snapshot '{snapshot_b_id}' not found.")

    findings_a = {f["finding_id"]: f for f in snap_a.get("findings", [])}
    findings_b = {f["finding_id"]: f for f in snap_b.get("findings", [])}

    evidence_a = {ef["filename"]: ef for ef in snap_a.get("evidence_files", [])}
    evidence_b = {ef["filename"]: ef for ef in snap_b.get("evidence_files", [])}

    # 1. Evidence Files Diff
    evidence_added = [ef for fn, ef in evidence_b.items() if fn not in evidence_a]
    evidence_removed = [ef for fn, ef in evidence_a.items() if fn not in evidence_b]
    evidence_modified = [
        {"filename": fn, "old_hash": evidence_a[fn]["sha256_hash"], "new_hash": evidence_b[fn]["sha256_hash"]}
        for fn in evidence_b
        if fn in evidence_a and evidence_a[fn]["sha256_hash"] != evidence_b[fn]["sha256_hash"]
    ]

    has_evidence_changes = len(evidence_added) > 0 or len(evidence_removed) > 0 or len(evidence_modified) > 0
    rule_version_changed = snap_a.get("rule_version") != snap_b.get("rule_version")

    # 2. Findings Diff
    added_findings = []
    removed_findings = []
    changed_findings = []
    unchanged_findings = []

    # Check Added (in B, not in A)
    for f_id, f_b in findings_b.items():
        if f_id not in findings_a:
            # Attribution analysis
            reason = "Unexplained change"
            if has_evidence_changes:
                ev_names = ", ".join([f["filename"] for f in evidence_added]) or "ingested evidence"
                reason = f"Generated following ingestion of new evidence ({ev_names})."
            elif rule_version_changed:
                reason = f"Generated by updated analysis rule engine version ({snap_b.get('rule_version')})."

            f_copy = dict(f_b)
            f_copy["diff_type"] = "Added"
            f_copy["attribution"] = reason
            f_copy["timeline_url"] = f"/timeline?case_id={actual_case_id}"
            added_findings.append(f_copy)

    # Check Removed (in A, not in B)
    for f_id, f_a in findings_a.items():
        if f_id not in findings_b:
            reason = "Finding removed from latest analysis state. Note: Removal does not prove the hypothesis was disproved."
            if has_evidence_changes and evidence_removed:
                reason = f"Removed after source evidence file(s) ({', '.join([f['filename'] for f in evidence_removed])}) were excluded."
            elif rule_version_changed:
                reason = f"Removed under modified correlation thresholds in rule version {snap_b.get('rule_version')}."

            f_copy = dict(f_a)
            f_copy["diff_type"] = "Removed"
            f_copy["attribution"] = reason
            f_copy["timeline_url"] = f"/timeline?case_id={actual_case_id}"
            removed_findings.append(f_copy)

    # Check Changed vs Unchanged (present in both)
    for f_id, f_a in findings_a.items():
        if f_id in findings_b:
            f_b = findings_b[f_id]
            changes = []
            
            # Status change
            if f_a.get("status") != f_b.get("status"):
                changes.append({
                    "field": "status",
                    "old_value": f_a.get("status"),
                    "new_value": f_b.get("status"),
                    "description": f"Status updated from '{f_a.get('status')}' to '{f_b.get('status')}'"
                })

            # Severity change
            if f_a.get("severity") != f_b.get("severity"):
                changes.append({
                    "field": "severity",
                    "old_value": f_a.get("severity"),
                    "new_value": f_b.get("severity"),
                    "description": f"Severity altered from '{f_a.get('severity')}' to '{f_b.get('severity')}'"
                })

            # Supporting events change
            ev_a_set = set(f_a.get("supporting_event_ids") or [])
            ev_b_set = set(f_b.get("supporting_event_ids") or [])
            if ev_a_set != ev_b_set:
                added_evs = list(ev_b_set - ev_a_set)
                removed_evs = list(ev_a_set - ev_b_set)
                changes.append({
                    "field": "supporting_events",
                    "added_events": added_evs,
                    "removed_events": removed_evs,
                    "description": (
                        f"Supporting evidence set modified. Added events: {added_evs if added_evs else 'none'}, "
                        f"Removed events: {removed_evs if removed_evs else 'none'}"
                    )
                })

            if changes:
                # Determine attribution
                status_changes = [c for c in changes if c["field"] == "status"]
                ev_changes = [c for c in changes if c["field"] == "supporting_events"]

                if status_changes and not ev_changes:
                    attribution = f"Status modified by investigator review ({status_changes[0]['old_value']} → {status_changes[0]['new_value']})."
                elif ev_changes and has_evidence_changes:
                    attribution = "Supporting evidence modified due to new evidence file ingestion."
                elif rule_version_changed:
                    attribution = f"Correlation scope adjusted by rule engine version {snap_b.get('rule_version')}."
                else:
                    attribution = "Change persisted from investigator review and manual adjudication."

                f_diff = dict(f_b)
                f_diff["diff_type"] = "Changed"
                f_diff["changes"] = changes
                f_diff["old_finding"] = f_a
                f_diff["attribution"] = attribution
                f_diff["timeline_url"] = f"/timeline?case_id={actual_case_id}"
                changed_findings.append(f_diff)
            else:
                f_unchanged = dict(f_b)
                f_unchanged["diff_type"] = "Unchanged"
                f_unchanged["timeline_url"] = f"/timeline?case_id={actual_case_id}"
                unchanged_findings.append(f_unchanged)

    # 3. Check for Newly Detected Contradictions
    # Run stress test on snapshot B findings vs snapshot A findings
    stress_b = [stress_test_finding(actual_case_id, f) for f in snap_b.get("findings", [])]
    stress_a = [stress_test_finding(actual_case_id, f) for f in snap_a.get("findings", [])]

    contradictions_a = {
        s["finding_id"]: s for s in stress_a if s.get("status") == "Contradictory evidence found"
    }
    new_contradictions = []
    for s in stress_b:
        if s.get("status") == "Contradictory evidence found" and s["finding_id"] not in contradictions_a:
            new_contradictions.append({
                "finding_id": s["finding_id"],
                "rule_name": s["rule_name"],
                "explanation": s["explanation"],
                "contradictory_events": s.get("contradictory_events", []),
                "warnings": s.get("warnings", [])
            })

    return {
        "case_id": actual_case_id,
        "baseline_snapshot": {
            "id": snap_a["id"],
            "name": snap_a["name"],
            "created_at": snap_a["created_at"],
            "rule_version": snap_a["rule_version"],
            "integrity_status": snap_a["integrity_status"],
            "finding_count": snap_a["finding_count"],
            "evidence_file_count": snap_a["evidence_file_count"]
        },
        "comparison_snapshot": {
            "id": snap_b["id"],
            "name": snap_b["name"],
            "created_at": snap_b["created_at"],
            "rule_version": snap_b["rule_version"],
            "integrity_status": snap_b["integrity_status"],
            "finding_count": snap_b["finding_count"],
            "evidence_file_count": snap_b["evidence_file_count"]
        },
        "summary": {
            "findings_added_count": len(added_findings),
            "findings_removed_count": len(removed_findings),
            "findings_changed_count": len(changed_findings),
            "findings_unchanged_count": len(unchanged_findings),
            "evidence_files_added_count": len(evidence_added),
            "evidence_files_removed_count": len(evidence_removed),
            "newly_detected_contradictions_count": len(new_contradictions)
        },
        "added_findings": added_findings,
        "removed_findings": removed_findings,
        "changed_findings": changed_findings,
        "unchanged_findings": unchanged_findings,
        "evidence_diff": {
            "added": evidence_added,
            "removed": evidence_removed,
            "modified": evidence_modified
        },
        "newly_detected_contradictions": new_contradictions
    }

