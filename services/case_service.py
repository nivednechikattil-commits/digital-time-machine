"""
Case Management Service for Digital Time Machine.
Handles case lifecycle, demo case seeding, metric aggregation, and investigator notes.
"""

import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from database.db import get_db_connection, query_all, query_one, execute_write
from parsers.csv_parser import parse_csv_content
from parsers.json_parser import parse_json_content
from engine.correlator import run_correlation_engine
from engine.ghost_evidence import detect_ghost_evidence
from config import Config

def get_or_create_case(case_id: str, name: str, description: str = "") -> dict:
    """Retrieves an existing case or creates a new one."""
    conn = get_db_connection(Config.DATABASE_PATH)
    case = query_one(conn, "SELECT * FROM cases WHERE id = ?", (case_id,))
    if not case:
        now_iso = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        execute_write(
            conn,
            "INSERT INTO cases (id, name, description, created_at, status) VALUES (?, ?, ?, ?, ?)",
            (case_id, name, description, now_iso, "active")
        )
        case = query_one(conn, "SELECT * FROM cases WHERE id = ?", (case_id,))
    conn.close()
    return case

def list_cases() -> list[dict]:
    """Returns all investigations."""
    conn = get_db_connection(Config.DATABASE_PATH)
    cases = query_all(conn, "SELECT * FROM cases ORDER BY created_at DESC")
    conn.close()
    return cases

def get_case(case_id: str) -> dict | None:
    """Returns single case dictionary or None, supporting legacy demo ID alias."""
    conn = get_db_connection(Config.DATABASE_PATH)
    case = query_one(conn, "SELECT * FROM cases WHERE id = ?", (case_id,))
    if not case and case_id in (getattr(Config, "LEGACY_DEMO_CASE_ID", "CASE-2026-001"), "CASE-2026-001"):
        case = query_one(conn, "SELECT * FROM cases WHERE id = ?", (Config.DEMO_CASE_ID,))
    conn.close()
    return case

def load_demo_case(case_id: str = Config.DEMO_CASE_ID) -> dict:
    """
    Clears and seeds the synthetic demo investigation 'CASE-001: MISSING CUSTOMER DATABASE'.
    """
    conn = get_db_connection(Config.DATABASE_PATH)
    demo_dir = Path(Config.DEMO_DATA_DIR)
    manifest_path = demo_dir / "scenario_manifest.json"

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Use specified case_id or fallback to manifest
    actual_case_id = case_id or manifest.get("case_id", Config.DEMO_CASE_ID)

    # 1. Clear existing case data for clean demo state
    execute_write(conn, "DELETE FROM correlation_findings WHERE case_id = ?", (actual_case_id,))
    execute_write(conn, "DELETE FROM events WHERE case_id = ?", (actual_case_id,))
    execute_write(conn, "DELETE FROM evidence_files WHERE case_id = ?", (actual_case_id,))
    execute_write(conn, "DELETE FROM investigation_notes WHERE case_id = ?", (actual_case_id,))
    execute_write(conn, "DELETE FROM cases WHERE id = ?", (actual_case_id,))

    # 2. Insert case record
    execute_write(
        conn,
        "INSERT INTO cases (id, name, description, created_at, status) VALUES (?, ?, ?, ?, ?)",
        (actual_case_id, manifest["name"], manifest["description"], manifest["created_at"], "active")
    )

    all_events = []

    # 3. Ingest each synthetic evidence file
    for filename in manifest["seeded_files"]:
        filepath = demo_dir / filename
        if not filepath.exists():
            continue

        with open(filepath, "rb") as f:
            raw_bytes = f.read()

        file_hash = hashlib.sha256(raw_bytes).hexdigest()
        file_size = len(raw_bytes)
        text_content = raw_bytes.decode("utf-8", errors="replace")

        if filename.endswith(".csv"):
            valid, errors = parse_csv_content(text_content, filename=filename)
        else:
            valid, errors = parse_json_content(text_content, filename=filename)

        now_iso = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        execute_write(
            conn,
            """INSERT INTO evidence_files 
               (case_id, filename, original_filename, file_type, sha256_hash, record_count, valid_count, invalid_count, imported_at, file_size_bytes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                actual_case_id,
                filename,
                filename,
                "csv" if filename.endswith(".csv") else "json",
                file_hash,
                len(valid) + len(errors),
                len(valid),
                len(errors),
                now_iso,
                file_size
            )
        )

        for ev in valid:
            execute_write(
                conn,
                """INSERT OR REPLACE INTO events
                   (id, case_id, timestamp, source, event_type, actor, object, severity, description, evidence_ref, confidence, details, is_inferred)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    ev["id"],
                    actual_case_id,
                    ev["timestamp"],
                    ev["source"],
                    ev["event_type"],
                    ev["actor"],
                    ev["object"],
                    ev["severity"],
                    ev["description"],
                    ev["evidence_ref"],
                    ev["confidence"],
                    ev["details"],
                    ev["is_inferred"]
                )
            )
            all_events.append(ev)

    # 4. Run correlation engine and persist findings
    findings = run_correlation_engine(all_events, case_id=actual_case_id)
    for f in findings:
        execute_write(
            conn,
            """INSERT OR REPLACE INTO correlation_findings
               (id, case_id, rule_id, rule_name, severity, supporting_event_ids, explanation, start_time, end_time, confidence, limitations, recommended_action, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f["id"],
                actual_case_id,
                f["rule_id"],
                f["rule_name"],
                f["severity"],
                json.dumps(f["supporting_event_ids"]),
                f["explanation"],
                f["start_time"],
                f["end_time"],
                f["confidence"],
                f["limitations"],
                f["recommended_action"],
                f.get("status", "open")
            )
        )

    # 5. Add initial forensic triage note
    execute_write(
        conn,
        "INSERT INTO investigation_notes (case_id, timestamp, author, note) VALUES (?, ?, ?, ?)",
        (
            actual_case_id,
            datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "Lead Investigator",
            "Demo case initialized. Synthetic telemetry ingested from workstation-01 and perimeter sensors."
        )
    )

    conn.close()
    return get_case_metrics(actual_case_id)

def update_finding_status(case_id: str, finding_id: str, new_status: str) -> dict | None:
    """Updates the status of a correlation finding (e.g. open, under_review, resolved)."""
    conn = get_db_connection(Config.DATABASE_PATH)
    execute_write(
        conn,
        "UPDATE correlation_findings SET status = ? WHERE case_id = ? AND id = ?",
        (new_status, case_id, finding_id)
    )
    finding = query_one(conn, "SELECT * FROM correlation_findings WHERE case_id = ? AND id = ?", (case_id, finding_id))
    conn.close()
    return finding

def get_case_metrics(case_id: str) -> dict:
    """
    Computes live metrics directly derived from loaded SQLite dataset.
    Never uses random or changing mock counters.
    """
    conn = get_db_connection(Config.DATABASE_PATH)
    case = query_one(conn, "SELECT * FROM cases WHERE id = ?", (case_id,))
    if not case and case_id in (getattr(Config, "LEGACY_DEMO_CASE_ID", "CASE-2026-001"), "CASE-2026-001"):
        case_id = Config.DEMO_CASE_ID
        case = query_one(conn, "SELECT * FROM cases WHERE id = ?", (case_id,))
    if not case:
        conn.close()
        return {}

    events = query_all(conn, "SELECT * FROM events WHERE case_id = ? ORDER BY timestamp ASC", (case_id,))
    evidence_files = query_all(conn, "SELECT * FROM evidence_files WHERE case_id = ?", (case_id,))
    findings = query_all(conn, "SELECT * FROM correlation_findings WHERE case_id = ?", (case_id,))
    notes = query_all(conn, "SELECT * FROM investigation_notes WHERE case_id = ? ORDER BY timestamp DESC", (case_id,))

    # Ghost evidence detector analysis
    ghost_findings = detect_ghost_evidence(events, case_id=case_id)

    # Calculate distributions
    source_counts = {}
    severity_counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    observed_count = 0
    inferred_count = 0

    for ev in events:
        src = ev["source"]
        source_counts[src] = source_counts.get(src, 0) + 1
        sev = ev["severity"].lower()
        if sev in severity_counts:
            severity_counts[sev] += 1
        if ev.get("confidence") == "observed":
            observed_count += 1
        else:
            inferred_count += 1

    time_start = events[0]["timestamp"] if events else "N/A"
    time_end = events[-1]["timestamp"] if events else "N/A"

    conn.close()

    return {
        "case": case,
        "time_range": {
            "start": time_start,
            "end": time_end
        },
        "total_events": len(events),
        "observed_events": observed_count,
        "inferred_events": inferred_count,
        "source_counts": source_counts,
        "severity_counts": severity_counts,
        "evidence_files_count": len(evidence_files),
        "correlation_findings_count": len(findings),
        "ghost_anomalies_count": len(ghost_findings),
        "recent_notes": notes[:5],
        "evidence_files": evidence_files,
        "findings": findings,
        "ghost_findings": ghost_findings
    }

def add_investigation_note(case_id: str, note_text: str, author: str = "Investigator") -> dict:
    """Adds a timestamped forensic note to the investigation."""
    conn = get_db_connection(Config.DATABASE_PATH)
    now_iso = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    note_id = execute_write(
        conn,
        "INSERT INTO investigation_notes (case_id, timestamp, author, note) VALUES (?, ?, ?, ?)",
        (case_id, now_iso, author, note_text.strip())
    )
    conn.close()
    return {"id": note_id, "case_id": case_id, "timestamp": now_iso, "author": author, "note": note_text}

def get_investigation_notes(case_id: str) -> list[dict]:
    """Retrieves all notes for a case."""
    conn = get_db_connection(Config.DATABASE_PATH)
    notes = query_all(conn, "SELECT * FROM investigation_notes WHERE case_id = ? ORDER BY timestamp DESC", (case_id,))
    conn.close()
    return notes

