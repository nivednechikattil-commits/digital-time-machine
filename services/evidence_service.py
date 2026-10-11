"""
Evidence Ingestion and Query Service for Digital Time Machine.
Handles safe evidence ingestion, file hashing, duplicate prevention, and event querying.
"""

import os
import re
import json
import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path
from database.db import get_db_connection, query_all, query_one, execute_write
from parsers.csv_parser import parse_csv_content
from parsers.json_parser import parse_json_content
from engine.correlator import run_correlation_engine
from config import Config

def sanitize_filename(filename: str) -> str:
    """Sanitizes filename against path traversal and dangerous characters."""
    clean = os.path.basename(filename)
    clean = re.sub(r"[^a-zA-Z0-9_\.\-]", "_", clean)
    return clean or "uploaded_evidence"

def import_evidence_file(case_id: str, file_bytes: bytes, original_filename: str) -> dict:
    """
    Safely imports an evidence file (CSV or JSON).
    Calculates SHA-256, verifies duplicate status, parses records, stores normalized events,
    and recalculates correlation findings.
    """
    clean_name = sanitize_filename(original_filename)
    ext = clean_name.rsplit(".", 1)[-1].lower() if "." in clean_name else ""

    if ext not in Config.ALLOWED_EXTENSIONS:
        return {
            "success": False,
            "error": f"Unsupported file extension '.{ext}'. Supported formats: CSV, JSON.",
            "accepted": 0,
            "rejected": 0,
            "errors": []
        }

    if not file_bytes or len(file_bytes.strip()) == 0:
        return {
            "success": False,
            "error": "Uploaded evidence file is empty (0 bytes).",
            "accepted": 0,
            "rejected": 0,
            "errors": []
        }

    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    file_size = len(file_bytes)

    conn = get_db_connection(Config.DATABASE_PATH)

    # Ensure case exists to satisfy foreign key constraints
    case_record = query_one(conn, "SELECT id FROM cases WHERE id = ?", (case_id,))
    if not case_record:
        now_case = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
        execute_write(
            conn,
            "INSERT INTO cases (id, name, description, created_at, status) VALUES (?, ?, ?, ?, ?)",
            (case_id, f"Investigation {case_id}", "Active forensic investigation", now_case, "active")
        )

    # Check for duplicate import of identical file using SHA-256 hash as primary key
    if case_id:
        existing = query_one(
            conn,
            "SELECT * FROM evidence_files WHERE case_id = ? AND sha256_hash = ?",
            (case_id, sha256_hash)
        )
    else:
        existing = query_one(
            conn,
            "SELECT * FROM evidence_files WHERE sha256_hash = ?",
            (sha256_hash,)
        )
    if existing:
        conn.close()
        return {
            "success": False,
            "error": "Duplicate evidence detected. This file has already been ingested.",
            "message": "Duplicate evidence detected. This file has already been ingested.",
            "duplicate": True,
            "sha256": sha256_hash,
            "filename": clean_name,
            "existing_file": dict(existing),
            "accepted": 0,
            "rejected": 0,
            "errors": []
        }

    text_content = file_bytes.decode("utf-8", errors="replace")

    if ext == "csv":
        valid_records, errors = parse_csv_content(text_content, filename=clean_name)
    else:
        valid_records, errors = parse_json_content(text_content, filename=clean_name)

    if len(valid_records) == 0:
        conn.close()
        first_err = errors[0]["error"] if errors else "No valid event records identified."
        return {
            "success": False,
            "error": f"Uploaded file contains no valid event records: {first_err}",
            "accepted": 0,
            "rejected": len(errors),
            "errors": errors
        }

    # Save copy of raw evidence in uploads folder safely
    upload_dir = Path(Config.UPLOAD_FOLDER)
    upload_dir.mkdir(parents=True, exist_ok=True)
    saved_path = upload_dir / f"{case_id}_{sha256_hash[:10]}_{clean_name}"
    with open(saved_path, "wb") as f:
        f.write(file_bytes)

    now_iso = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    # Record evidence file metadata with concurrency duplicate protection
    try:
        execute_write(
            conn,
            """INSERT INTO evidence_files 
               (case_id, filename, original_filename, file_type, sha256_hash, record_count, valid_count, invalid_count, imported_at, file_size_bytes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                case_id,
                clean_name,
                original_filename,
                ext,
                sha256_hash,
                len(valid_records) + len(errors),
                len(valid_records),
                len(errors),
                now_iso,
                file_size
            )
        )
    except sqlite3.IntegrityError:
        # Caught by UNIQUE index on (case_id, sha256_hash)
        existing = query_one(
            conn,
            "SELECT * FROM evidence_files WHERE case_id = ? AND sha256_hash = ?",
            (case_id, sha256_hash)
        )
        conn.close()
        return {
            "success": False,
            "error": "Duplicate evidence detected. This file has already been ingested.",
            "message": "Duplicate evidence detected. This file has already been ingested.",
            "duplicate": True,
            "sha256": sha256_hash,
            "filename": clean_name,
            "existing_file": dict(existing) if existing else None,
            "accepted": 0,
            "rejected": 0,
            "errors": []
        }

    # Insert valid records
    accepted_count = 0
    for ev in valid_records:
        execute_write(
            conn,
            """INSERT OR REPLACE INTO events
               (id, case_id, timestamp, source, event_type, actor, object, severity, description, evidence_ref, confidence, details, is_inferred)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ev["id"],
                case_id,
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
        accepted_count += 1

    # Re-run correlation engine across all case events to incorporate new evidence
    all_case_events = query_all(conn, "SELECT * FROM events WHERE case_id = ? ORDER BY timestamp ASC", (case_id,))
    findings = run_correlation_engine(all_case_events, case_id=case_id)
    for f in findings:
        existing_status = query_one(conn, "SELECT status FROM correlation_findings WHERE case_id = ? AND id = ?", (case_id, f["id"]))
        status_val = existing_status["status"] if existing_status and existing_status.get("status") else f.get("status", "open")
        execute_write(
            conn,
            """INSERT OR REPLACE INTO correlation_findings
               (id, case_id, rule_id, rule_name, severity, supporting_event_ids, explanation, start_time, end_time, confidence, limitations, recommended_action, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f["id"],
                case_id,
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
                status_val
            )
        )

    conn.close()

    return {
        "success": True,
        "filename": clean_name,
        "sha256": sha256_hash,
        "file_size": file_size,
        "total_records": len(valid_records) + len(errors),
        "accepted": accepted_count,
        "rejected": len(errors),
        "errors": errors[:25]  # Cap errors in response to prevent huge payloads
    }

def get_events(
    case_id: str,
    source: str | None = None,
    severity: str | None = None,
    actor: str | None = None,
    until_timestamp: str | None = None
) -> list[dict]:
    """Retrieves events for a case with optional forensic filters, supporting legacy demo ID."""
    conn = get_db_connection(Config.DATABASE_PATH)
    actual_case_id = case_id
    if actual_case_id in (getattr(Config, "LEGACY_DEMO_CASE_ID", "CASE-2026-001"), "CASE-2026-001"):
        # Check if legacy case exists, otherwise map to current demo case
        exists = query_one(conn, "SELECT id FROM cases WHERE id = ?", (actual_case_id,))
        if not exists:
            actual_case_id = Config.DEMO_CASE_ID

    sql = "SELECT * FROM events WHERE case_id = ?"
    params = [actual_case_id]

    if source:
        sql += " AND source = ?"
        params.append(source.lower())
    if severity:
        sql += " AND severity = ?"
        params.append(severity.lower())
    if actor:
        sql += " AND actor = ?"
        params.append(actor)
    if until_timestamp:
        sql += " AND timestamp <= ?"
        params.append(until_timestamp)

    sql += " ORDER BY timestamp ASC"
    events = query_all(conn, sql, tuple(params))
    conn.close()
    return events

def get_event_by_id(case_id: str, event_id: str) -> dict | None:
    """Retrieves single event by ID, supporting legacy demo ID."""
    conn = get_db_connection(Config.DATABASE_PATH)
    actual_case_id = case_id
    if actual_case_id in (getattr(Config, "LEGACY_DEMO_CASE_ID", "CASE-2026-001"), "CASE-2026-001"):
        exists = query_one(conn, "SELECT id FROM cases WHERE id = ?", (actual_case_id,))
        if not exists:
            actual_case_id = Config.DEMO_CASE_ID

    event = query_one(conn, "SELECT * FROM events WHERE case_id = ? AND id = ?", (actual_case_id, event_id))
    conn.close()
    return event

def list_evidence_files(case_id: str) -> list[dict]:
    """Retrieves list of all imported evidence files for a case, supporting legacy demo ID."""
    conn = get_db_connection(Config.DATABASE_PATH)
    actual_case_id = case_id
    if actual_case_id in (getattr(Config, "LEGACY_DEMO_CASE_ID", "CASE-2026-001"), "CASE-2026-001"):
        exists = query_one(conn, "SELECT id FROM cases WHERE id = ?", (actual_case_id,))
        if not exists:
            actual_case_id = Config.DEMO_CASE_ID

    files = query_all(conn, "SELECT * FROM evidence_files WHERE case_id = ? ORDER BY imported_at DESC", (actual_case_id,))
    conn.close()
    return files

