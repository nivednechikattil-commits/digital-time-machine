"""
Evidence Ingestion and Query Service for Digital Time Machine.
Handles safe evidence ingestion, file hashing, duplicate prevention, and event querying.
"""

import os
import re
import json
import hashlib
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

    sha256_hash = hashlib.sha256(file_bytes).hexdigest()
    file_size = len(file_bytes)

    conn = get_db_connection(Config.DATABASE_PATH)

    # Check for duplicate import of identical file in the same case
    existing = query_one(
        conn,
        "SELECT * FROM evidence_files WHERE case_id = ? AND sha256_hash = ?",
        (case_id, sha256_hash)
    )
    if existing:
        conn.close()
        return {
            "success": False,
            "error": f"Duplicate evidence file: '{clean_name}' (SHA-256: {sha256_hash[:12]}...) was already imported into this case on {existing['imported_at']}.",
            "duplicate": True,
            "sha256": sha256_hash,
            "accepted": 0,
            "rejected": 0,
            "errors": []
        }

    # Save copy of raw evidence in uploads folder safely
    upload_dir = Path(Config.UPLOAD_FOLDER)
    upload_dir.mkdir(parents=True, exist_ok=True)
    saved_path = upload_dir / f"{case_id}_{sha256_hash[:10]}_{clean_name}"
    with open(saved_path, "wb") as f:
        f.write(file_bytes)

    text_content = file_bytes.decode("utf-8", errors="replace")

    if ext == "csv":
        valid_records, errors = parse_csv_content(text_content, filename=clean_name)
    else:
        valid_records, errors = parse_json_content(text_content, filename=clean_name)

    now_iso = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")

    # Record evidence file metadata
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
        execute_write(
            conn,
            """INSERT OR REPLACE INTO correlation_findings
               (id, case_id, rule_id, rule_name, severity, supporting_event_ids, explanation, start_time, end_time, confidence, limitations, recommended_action)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
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
                f["recommended_action"]
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
    """Retrieves events for a case with optional forensic filters."""
    conn = get_db_connection(Config.DATABASE_PATH)
    sql = "SELECT * FROM events WHERE case_id = ?"
    params = [case_id]

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
    """Retrieves single event by ID."""
    conn = get_db_connection(Config.DATABASE_PATH)
    event = query_one(conn, "SELECT * FROM events WHERE case_id = ? AND id = ?", (case_id, event_id))
    conn.close()
    return event

def list_evidence_files(case_id: str) -> list[dict]:
    """Retrieves list of all imported evidence files for a case."""
    conn = get_db_connection(Config.DATABASE_PATH)
    files = query_all(conn, "SELECT * FROM evidence_files WHERE case_id = ? ORDER BY imported_at DESC", (case_id,))
    conn.close()
    return files

