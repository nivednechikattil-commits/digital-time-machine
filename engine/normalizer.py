"""
Event Normalizer for Digital Time Machine.
Validates, normalizes timestamps, sources, severities, and event schemas.
"""

from datetime import datetime, timezone
import re
import json

VALID_SOURCES = {"login", "browser", "file", "network", "usb", "system", "auth"}
SOURCE_ALIASES = {
    "auth": "login",
    "authentication": "login",
    "logon": "login",
    "web": "browser",
    "http": "browser",
    "disk": "file",
    "filesystem": "file",
    "net": "network",
    "traffic": "network",
    "device": "usb",
    "drive": "usb"
}

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
SEVERITY_ALIASES = {
    "info": "low",
    "informational": "low",
    "warn": "medium",
    "warning": "medium",
    "error": "high",
    "alert": "high",
    "crit": "critical",
    "severe": "critical"
}

REQUIRED_FIELDS = ["timestamp", "source", "event_type", "actor", "object"]

def normalize_timestamp(raw_ts: str | int | float) -> str:
    """
    Normalizes a timestamp into standard ISO format: YYYY-MM-DDTHH:MM:SS.
    Handles ISO strings, common datetime strings, and unix epochs.
    Raises ValueError if unparseable.
    """
    if raw_ts is None:
        raise ValueError("Timestamp cannot be null or empty")

    # If epoch numeric
    if isinstance(raw_ts, (int, float)):
        # Check if ms or sec
        if raw_ts > 1e11:
            raw_ts = raw_ts / 1000.0
        dt = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S")

    ts_str = str(raw_ts).strip()
    if not ts_str:
        raise ValueError("Timestamp string is empty")

    # If numeric string
    if ts_str.replace(".", "", 1).isdigit():
        val = float(ts_str)
        if val > 1e11:
            val = val / 1000.0
        dt = datetime.fromtimestamp(val, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S")

    # Common formats to try
    formats = [
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y/%m/%d %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%Y-%m-%d",
    ]

    # Handle ISO strings with timezone offsets like +00:00 or -05:00
    iso_match = re.sub(r"([+-]\d{2}):(\d{2})$", r"\1\2", ts_str)
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt.strftime("%Y-%m-%dT%H:%M:%S")
    except ValueError:
        pass

    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str, fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%S")
        except ValueError:
            continue

    raise ValueError(f"Unsupported timestamp format: '{raw_ts}'")

def normalize_source(raw_source: str) -> str:
    """Normalizes source name into standard category."""
    if not raw_source:
        return "system"
    clean = str(raw_source).strip().lower()
    clean = SOURCE_ALIASES.get(clean, clean)
    if clean in VALID_SOURCES:
        return clean
    return clean if clean else "system"

def normalize_severity(raw_sev: str) -> str:
    """Normalizes severity to low, medium, high, critical."""
    if not raw_sev:
        return "low"
    clean = str(raw_sev).strip().lower()
    clean = SEVERITY_ALIASES.get(clean, clean)
    if clean in VALID_SEVERITIES:
        return clean
    return "low"

def validate_and_normalize_event(record: dict, default_evidence_ref: str = "imported_evidence") -> dict:
    """
    Validates a raw event record dictionary and returns a normalized event dictionary.
    Raises ValueError with a helpful message on invalid records.
    """
    if not isinstance(record, dict):
        raise ValueError("Record must be a JSON/dict object")

    missing = [f for f in REQUIRED_FIELDS if f not in record or record[f] is None or str(record[f]).strip() == ""]
    if missing:
        raise ValueError(f"Missing required field(s): {', '.join(missing)}")

    norm_ts = normalize_timestamp(record["timestamp"])
    norm_source = normalize_source(record["source"])
    norm_sev = normalize_severity(record.get("severity", "low"))
    event_type = str(record["event_type"]).strip().upper()
    actor = str(record["actor"]).strip()
    obj = str(record["object"]).strip()

    event_id = str(record.get("id") or "").strip()
    if not event_id:
        # Generate stable identifier from content
        import hashlib
        hash_seed = f"{norm_ts}_{norm_source}_{event_type}_{actor}_{obj}"
        event_id = "EVT-" + hashlib.md5(hash_seed.encode("utf-8")).hexdigest()[:8].upper()

    description = str(record.get("description") or f"{event_type} on {obj} by {actor}").strip()
    evidence_ref = str(record.get("evidence_ref") or default_evidence_ref).strip()
    confidence = str(record.get("confidence") or "observed").strip().lower()
    if confidence not in {"observed", "inferred"}:
        confidence = "observed"

    # Extract extra details
    details = record.get("details", {})
    if isinstance(details, str):
        try:
            details = json.loads(details)
        except json.JSONDecodeError:
            details = {"raw_text": details}
    elif not isinstance(details, dict):
        details = {"value": str(details)}

    # Include any non-standard fields from top level into details
    standard_keys = {
        "id", "timestamp", "source", "event_type", "actor", "object",
        "severity", "description", "evidence_ref", "confidence", "details",
        "case_id", "is_inferred"
    }
    for k, v in record.items():
        if k not in standard_keys and k not in details:
            details[k] = v

    is_inferred = 1 if confidence == "inferred" or record.get("is_inferred") in (1, True, "true") else 0

    return {
        "id": event_id,
        "timestamp": norm_ts,
        "source": norm_source,
        "event_type": event_type,
        "actor": actor,
        "object": obj,
        "severity": norm_sev,
        "description": description,
        "evidence_ref": evidence_ref,
        "confidence": confidence,
        "details": json.dumps(details),
        "is_inferred": is_inferred
    }

