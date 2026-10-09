"""
JSON Evidence Parser for Digital Time Machine.
Parses JSON arrays, wrappers, or JSONL files into normalized forensic events.
"""

import json
from engine.normalizer import validate_and_normalize_event

def parse_json_content(content: str, filename: str = "upload.json") -> tuple[list[dict], list[dict]]:
    """
    Parses a JSON or JSONL string, normalizes each record, and returns (valid_records, rejection_errors).
    """
    valid_records = []
    errors = []
    content = content.strip()

    if not content:
        return [], [{"line_number": 1, "row_data": None, "error": "JSON file is empty"}]

    records_to_process = []

    # Attempt to parse as standard JSON
    try:
        data = json.loads(content)
        if isinstance(data, list):
            records_to_process = list(enumerate(data, start=1))
        elif isinstance(data, dict):
            # Check for wrapper keys like "events", "data", "records"
            found_array = None
            for key in ["events", "data", "records", "logs"]:
                if key in data and isinstance(data[key], list):
                    found_array = data[key]
                    break
            if found_array is not None:
                records_to_process = list(enumerate(found_array, start=1))
            else:
                records_to_process = [(1, data)]
        else:
            return [], [{"line_number": 1, "row_data": None, "error": "Root JSON must be an object or array"}]
    except json.JSONDecodeError:
        # Try JSON Lines (line by line)
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                item = json.loads(line_str)
                records_to_process.append((idx, item))
            except json.JSONDecodeError as je:
                errors.append({
                    "line_number": idx,
                    "row_data": line_str[:100],
                    "error": f"Invalid JSON on line {idx}: {str(je)}"
                })

    for idx, raw_record in records_to_process:
        try:
            norm_event = validate_and_normalize_event(raw_record, default_evidence_ref=filename)
            valid_records.append(norm_event)
        except Exception as err:
            errors.append({
                "line_number": idx,
                "row_data": raw_record if isinstance(raw_record, dict) else str(raw_record)[:100],
                "error": str(err)
            })

    return valid_records, errors

