"""
CSV Evidence Parser for Digital Time Machine.
Parses CSV files into normalized forensic events while collecting validation diagnostics.
"""

import csv
import io
from engine.normalizer import validate_and_normalize_event

def parse_csv_content(content: str, filename: str = "upload.csv") -> tuple[list[dict], list[dict]]:
    """
    Parses a CSV string, normalizes each record, and returns (valid_records, rejection_errors).
    Each error contains {line_number, row_data, error}.
    """
    valid_records = []
    errors = []

    f = io.StringIO(content.strip())
    # Detect dialect or fallback to standard excel
    try:
        sample = content[:2048]
        try:
            dialect = csv.Sniffer().sniff(sample)
        except csv.Error:
            dialect = csv.excel
        f.seek(0)
        reader = csv.DictReader(f, dialect=dialect)
    except Exception as e:
        return [], [{"line_number": 1, "row_data": None, "error": f"Failed to parse CSV headers: {str(e)}"}]

    if not reader.fieldnames:
        return [], [{"line_number": 1, "row_data": None, "error": "CSV file contains no headers"}]

    # Normalize fieldnames to lowercase and trimmed
    fieldnames_map = {name: name.strip().lower() for name in reader.fieldnames if name}

    for idx, row in enumerate(reader, start=2):
        if not any(v.strip() for v in row.values() if isinstance(v, str)):
            # Skip empty lines
            continue

        # Remap row keys
        normalized_row = {}
        for k, v in row.items():
            if k is not None:
                clean_k = fieldnames_map.get(k, k.strip().lower())
                normalized_row[clean_k] = v.strip() if isinstance(v, str) else v

        try:
            norm_event = validate_and_normalize_event(normalized_row, default_evidence_ref=filename)
            valid_records.append(norm_event)
        except Exception as err:
            errors.append({
                "line_number": idx,
                "row_data": normalized_row,
                "error": str(err)
            })

    return valid_records, errors

