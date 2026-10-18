"""
Digital Time Machine — Interactive Digital Forensics & Cyber Incident Reconstruction Platform.
Main Flask Application and API Router.
"""

import os
import io
import csv
import json
from datetime import datetime
from pathlib import Path

from flask import (
    Flask, request, jsonify, render_template, redirect, Response,
    set_active_flask_app
)

from config import Config
from database.db import init_db
from services.case_service import (
    get_or_create_case, list_cases, get_case, load_demo_case,
    get_case_metrics, add_investigation_note, get_investigation_notes,
    update_finding_status
)
from services.evidence_service import (
    import_evidence_file, get_events, get_event_by_id, list_evidence_files
)
from engine.state_reconstructor import reconstruct_system_state
from engine.correlator import run_correlation_engine
from engine.ghost_evidence import detect_ghost_evidence
from engine.graph_generator import generate_relationship_graph
from engine.investigator import get_all_investigative_inquiries, answer_investigative_query
from engine.report_generator import generate_investigation_report_data
from engine.evidence_dna import get_evidence_dna
from engine.stress_tester import stress_test_finding, stress_test_case, stress_test_custom_conclusion
from services.snapshot_service import create_snapshot, list_snapshots, get_snapshot, compare_snapshots

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config.from_object(Config)
set_active_flask_app(app)

# Ensure database and upload folders are initialized
init_db(Config.DATABASE_PATH)
Path(Config.UPLOAD_FOLDER).mkdir(parents=True, exist_ok=True)

# Pre-seed demo case on first start if not already present
if not get_case(Config.DEMO_CASE_ID):
    load_demo_case(Config.DEMO_CASE_ID)


def get_current_case_id() -> str:
    """Helper to extract case_id from query params or fallback to demo case."""
    return request.args.get("case_id") or Config.DEMO_CASE_ID


# ==========================================
# UI PAGE ROUTES
# ==========================================

@app.route("/")
def dashboard_page():
    case_id = get_current_case_id()
    metrics = get_case_metrics(case_id)
    cases = list_cases()
    return render_template("dashboard.html", case_id=case_id, metrics=metrics, cases=cases, active_tab="dashboard")

@app.route("/timeline")
def timeline_page():
    case_id = get_current_case_id()
    metrics = get_case_metrics(case_id)
    return render_template("timeline.html", case_id=case_id, metrics=metrics, active_tab="timeline")

@app.route("/state")
def state_page():
    case_id = get_current_case_id()
    metrics = get_case_metrics(case_id)
    target_timestamp = request.args.get("timestamp")
    return render_template("system_state.html", case_id=case_id, metrics=metrics, target_timestamp=target_timestamp, active_tab="state")

@app.route("/evidence")
def evidence_page():
    case_id = get_current_case_id()
    metrics = get_case_metrics(case_id)
    files = list_evidence_files(case_id)
    return render_template("evidence.html", case_id=case_id, metrics=metrics, files=files, active_tab="evidence")

@app.route("/graph")
def graph_page():
    case_id = get_current_case_id()
    metrics = get_case_metrics(case_id)
    return render_template("incident_graph.html", case_id=case_id, metrics=metrics, active_tab="graph")

@app.route("/ghost")
def ghost_page():
    case_id = get_current_case_id()
    metrics = get_case_metrics(case_id)
    return render_template("ghost_evidence.html", case_id=case_id, metrics=metrics, active_tab="ghost")

@app.route("/investigate")
def investigate_page():
    case_id = get_current_case_id()
    metrics = get_case_metrics(case_id)
    return render_template("investigate.html", case_id=case_id, metrics=metrics, active_tab="investigate")

@app.route("/report")
def report_page():
    case_id = get_current_case_id()
    case = get_case(case_id)
    if not case:
        return redirect(f"/?case_id={Config.DEMO_CASE_ID}")
    
    events = get_events(case_id)
    evidence_files = list_evidence_files(case_id)
    findings = run_correlation_engine(events, case_id=case_id)
    ghost_findings = detect_ghost_evidence(events, case_id=case_id)
    notes = get_investigation_notes(case_id)

    report_data = generate_investigation_report_data(
        case=case,
        events=events,
        evidence_files=evidence_files,
        correlation_findings=findings,
        ghost_findings=ghost_findings,
        notes=notes
    )
    return render_template("report.html", case_id=case_id, report=report_data, active_tab="report")

@app.route("/settings")
def settings_page():
    case_id = get_current_case_id()
    case = get_case(case_id)
    cases = list_cases()
    return render_template("settings.html", case_id=case_id, case=case, cases=cases, active_tab="settings")

@app.route("/stress-test")
def stress_test_page():
    case_id = get_current_case_id()
    metrics = get_case_metrics(case_id)
    return render_template("stress_test.html", case_id=case_id, metrics=metrics, active_tab="stress-test")

@app.route("/time-machine")
def time_machine_page():
    case_id = get_current_case_id()
    metrics = get_case_metrics(case_id)
    return render_template("time_machine.html", case_id=case_id, metrics=metrics, active_tab="time-machine")


# ==========================================
# REST API ENDPOINTS
# ==========================================

@app.route("/api/health")
def api_health():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "version": "1.0.0",
        "service": "Digital Time Machine",
        "database": "sqlite3_active"
    })

@app.route("/api/cases", methods=["GET", "POST"])
def api_cases():
    """Lists all cases or creates a new investigation."""
    if request.method == "POST":
        data = request.get_json() or {}
        case_id = data.get("id") or f"CASE-{datetime.now().strftime('%Y%m%d%H%M')}"
        name = data.get("name") or "New Cyber Investigation"
        desc = data.get("description") or "Digital Forensics Case"
        case = get_or_create_case(case_id, name, desc)
        return jsonify(case), 201

    return jsonify({"cases": list_cases()})

@app.route("/api/cases/load-demo", methods=["POST", "GET"])
def api_load_demo():
    """Resets and loads the synthetic demo case 'CASE-001: MISSING CUSTOMER DATABASE'."""
    case_id = None
    if request.method == "POST":
        data = request.get_json() or {}
        case_id = data.get("case_id") if isinstance(data, dict) else None
        if not case_id and hasattr(request, "form") and request.form:
            case_id = request.form.get("case_id")
    if not case_id:
        case_id = request.args.get("case_id") or Config.DEMO_CASE_ID

    metrics = load_demo_case(case_id)
    return jsonify({
        "success": True,
        "case_id": case_id,
        "message": f"Demo investigation '{Config.DEMO_CASE_NAME}' seeded successfully.",
        "metrics": metrics
    })

@app.route("/api/cases/<case_id>")
def api_case_detail(case_id):
    """Retrieves specific case metrics and metadata."""
    metrics = get_case_metrics(case_id)
    if not metrics:
        return jsonify({"error": f"Case '{case_id}' not found."}), 404
    return jsonify(metrics)

@app.route("/api/events")
def api_events():
    """
    Returns filtered chronological events for a case.
    Supports query params: case_id, source, severity, actor, until_timestamp
    """
    case_id = get_current_case_id()
    source = request.args.get("source")
    severity = request.args.get("severity")
    actor = request.args.get("actor")
    until_ts = request.args.get("until_timestamp")

    events = get_events(case_id, source=source, severity=severity, actor=actor, until_timestamp=until_ts)
    return jsonify({
        "case_id": case_id,
        "count": len(events),
        "events": events
    })

@app.route("/api/events/<event_id>")
def api_event_detail(event_id):
    """Returns single event details."""
    case_id = get_current_case_id()
    event = get_event_by_id(case_id, event_id)
    if not event:
        return jsonify({"error": f"Event '{event_id}' not found in case '{case_id}'."}), 404
    return jsonify(event)

@app.route("/api/state")
def api_state():
    """
    Reconstructs digital system state at a specific point in time.
    Query params: timestamp (ISO), case_id
    """
    case_id = get_current_case_id()
    target_ts = request.args.get("timestamp")
    all_events = get_events(case_id)

    state = reconstruct_system_state(all_events, target_timestamp=target_ts)
    return jsonify({
        "case_id": case_id,
        "state": state
    })

@app.route("/api/incidents")
def api_incidents():
    """Retrieves correlation findings for a case."""
    case_id = get_current_case_id()
    events = get_events(case_id)
    findings = run_correlation_engine(events, case_id=case_id)
    return jsonify({
        "case_id": case_id,
        "count": len(findings),
        "findings": findings
    })

@app.route("/api/incidents/<finding_id>")
@app.route("/api/incidents/<finding_id>/evidence-dna")
def api_incident_evidence_dna(finding_id):
    """
    Evidence DNA endpoint: retrieves granular evidence lineage,
    recorded facts vs inferred deductions, and dataset gap analysis for a finding.
    """
    case_id = get_current_case_id()
    dna = get_evidence_dna(case_id, finding_id)
    if not dna:
        return jsonify({"error": f"Finding '{finding_id}' not found in case '{case_id}'."}), 404
    return jsonify(dna)

@app.route("/api/incidents/<finding_id>/status", methods=["POST", "PATCH"])
def api_incident_status(finding_id):
    """
    Updates status of a correlation finding (open, under_review, resolved) and persists in SQLite.
    """
    case_id = get_current_case_id()
    data = request.get_json() or {}
    new_status = (data.get("status") or "open").lower()
    if new_status not in ("open", "under_review", "resolved"):
        return jsonify({"error": f"Invalid status '{new_status}'. Allowed: open, under_review, resolved"}), 400

    updated = update_finding_status(case_id, finding_id, new_status)
    if not updated:
        return jsonify({"error": f"Finding '{finding_id}' not found in case '{case_id}'."}), 404

    return jsonify({
        "success": True,
        "finding_id": finding_id,
        "status": updated.get("status", new_status),
        "message": f"Finding '{finding_id}' status updated to '{new_status}' in SQLite."
    })

@app.route("/api/ghost-evidence")
def api_ghost_evidence():
    """Retrieves ghost evidence gap and anomaly detections."""
    case_id = get_current_case_id()
    events = get_events(case_id)
    anomalies = detect_ghost_evidence(events, case_id=case_id)
    return jsonify({
        "case_id": case_id,
        "count": len(anomalies),
        "anomalies": anomalies
    })

@app.route("/api/evidence")
def api_evidence():
    """Retrieves metadata of imported evidence files."""
    case_id = get_current_case_id()
    files = list_evidence_files(case_id)
    return jsonify({
        "case_id": case_id,
        "count": len(files),
        "files": files
    })

@app.route("/api/upload", methods=["POST"])
def api_upload():
    """
    Uploads and safely parses an evidence file (CSV or JSON).
    Prevents duplicates, validates fields, hashes file, normalizes events.
    """
    case_id = request.form.get("case_id") or get_current_case_id()

    if "file" not in request.files:
        return jsonify({"success": False, "error": "No file field provided in upload request."}), 400

    file_obj = request.files["file"]
    if not file_obj or not file_obj.filename:
        return jsonify({"success": False, "error": "No file selected."}), 400

    file_bytes = file_obj.read()
    result = import_evidence_file(case_id, file_bytes, file_obj.filename)
    status_code = 200 if result.get("success") else 400
    return jsonify(result), status_code

@app.route("/api/graph")
def api_graph():
    """Returns incident relationship graph nodes and edges."""
    case_id = get_current_case_id()
    events = get_events(case_id)
    findings = run_correlation_engine(events, case_id=case_id)
    graph_data = generate_relationship_graph(events, findings)
    return jsonify({
        "case_id": case_id,
        "graph": graph_data
    })

@app.route("/api/investigate", methods=["GET", "POST"])
def api_investigate():
    """Runs investigator workspace inquiries against current evidence."""
    case_id = get_current_case_id()
    events = get_events(case_id)
    findings = run_correlation_engine(events, case_id=case_id)
    ghost_anomalies = detect_ghost_evidence(events, case_id=case_id)

    if request.method == "POST":
        data = request.get_json() or {}
        q_val = data.get("question_id") or data.get("query")
        if q_val:
            answer = answer_investigative_query(q_val, events, findings, ghost_anomalies)
            return jsonify(answer)

    inquiries = get_all_investigative_inquiries(events, findings, ghost_anomalies)
    return jsonify({
        "case_id": case_id,
        "inquiries": inquiries
    })

@app.route("/api/notes", methods=["GET", "POST"])
def api_notes():
    """Retrieves or creates investigator notes."""
    case_id = get_current_case_id()
    if request.method == "POST":
        data = request.get_json() or {}
        note_text = data.get("note", "").strip()
        author = data.get("author", "Investigator")
        if not note_text:
            return jsonify({"error": "Note text cannot be empty."}), 400
        new_note = add_investigation_note(case_id, note_text, author)
        return jsonify(new_note), 201

    notes = get_investigation_notes(case_id)
    return jsonify({"case_id": case_id, "notes": notes})

@app.route("/api/report")
def api_report():
    """Returns full report payload in JSON format."""
    case_id = get_current_case_id()
    case = get_case(case_id)
    if not case:
        return jsonify({"error": f"Case '{case_id}' not found."}), 404

    events = get_events(case_id)
    evidence_files = list_evidence_files(case_id)
    findings = run_correlation_engine(events, case_id=case_id)
    ghost_findings = detect_ghost_evidence(events, case_id=case_id)
    notes = get_investigation_notes(case_id)

    report_data = generate_investigation_report_data(
        case=case,
        events=events,
        evidence_files=evidence_files,
        correlation_findings=findings,
        ghost_findings=ghost_findings,
        notes=notes
    )
    return jsonify(report_data)

@app.route("/api/report/export")
def api_report_export():
    """
    Exports structured investigation report as downloadable HTML or CSV dossier.
    """
    case_id = get_current_case_id()
    fmt = request.args.get("format", "html").lower()
    case = get_case(case_id)
    if not case:
        return jsonify({"error": f"Case '{case_id}' not found."}), 404

    events = get_events(case_id)
    evidence_files = list_evidence_files(case_id)
    findings = run_correlation_engine(events, case_id=case_id)
    ghost_findings = detect_ghost_evidence(events, case_id=case_id)
    notes = get_investigation_notes(case_id)

    report_data = generate_investigation_report_data(
        case=case,
        events=events,
        evidence_files=evidence_files,
        correlation_findings=findings,
        ghost_findings=ghost_findings,
        notes=notes
    )

    if fmt == "csv":
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["RECORD_TYPE", "ID", "TIMESTAMP", "SOURCE_OR_RULE", "ACTOR_OR_SEV", "OBJECT_OR_CONFIDENCE", "DESCRIPTION_OR_EXPLANATION"])
        for f in findings:
            writer.writerow(["CORRELATION_FINDING", f["id"], f["start_time"], f["rule_name"], f["severity"], f.get("confidence", "observed"), f["explanation"]])
        for g in ghost_findings:
            writer.writerow(["GHOST_ANOMALY", g["id"], "", g["anomaly_type"], g["severity"], g.get("category", "OBSERVED GAP"), g["title"] + " - " + g["missing"]])
        for ev in events:
            writer.writerow(["TIMELINE_EVENT", ev["id"], ev["timestamp"], ev["source"], ev["actor"], ev["object"], ev["description"]])
        for n in notes:
            writer.writerow(["INVESTIGATOR_NOTE", str(n.get("id", "")), n.get("timestamp", ""), "JOURNAL", n.get("author", ""), "NOTE", n.get("note", "")])

        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=investigation_report_{case_id}.csv"}
        )
    else:
        rendered = render_template("report.html", report=report_data, active_tab="report", is_export=True)
        content_bytes = rendered.data if hasattr(rendered, "data") else (rendered.encode("utf-8") if isinstance(rendered, str) else rendered)
        return Response(
            content_bytes,
            mimetype="text/html",
            headers={"Content-Disposition": f"attachment; filename=investigation_report_{case_id}.html"}
        )


# ==========================================
# CONCLUSION STRESS TESTER API
# ==========================================

@app.route("/api/stress-test")
def api_stress_test():
    """Evaluates conclusion stress testing across case findings or for a single finding."""
    case_id = get_current_case_id()
    finding_id = request.args.get("finding_id")
    if finding_id:
        from database.db import get_db_connection, query_one
        conn = get_db_connection(Config.DATABASE_PATH)
        finding = query_one(conn, "SELECT * FROM correlation_findings WHERE case_id = ? AND id = ?", (case_id, finding_id))
        conn.close()
        if not finding:
            return jsonify({"error": f"Finding '{finding_id}' not found in case '{case_id}'."}), 404
        result = stress_test_finding(case_id, finding)
        return jsonify(result)
    result = stress_test_case(case_id)
    return jsonify(result)

@app.route("/api/stress-test/<finding_id>")
def api_stress_test_detail(finding_id):
    """Stress tests a specific correlation finding."""
    case_id = get_current_case_id()
    from database.db import get_db_connection, query_one
    conn = get_db_connection(Config.DATABASE_PATH)
    finding = query_one(conn, "SELECT * FROM correlation_findings WHERE case_id = ? AND id = ?", (case_id, finding_id))
    conn.close()
    if not finding:
        return jsonify({"error": f"Finding '{finding_id}' not found in case '{case_id}'."}), 404
    result = stress_test_finding(case_id, finding)
    return jsonify(result)

@app.route("/api/stress-test/custom", methods=["POST"])
def api_stress_test_custom():
    """Evaluates an ad-hoc investigator conclusion against specified event IDs."""
    data = request.get_json() or {}
    case_id = data.get("case_id") or get_current_case_id()
    conclusion_text = data.get("conclusion") or data.get("hypothesis") or ""
    event_ids = data.get("event_ids") or []
    if not conclusion_text.strip():
        return jsonify({"error": "Conclusion statement cannot be empty."}), 400
    result = stress_test_custom_conclusion(case_id, conclusion_text.strip(), event_ids)
    return jsonify(result)


# ==========================================
# INVESTIGATION TIME MACHINE SNAPSHOTS API
# ==========================================

@app.route("/api/snapshots", methods=["GET", "POST"])
def api_snapshots():
    """Lists saved analysis snapshots or creates a new snapshot."""
    case_id = get_current_case_id()
    if request.method == "POST":
        data = request.get_json() or {}
        name = data.get("name")
        note = data.get("note", "")
        rule_version = data.get("rule_version", "v1.2.0-deterministic")
        c_id = data.get("case_id") or case_id
        if not name or not name.strip():
            return jsonify({"error": "Snapshot name is required."}), 400
        try:
            snapshot = create_snapshot(c_id, name, note=note, rule_version=rule_version)
            return jsonify({"success": True, "snapshot": snapshot}), 201
        except Exception as ex:
            return jsonify({"error": str(ex)}), 400

    snapshots = list_snapshots(case_id)
    return jsonify({"case_id": case_id, "count": len(snapshots), "snapshots": snapshots})

@app.route("/api/snapshots/compare", methods=["GET", "POST"])
def api_snapshots_compare():
    """Compares two investigation snapshots and returns diff breakdown."""
    case_id = get_current_case_id()
    if request.method == "POST":
        data = request.get_json() or {}
        snap_a = data.get("snapshot_a_id") or data.get("base_snapshot_id")
        snap_b = data.get("snapshot_b_id") or data.get("compare_snapshot_id")
        c_id = data.get("case_id") or case_id
    else:
        snap_a = request.args.get("snapshot_a_id") or request.args.get("base_id")
        snap_b = request.args.get("snapshot_b_id") or request.args.get("compare_id")
        c_id = request.args.get("case_id") or case_id

    if not snap_a or not snap_b:
        return jsonify({"error": "Both 'snapshot_a_id' and 'snapshot_b_id' are required."}), 400

    try:
        diff = compare_snapshots(c_id, snap_a, snap_b)
        return jsonify(diff)
    except Exception as ex:
        return jsonify({"error": str(ex)}), 400

@app.route("/api/snapshots/<snapshot_id>")
def api_snapshot_detail(snapshot_id):
    """Retrieves full snapshot details and verifies SHA-256 integrity."""
    snapshot = get_snapshot(snapshot_id)
    if not snapshot:
        return jsonify({"error": f"Snapshot '{snapshot_id}' not found."}), 404
    return jsonify(snapshot)


if __name__ == "__main__":
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")
    app.run(host=host, port=port, debug=debug)

