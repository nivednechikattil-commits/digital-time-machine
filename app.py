"""
Digital Time Machine — Interactive Digital Forensics & Cyber Incident Reconstruction Platform.
Main Flask Application and API Router.
"""

import os
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
    get_case_metrics, add_investigation_note, get_investigation_notes
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
    return render_template("system_state.html", case_id=case_id, metrics=metrics, active_tab="state")

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
    return render_template("report.html", report=report_data, active_tab="report")

@app.route("/settings")
def settings_page():
    case_id = get_current_case_id()
    case = get_case(case_id)
    cases = list_cases()
    return render_template("settings.html", case_id=case_id, case=case, cases=cases, active_tab="settings")


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

@app.route("/api/cases/<case_id>")
def api_case_detail(case_id):
    """Retrieves specific case metrics and metadata."""
    metrics = get_case_metrics(case_id)
    if not metrics:
        return jsonify({"error": f"Case '{case_id}' not found."}), 404
    return jsonify(metrics)

@app.route("/api/cases/load-demo", methods=["POST"])
def api_load_demo():
    """Resets and loads the synthetic demo case 'The Missing Customer Database'."""
    data = request.get_json() or {}
    case_id = data.get("case_id") or Config.DEMO_CASE_ID
    metrics = load_demo_case(case_id)
    return jsonify({
        "success": True,
        "message": f"Demo investigation '{Config.DEMO_CASE_NAME}' seeded successfully.",
        "metrics": metrics
    })

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
        q_id = data.get("question_id")
        if q_id:
            answer = answer_investigative_query(q_id, events, findings, ghost_anomalies)
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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=True)

