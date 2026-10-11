"""
Comprehensive End-to-End Test Suite for Digital Time Machine.
Tests CASE-001 scenario, timeline scrubbing, point-in-time system state,
evidence hashing, duplicate rejection, incident graph, ghost evidence,
investigator queries, finding status persistence in SQLite, and report generation.
Runs against an isolated temporary SQLite database and upload directory.
"""

import unittest
import os
import io
import json
import tempfile
from pathlib import Path

from app import app
from config import Config
from database.db import init_db, get_db_connection, query_one, query_all
from services.case_service import load_demo_case, get_case, get_case_metrics, update_finding_status
from services.evidence_service import get_events, import_evidence_file
from engine.state_reconstructor import reconstruct_system_state
from engine.correlator import run_correlation_engine
from engine.ghost_evidence import detect_ghost_evidence
from engine.graph_generator import generate_relationship_graph
from engine.investigator import answer_investigative_query, get_all_investigative_inquiries
from engine.report_generator import generate_investigation_report_data


class TestDemoCaseE2E(unittest.TestCase):

    def setUp(self):
        # Create temporary database file and uploads folder
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_uploads = tempfile.TemporaryDirectory()
        
        self.orig_db_path = Config.DATABASE_PATH
        self.orig_upload_folder = Config.UPLOAD_FOLDER

        Config.DATABASE_PATH = self.temp_db.name
        Config.UPLOAD_FOLDER = self.temp_uploads.name
        self.temp_db.close()

        # Initialize schema with migrations
        init_db(Config.DATABASE_PATH)
        self.client = app.test_client()
        self.case_id = "CASE-001"

    def tearDown(self):
        Config.DATABASE_PATH = self.orig_db_path
        Config.UPLOAD_FOLDER = self.orig_upload_folder
        self.temp_uploads.cleanup()
        if os.path.exists(self.temp_db.name):
            os.remove(self.temp_db.name)

    def test_phase2_demo_case_creation_and_idempotence(self):
        """Phase 2: Verifies CASE-001 creation, stable event IDs, and duplicate-free reload."""
        metrics1 = load_demo_case(self.case_id)
        self.assertIsNotNone(metrics1)
        self.assertEqual(metrics1["case"]["id"], "CASE-001")
        self.assertIn("MISSING CUSTOMER DATABASE", metrics1["case"]["name"])
        self.assertEqual(metrics1["total_events"], 18)

        # Verify all key sequence events are present with stable IDs
        events = get_events(self.case_id)
        evt_ids = [e["id"] for e in events]
        expected_ids = ["EVT-003", "EVT-021", "EVT-030", "EVT-022", "EVT-041", "EVT-024", "EVT-025"]
        for expected in expected_ids:
            self.assertIn(expected, evt_ids, f"Event {expected} must exist in CASE-001")

        # Test idempotence: loading again must not create duplicates
        metrics2 = load_demo_case(self.case_id)
        self.assertEqual(metrics2["total_events"], 18)
        events_after = get_events(self.case_id)
        self.assertEqual(len(events_after), 18)

        # Test HTTP API endpoint POST /api/cases/load-demo matches frontend call
        resp = self.client.post("/api/cases/load-demo", json={"case_id": self.case_id})
        self.assertEqual(resp.status_code, 200, "POST /api/cases/load-demo must return 200 OK")
        api_data = resp.get_json()
        self.assertTrue(api_data["success"])
        self.assertEqual(api_data["case_id"], self.case_id)

    def test_phase3_timeline_ordering_and_filters(self):
        """Phase 3: Verifies chronological ordering, filtering, and scrubber isolation."""
        load_demo_case(self.case_id)
        events = get_events(self.case_id)
        
        # Verify strictly chronological
        timestamps = [e["timestamp"] for e in events]
        self.assertEqual(timestamps, sorted(timestamps))

        # Test filtering by source
        login_events = get_events(self.case_id, source="login")
        self.assertTrue(len(login_events) > 0)
        self.assertTrue(all(e["source"] == "login" for e in login_events))

        # Test filtering by severity
        crit_events = get_events(self.case_id, severity="critical")
        self.assertTrue(len(crit_events) > 0)
        self.assertTrue(all(e["severity"] == "critical" for e in crit_events))

        # Test temporal isolation with until_timestamp
        events_up_to_1007 = get_events(self.case_id, until_timestamp="2026-10-07T10:07:00")
        for ev in events_up_to_1007:
            self.assertTrue(ev["timestamp"] <= "2026-10-07T10:07:00")
        # Event at 10:12:00 (deletion) must NOT be present
        self.assertNotIn("EVT-024", [e["id"] for e in events_up_to_1007])

    def test_phase4_system_state_reconstruction_and_file_deletion(self):
        """Phase 4: Point-in-time system state, USB attachment at 10:05, access at 10:07, deletion at 10:12."""
        load_demo_case(self.case_id)
        all_events = get_events(self.case_id)

        # State at 10:00:00 (Login)
        state_1000 = reconstruct_system_state(all_events, target_timestamp="2026-10-07T10:00:00")
        self.assertIn("alice", state_1000["active_sessions"])
        self.assertEqual(state_1000["active_sessions"]["alice"]["status"], "ACTIVE")
        self.assertEqual(len(state_1000["connected_devices"]), 0)

        # State at 10:05:00 (USB Connected)
        state_1005 = reconstruct_system_state(all_events, target_timestamp="2026-10-07T10:05:00")
        self.assertIn("Kingston DataTraveler 3.0", state_1005["connected_devices"])
        self.assertTrue(state_1005["connected_devices"]["Kingston DataTraveler 3.0"]["is_connected"])

        # State at 10:07:00 (Database file accessed)
        state_1007 = reconstruct_system_state(all_events, target_timestamp="2026-10-07T10:07:00")
        db_file = "C:\\Data\\customer_database_q3.csv"
        self.assertIn(db_file, state_1007["file_system"])
        self.assertEqual(state_1007["file_system"][db_file]["status"], "ACCESSED")

        # State at 10:11:00 (Before deletion -> file is NOT deleted)
        state_1011 = reconstruct_system_state(all_events, target_timestamp="2026-10-07T10:11:00")
        self.assertNotEqual(state_1011["file_system"][db_file]["status"], "DELETED")

        # State at 10:12:00 (Database file deleted)
        state_1012 = reconstruct_system_state(all_events, target_timestamp="2026-10-07T10:12:00")
        self.assertEqual(state_1012["file_system"][db_file]["status"], "DELETED")
        self.assertEqual(state_1012["file_system"][db_file]["deleted_at"], "2026-10-07T10:12:00")

        # State at 10:15:00 (File remains deleted)
        state_1015 = reconstruct_system_state(all_events, target_timestamp="2026-10-07T10:15:00")
        self.assertEqual(state_1015["file_system"][db_file]["status"], "DELETED")

    def test_phase5_evidence_hashing_duplicate_and_empty_file_guards(self):
        """Phase 5: Real SHA-256 computation, duplicate prevention, and empty file rejection."""
        load_demo_case(self.case_id)
        
        sample_csv = b"id,timestamp,source,event_type,actor,object,severity,description\nEVT-999,2026-10-07T11:00:00,login,LOGIN_SUCCESS,charlie,ws-3,low,Test login\n"
        
        # Valid import
        res1 = import_evidence_file(self.case_id, sample_csv, "new_evidence.csv")
        self.assertTrue(res1["success"])
        self.assertEqual(res1["accepted"], 1)
        self.assertEqual(len(res1["sha256"]), 64)

        # Duplicate import
        res2 = import_evidence_file(self.case_id, sample_csv, "copy_new_evidence.csv")
        self.assertFalse(res2["success"])
        self.assertTrue(res2.get("duplicate"))
        self.assertIn("Duplicate evidence detected", res2["error"])

        # Empty file rejection
        res_empty = import_evidence_file(self.case_id, b"", "empty.csv")
        self.assertFalse(res_empty["success"])
        self.assertIn("empty", res_empty["error"].lower())

    def test_phase6_incident_graph_nodes_and_relationships(self):
        """Phase 6: Verifies User->Device, User->Dir, User->File, Device->USB, File->Deletion, Network."""
        load_demo_case(self.case_id)
        events = get_events(self.case_id)
        findings = run_correlation_engine(events, case_id=self.case_id)
        graph = generate_relationship_graph(events, findings)

        self.assertTrue(graph["counts"]["total_nodes"] > 0)
        self.assertTrue(graph["counts"]["total_edges"] > 0)

        edge_labels = [e["label"] for e in graph["edges"]]
        # User -> Device
        self.assertIn("LOGGED_INTO", edge_labels)
        # User -> Directory
        self.assertIn("ACCESSED_DIR", edge_labels)
        # User -> File
        self.assertIn("ACCESSED", edge_labels)
        # Device -> USB
        self.assertIn("MOUNTED_USB", edge_labels)
        # Database file -> Deletion
        self.assertIn("RECORDED_DELETION", edge_labels)
        # Network connection
        self.assertTrue(any(l in edge_labels for l in ("CONNECTED_TO", "EXFIL_TRANSFER", "OUTBOUND_SOCKET")))

    def test_phase7_ghost_evidence_anomalies_and_categories(self):
        """Phase 7: Verifies gap detection, unclosed lifecycles, and category labels."""
        load_demo_case(self.case_id)
        events = get_events(self.case_id)
        anomalies = detect_ghost_evidence(events, case_id=self.case_id)

        self.assertTrue(len(anomalies) > 0)
        types = [a["anomaly_type"] for a in anomalies]
        categories = [a.get("category") for a in anomalies]

        self.assertIn("TEMPORAL_COVERAGE_GAP", types)
        self.assertIn("UNCLOSED_ARTIFACT_LIFECYCLE", types)
        
        # Verify valid category labels
        for cat in categories:
            self.assertIn(cat, ("OBSERVED GAP", "POSSIBLE INCONSISTENCY", "UNVERIFIED HYPOTHESIS"))

    def test_phase8_investigator_queries_notes_and_status_persistence(self):
        """Phase 8: Timeline queries, journal notes, and finding status updates in SQLite."""
        load_demo_case(self.case_id)
        events = get_events(self.case_id)
        findings = run_correlation_engine(events, case_id=self.case_id)
        anomalies = detect_ghost_evidence(events, case_id=self.case_id)

        # Query: Who accessed the database?
        ans_db = answer_investigative_query("Q_DB", events, findings, anomalies)
        self.assertEqual(ans_db["status"], "answered")
        self.assertIn("alice", ans_db["answer"])
        self.assertTrue(len(ans_db["supporting_event_ids"]) > 0)

        # Query: When was the USB device inserted?
        ans_usb = answer_investigative_query("Q_USB", events, findings, anomalies)
        self.assertEqual(ans_usb["status"], "answered")
        self.assertIn("10:05:00", ans_usb["answer"])
        self.assertIn("EVT-030", ans_usb["supporting_event_ids"])

        # Test finding status update and SQLite persistence
        first_finding = findings[0]
        finding_id = first_finding["id"]

        # Default is open
        self.assertEqual(first_finding.get("status", "open"), "open")

        # Update to under_review
        resp_update = self.client.post(
            f"/api/incidents/{finding_id}/status?case_id={self.case_id}",
            json={"status": "under_review"}
        )
        self.assertEqual(resp_update.status_code, 200)
        self.assertEqual(resp_update.get_json()["status"], "under_review")

        # Verify persisted in SQLite
        conn = get_db_connection(Config.DATABASE_PATH)
        row = query_one(conn, "SELECT status FROM correlation_findings WHERE case_id = ? AND id = ?", (self.case_id, finding_id))
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "under_review")

        # Update to resolved
        resp_resolved = self.client.post(
            f"/api/incidents/{finding_id}/status?case_id={self.case_id}",
            json={"status": "resolved"}
        )
        self.assertEqual(resp_resolved.status_code, 200)
        self.assertEqual(resp_resolved.get_json()["status"], "resolved")

    def test_phase9_investigation_report_and_exports(self):
        """Phase 9: JSON report, HTML download, and CSV export."""
        load_demo_case(self.case_id)

        # Test JSON report endpoint
        resp_json = self.client.get(f"/api/report?case_id={self.case_id}")
        self.assertEqual(resp_json.status_code, 200)
        rep = resp_json.get_json()
        self.assertIn("system_state", rep)
        self.assertIn("investigation_notes", rep)
        self.assertIn("key_milestones", rep)
        self.assertTrue(len(rep["evidence_files"]) > 0)

        # Test HTML export endpoint
        resp_html = self.client.get(f"/api/report/export?case_id={self.case_id}&format=html")
        self.assertEqual(resp_html.status_code, 200)
        self.assertIn("text/html", resp_html.headers.get("Content-Type", ""))
        self.assertIn(b"CASE-001", resp_html.data)

        # Test CSV export endpoint
        resp_csv = self.client.get(f"/api/report/export?case_id={self.case_id}&format=csv")
        self.assertEqual(resp_csv.status_code, 200)
        self.assertIn("text/csv", resp_csv.headers.get("Content-Type", ""))
        csv_text = resp_csv.data.decode("utf-8")
        self.assertIn("CORRELATION_FINDING", csv_text)
        self.assertIn("TIMELINE_EVENT", csv_text)

    def test_phase10_all_views_accessible(self):
        """Phase 10: Verifies all 9 views return 200 OK with CASE-001 context."""
        load_demo_case(self.case_id)
        routes = [
            f"/?case_id={self.case_id}",
            f"/timeline?case_id={self.case_id}",
            f"/state?case_id={self.case_id}",
            f"/evidence?case_id={self.case_id}",
            f"/graph?case_id={self.case_id}",
            f"/ghost?case_id={self.case_id}",
            f"/investigate?case_id={self.case_id}",
            f"/report?case_id={self.case_id}",
            f"/settings?case_id={self.case_id}",
        ]
        for route in routes:
            resp = self.client.get(route)
            self.assertEqual(resp.status_code, 200, f"Route {route} must return 200 OK")


if __name__ == "__main__":
    unittest.main()

