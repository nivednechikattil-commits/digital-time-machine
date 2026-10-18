"""
Automated tests for Conclusion Stress Tester in Digital Time Machine.
Verifies forensic stress-testing rules:
- Well-supported conclusions
- Insufficient evidence (including USB copy over-claim)
- Contradictory evidence records
- Duplicate evidence records
- Missing evidence references
- Verification that all returned event IDs exist in the database
- REST API endpoints and UI route
"""

import unittest
import json
from app import app
from database.db import get_db_connection, execute_write, query_all
from services.case_service import load_demo_case, get_case
from engine.stress_tester import (
    stress_test_finding,
    stress_test_case,
    stress_test_custom_conclusion,
    STATUS_SUPPORTED,
    STATUS_PARTIALLY_SUPPORTED,
    STATUS_CONTRADICTORY,
    STATUS_INSUFFICIENT,
    STATUS_REQUIRES_REVIEW
)
from config import Config


class TestStressTester(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.case_id = "CASE-TEST-STRESS"
        load_demo_case(self.case_id)

    def test_conclusion_with_appropriate_supporting_evidence(self):
        """Verifies a finding with verified independent evidence receives Supported status."""
        conn = get_db_connection(Config.DATABASE_PATH)
        # Find a clean sequence finding in test case
        finding = {
            "id": "FIND-CLEAN-01",
            "rule_id": "RULE_A",
            "rule_name": "Suspicious Website Visit Preceding File Download",
            "explanation": "Browser navigation to URL was followed by file download.",
            "start_time": "2026-10-07T10:01:30",
            "end_time": "2026-10-07T10:02:45",
            "supporting_event_ids": ["EVT-010", "EVT-020"]
        }
        res = stress_test_finding(self.case_id, finding)
        self.assertIn(res["status"], [STATUS_SUPPORTED, STATUS_PARTIALLY_SUPPORTED])
        self.assertEqual(res["supporting_event_count"], 2)
        self.assertEqual(len(res["unresolved_event_ids"]), 0)
        conn.close()

    def test_insufficient_evidence_usb_copy_scenario(self):
        """
        Requirement D:
        Finding says: 'The customer database was copied to a USB device.'
        Available records: Database file accessed, USB connected, No file-copy record exists.
        System must flag conclusion as Insufficient evidence and explain that USB insertion
        and file access do not establish the database was copied.
        """
        conclusion = "The customer database was copied to a USB device."
        # EVT-030 = USB inserted at 10:05; EVT-022 = Database accessed at 10:07; no copy event
        res = stress_test_custom_conclusion(self.case_id, conclusion, ["EVT-030", "EVT-022"])
        
        self.assertEqual(res["status"], STATUS_INSUFFICIENT)
        
        # Check rule triggered
        rules_triggered = [w["rule_triggered"] for w in res["warnings"]]
        self.assertIn("RULE_USB_COPY_OVERCLAIM", rules_triggered)
        
        # Verify explanation does not fabricate copy and explains the limitation
        usb_warning = next(w for w in res["warnings"] if w["rule_triggered"] == "RULE_USB_COPY_OVERCLAIM")
        self.assertIn("USB device was connected", usb_warning["explanation"])
        self.assertIn("database file was accessed", usb_warning["explanation"])
        self.assertIn("No file-copy record", usb_warning["explanation"])
        self.assertIn("USN Journal", usb_warning["additional_evidence_needed"])

    def test_conclusion_with_contradictory_records(self):
        """Verifies detection of contradictory telemetry (e.g. actor active while logged out)."""
        conn = get_db_connection(Config.DATABASE_PATH)
        # Seed an explicit contradiction: Logout event for 'alice' at 10:01, but activity attributed at 10:07
        execute_write(
            conn,
            """INSERT OR REPLACE INTO events
               (id, case_id, timestamp, source, event_type, actor, object, severity, description, evidence_ref, confidence, details, is_inferred)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "EVT-LOGOUT-CONTRADICTION",
                self.case_id,
                "2026-10-07T10:01:00",
                "login",
                "LOGOUT",
                "alice",
                "workstation-01",
                "medium",
                "User alice performed interactive session logout.",
                "auth_audit.csv",
                "observed",
                "{}",
                0
            )
        )
        conn.close()

        # Finding claims alice accessed file at 10:07 (EVT-022)
        finding = {
            "id": "FIND-CONTRADICT-01",
            "rule_id": "RULE_B",
            "rule_name": "File Access Event",
            "explanation": "Alice accessed customer database.",
            "start_time": "2026-10-07T10:07:00",
            "end_time": "2026-10-07T10:07:00",
            "supporting_event_ids": ["EVT-022"]
        }

        res = stress_test_finding(self.case_id, finding)
        self.assertEqual(res["status"], STATUS_CONTRADICTORY)
        self.assertTrue(len(res["contradictory_events"]) > 0)
        self.assertIn("EVT-LOGOUT-CONTRADICTION", [e["id"] for e in res["contradictory_events"]])

    def test_duplicate_evidence_records_detected(self):
        """Verifies duplicate event records in supporting list are flagged as non-independent corroboration."""
        finding = {
            "id": "FIND-DUP-01",
            "rule_id": "RULE_TEST",
            "rule_name": "Test Finding With Duplicates",
            "explanation": "Test explanation.",
            "start_time": "2026-10-07T10:00:00",
            "end_time": "2026-10-07T10:05:00",
            "supporting_event_ids": ["EVT-010", "EVT-010"]  # Repeated ID
        }
        res = stress_test_finding(self.case_id, finding)
        rules = [w["rule_triggered"] for w in res["warnings"]]
        self.assertIn("RULE_DUPLICATE_CORROBORATION", rules)

    def test_missing_evidence_references(self):
        """Verifies finding with non-existent event IDs flags missing evidence references."""
        finding = {
            "id": "FIND-MISSING-01",
            "rule_id": "RULE_TEST",
            "rule_name": "Finding with missing IDs",
            "explanation": "References non-existent events.",
            "supporting_event_ids": ["EVT-DOES-NOT-EXIST-999"]
        }
        res = stress_test_finding(self.case_id, finding)
        self.assertIn("EVT-DOES-NOT-EXIST-999", res["unresolved_event_ids"])
        self.assertEqual(res["status"], STATUS_INSUFFICIENT)
        rules = [w["rule_triggered"] for w in res["warnings"]]
        self.assertIn("RULE_UNRESOLVED_EVENT_REF", rules)

    def test_every_displayed_event_id_exists_in_database(self):
        """Verifies that all event IDs in supporting_events and contradictory_events exist in SQLite."""
        case_stress = stress_test_case(self.case_id)
        conn = get_db_connection(Config.DATABASE_PATH)

        for eval_item in case_stress["evaluations"]:
            for ev in eval_item["supporting_events"]:
                eid = ev["id"]
                db_record = query_all(conn, "SELECT id FROM events WHERE case_id = ? AND id = ?", (self.case_id, eid))
                self.assertTrue(len(db_record) > 0, f"Event {eid} does not exist in database!")

            for cev in eval_item["contradictory_events"]:
                cid = cev["id"]
                db_record = query_all(conn, "SELECT id FROM events WHERE case_id = ? AND id = ?", (self.case_id, cid))
                self.assertTrue(len(db_record) > 0, f"Contradictory event {cid} does not exist in database!")
        conn.close()

    def test_stress_test_rest_api_endpoints(self):
        """Verifies GET /api/stress-test, GET /api/stress-test/<id>, and POST /api/stress-test/custom."""
        # 1. Full case evaluation
        resp = self.client.get(f"/api/stress-test?case_id={self.case_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("status_summary", data)
        self.assertIn("evaluations", data)
        self.assertTrue(len(data["evaluations"]) > 0)

        # 2. Single finding evaluation
        first_finding_id = data["evaluations"][0]["finding_id"]
        resp_single = self.client.get(f"/api/stress-test/{first_finding_id}?case_id={self.case_id}")
        self.assertEqual(resp_single.status_code, 200)
        single_data = resp_single.get_json()
        self.assertEqual(single_data["finding_id"], first_finding_id)
        self.assertIn("status", single_data)
        self.assertIn("warnings", single_data)

        # 3. Custom hypothesis POST
        resp_custom = self.client.post("/api/stress-test/custom", json={
            "case_id": self.case_id,
            "conclusion": "The customer database was copied to a USB device.",
            "event_ids": ["EVT-030", "EVT-022"]
        })
        self.assertEqual(resp_custom.status_code, 200)
        custom_data = resp_custom.get_json()
        self.assertEqual(custom_data["status"], STATUS_INSUFFICIENT)

    def test_stress_test_ui_route(self):
        """Verifies GET /stress-test renders 200 OK with proper HTML elements."""
        resp = self.client.get(f"/stress-test?case_id={self.case_id}")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")
        self.assertIn("Conclusion Stress Tester", html)
        self.assertIn("findingsStressTableBody", html)
        self.assertIn("customHypothesisCard", html)


if __name__ == "__main__":
    unittest.main()
