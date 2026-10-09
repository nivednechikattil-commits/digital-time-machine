"""
Integration tests for app.py REST API endpoints.
Tests status codes, JSON response formats, query parameters, and error handling.
"""

import unittest
from app import app
from config import Config

class TestAPIEndpoints(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        self.case_id = Config.DEMO_CASE_ID

    def test_health_endpoint(self):
        resp = self.client.get("/api/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["service"], "Digital Time Machine")

    def test_cases_endpoint(self):
        resp = self.client.get("/api/cases")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("cases", data)
        self.assertTrue(len(data["cases"]) >= 1)

    def test_events_endpoint_and_filters(self):
        resp = self.client.get(f"/api/events?case_id={self.case_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("events", data)
        total = data["count"]
        self.assertTrue(total > 0)

        # Test source filter
        resp_login = self.client.get(f"/api/events?case_id={self.case_id}&source=login")
        data_login = resp_login.get_json()
        for ev in data_login["events"]:
            self.assertEqual(ev["source"], "login")

    def test_system_state_endpoint(self):
        resp = self.client.get(f"/api/state?case_id={self.case_id}&timestamp=2026-10-07T10:15:00")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("state", data)
        state = data["state"]
        self.assertIn("active_sessions", state)
        self.assertIn("file_system", state)
        self.assertIn("connected_devices", state)
        self.assertIn("network_connections", state)

    def test_incidents_correlation_endpoint(self):
        resp = self.client.get(f"/api/incidents?case_id={self.case_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("findings", data)
        self.assertTrue(data["count"] > 0)

    def test_ghost_evidence_endpoint(self):
        resp = self.client.get(f"/api/ghost-evidence?case_id={self.case_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("anomalies", data)
        self.assertTrue(data["count"] > 0)

    def test_investigate_post_endpoint(self):
        resp = self.client.post("/api/investigate", json={"question_id": "Q1"})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["question_id"], "Q1")
        self.assertIn("answer", data)
        self.assertIn("supporting_event_ids", data)

    def test_notes_post_and_get(self):
        new_note = {"note": "Test forensic triage note", "author": "Examiner 42"}
        resp = self.client.post("/api/notes", json=new_note)
        self.assertEqual(resp.status_code, 201)
        data = resp.get_json()
        self.assertEqual(data["note"], "Test forensic triage note")

        resp_get = self.client.get(f"/api/notes?case_id={self.case_id}")
        self.assertEqual(resp_get.status_code, 200)

    def test_report_json_endpoint(self):
        resp = self.client.get(f"/api/report?case_id={self.case_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("disclaimer", data)
        self.assertIn("evidence_files", data)
        self.assertIn("correlation_findings", data)

if __name__ == "__main__":
    unittest.main()
