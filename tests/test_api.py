"""
Integration tests for app.py REST API endpoints.
Tests status codes, JSON response formats, query parameters, and error handling.
"""

import io
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

    def test_case_detail_endpoint(self):
        resp = self.client.get(f"/api/cases/{self.case_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("case", data)
        self.assertEqual(data["case"]["id"], self.case_id)

    def test_load_demo_endpoint_post(self):
        """Verifies POST /api/cases/load-demo succeeds without Method Not Allowed error."""
        resp = self.client.post("/api/cases/load-demo", json={"case_id": self.case_id})
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("case_id"), self.case_id)
        self.assertIn("seeded successfully", data.get("message", ""))
        self.assertIn("metrics", data)
        self.assertTrue(data["metrics"]["total_events"] > 0)

    def test_load_demo_endpoint_get(self):
        """Verifies GET /api/cases/load-demo succeeds for browser navigation/curl requests."""
        resp = self.client.get(f"/api/cases/load-demo?case_id={self.case_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data.get("case_id"), self.case_id)

    def test_method_not_allowed_on_invalid_method(self):
        """Verifies 405 Method Not Allowed is returned for genuinely unsupported HTTP methods."""
        resp = self.client._request("DELETE", f"/api/cases/{self.case_id}")
        self.assertEqual(resp.status_code, 405)

    def test_exact_failing_request_load_demo_populates_dashboard(self):
        """Regression test: verifies exact POST request from dashboard 'Load Demo Case' button populates metrics."""
        # 1. Exact POST request sent by loadDemoBtn fetch()
        resp = self.client.post("/api/cases/load-demo", json={"case_id": self.case_id})
        self.assertEqual(resp.status_code, 200, "Must return 200 OK, never 405 Method Not Allowed")
        data = resp.get_json()
        self.assertTrue(data.get("success"))
        metrics = data.get("metrics", {})
        self.assertEqual(metrics.get("total_events"), 18)
        self.assertEqual(metrics.get("evidence_files_count"), 5)
        self.assertEqual(metrics.get("correlation_findings_count"), 9)
        self.assertEqual(metrics.get("ghost_anomalies_count"), 6)

        # 2. Check dashboard view renders populated non-zero metrics
        dash_resp = self.client.get(f"/?case_id={self.case_id}")
        self.assertEqual(dash_resp.status_code, 200)
        self.assertIn(b"18", dash_resp.data)

    def test_demo_load_preserves_unrelated_cases(self):
        """Requirement 6: Ensure demo data is loaded without deleting or overwriting unrelated cases."""
        from services.case_service import get_or_create_case, get_case
        get_or_create_case("CASE-CUSTOM-99", "Custom User Investigation", "Preserved user data")

        # Load demo case for CASE-001
        resp = self.client.post("/api/cases/load-demo", json={"case_id": "CASE-001"})
        self.assertEqual(resp.status_code, 200)

        # Verify unrelated case was preserved
        unrelated = get_case("CASE-CUSTOM-99")
        self.assertIsNotNone(unrelated)
    def test_user_case_load_demo_and_cross_module_consistency(self):
        """Verifies demo data loads into active case (e.g. CASE-2026-002) and timeline, graph, state, findings, ghost evidence and report all use it."""
        test_case = "CASE-2026-002"

        # 1. Trigger demo loading via button endpoint
        resp_load = self.client.post("/api/cases/load-demo", json={"case_id": test_case})
        self.assertEqual(resp_load.status_code, 200)
        data = resp_load.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["case_id"], test_case)

        # 2. Timeline uses the case data
        resp_events = self.client.get(f"/api/events?case_id={test_case}")
        self.assertEqual(resp_events.status_code, 200)
        self.assertEqual(resp_events.get_json()["count"], 18)

        # 3. Correlation findings use the case data
        resp_incidents = self.client.get(f"/api/incidents?case_id={test_case}")
        self.assertEqual(resp_incidents.status_code, 200)
        self.assertEqual(resp_incidents.get_json()["count"], 9)

        # 4. System state uses the case data
        resp_state = self.client.get(f"/api/state?case_id={test_case}&timestamp=2026-10-07T10:15:00")
        self.assertEqual(resp_state.status_code, 200)
        self.assertEqual(resp_state.get_json()["state"]["total_events_in_case"], 18)

        # 5. Ghost evidence uses the case data
        resp_ghost = self.client.get(f"/api/ghost-evidence?case_id={test_case}")
        self.assertEqual(resp_ghost.status_code, 200)
        self.assertEqual(resp_ghost.get_json()["count"], 6)

        # 6. Report uses the case data
        resp_report = self.client.get(f"/api/report?case_id={test_case}")
        self.assertEqual(resp_report.status_code, 200)
        rep = resp_report.get_json()
        self.assertEqual(len(rep["evidence_files"]), 5)
        self.assertEqual(len(rep["correlation_findings"]), 9)

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

    def test_upload_login_events_csv_and_duplicate_prevention(self):
        """Verifies POST /api/upload ingests login_events.csv, returns SHA-256 and records, and blocks duplicates."""
        import uuid
        test_case_id = f"CASE-UPLOAD-{uuid.uuid4().hex[:8]}"
        with open("data/demo/login_events.csv", "rb") as f:
            csv_bytes = f.read()

        # 1. Valid upload
        data = {
            "case_id": test_case_id,
            "file": ("login_events.csv", csv_bytes)
        }
        resp = self.client.post("/api/upload", data=data)
        self.assertEqual(resp.status_code, 200)
        res_json = resp.get_json()
        self.assertTrue(res_json.get("success"))
        self.assertEqual(res_json.get("filename"), "login_events.csv")
        self.assertEqual(res_json.get("accepted"), 4)
        self.assertEqual(res_json.get("rejected"), 0)
        self.assertEqual(res_json.get("total_records"), 4)
        self.assertTrue(len(res_json.get("sha256")) == 64)

        # 2. Duplicate upload rejection
        data_dup = {
            "case_id": test_case_id,
            "file": ("login_events.csv", csv_bytes)
        }
        resp_dup = self.client.post("/api/upload", data=data_dup)
        self.assertEqual(resp_dup.status_code, 400)
        dup_json = resp_dup.get_json()
        self.assertFalse(dup_json.get("success"))
        self.assertTrue(dup_json.get("duplicate"))
        self.assertEqual(dup_json.get("error"), "Duplicate evidence detected. This file has already been ingested.")
        self.assertIn("existing_file", dup_json)
        self.assertEqual(dup_json["existing_file"]["sha256_hash"], res_json["sha256"])

    def test_upload_identical_contents_different_filenames(self):
        """Requirement 11: Uploading identical contents under different filenames."""
        import uuid
        test_case_id = f"CASE-DUP-NAME-{uuid.uuid4().hex[:8]}"
        payload = b"id,timestamp,source,event_type,actor,object,severity,description\nEVT-D1,2026-10-07T12:00:00,login,LOGIN_SUCCESS,userA,ws-1,low,desc\n"

        # First upload as original_events.csv
        data1 = {"case_id": test_case_id, "file": ("original_events.csv", payload)}
        resp1 = self.client.post("/api/upload", data=data1)
        self.assertEqual(resp1.status_code, 200)

        # Second upload with different filename but identical content
        data2 = {"case_id": test_case_id, "file": ("different_filename.csv", payload)}
        resp2 = self.client.post("/api/upload", data=data2)
        self.assertEqual(resp2.status_code, 400)
        dup_json = resp2.get_json()
        self.assertTrue(dup_json.get("duplicate"))
        self.assertEqual(dup_json.get("error"), "Duplicate evidence detected. This file has already been ingested.")

    def test_upload_same_filename_different_contents(self):
        """Requirement 4 & 11: Uploading the same filename with different contents must allow both."""
        import uuid
        test_case_id = f"CASE-DIFF-CONTENT-{uuid.uuid4().hex[:8]}"
        payload1 = b"id,timestamp,source,event_type,actor,object,severity,description\nEVT-V1,2026-10-07T10:00:00,file,FILE_CREATE,alice,f1.doc,low,First file\n"
        payload2 = b"id,timestamp,source,event_type,actor,object,severity,description\nEVT-V2,2026-10-07T10:30:00,file,FILE_DELETE,alice,f1.doc,medium,Second file\n"

        # Upload first file with name report.csv
        resp1 = self.client.post("/api/upload", data={"case_id": test_case_id, "file": ("report.csv", payload1)})
        self.assertEqual(resp1.status_code, 200)
        json1 = resp1.get_json()
        self.assertTrue(json1.get("success"))

        # Upload second file with SAME name report.csv but DIFFERENT contents/SHA-256
        resp2 = self.client.post("/api/upload", data={"case_id": test_case_id, "file": ("report.csv", payload2)})
        self.assertEqual(resp2.status_code, 200)
        json2 = resp2.get_json()
        self.assertTrue(json2.get("success"))

        self.assertNotEqual(json1.get("sha256"), json2.get("sha256"))

        # Verify both records exist in evidence store
        resp_list = self.client.get(f"/api/evidence?case_id={test_case_id}")
        self.assertEqual(resp_list.status_code, 200)
        files = resp_list.get_json().get("files", [])
        self.assertEqual(len(files), 2)

    def test_refresh_page_and_upload_existing_file(self):
        """Requirement 6 & 11: Refreshing the page and uploading an existing file."""
        import uuid
        test_case_id = f"CASE-REFRESH-{uuid.uuid4().hex[:8]}"
        payload = b"id,timestamp,source,event_type,actor,object,severity,description\nEVT-R1,2026-10-07T14:00:00,login,LOGIN_SUCCESS,bob,ws-9,low,Persist test\n"

        # 1. Ingest evidence
        resp1 = self.client.post("/api/upload", data={"case_id": test_case_id, "file": ("persist_test.csv", payload)})
        self.assertEqual(resp1.status_code, 200)
        sha256_hash = resp1.get_json().get("sha256")

        # 2. Simulate page refresh: GET /evidence
        resp_page = self.client.get(f"/evidence?case_id={test_case_id}")
        self.assertEqual(resp_page.status_code, 200)
        self.assertIn(b"persist_test.csv", resp_page.data)
        self.assertIn(sha256_hash.encode("utf-8"), resp_page.data)
        self.assertIn(b'data-sha256="', resp_page.data)

        # 3. Check events count
        resp_events_before = self.client.get(f"/api/events?case_id={test_case_id}")
        events_before = resp_events_before.get_json().get("count", 0)

        # 4. Upload existing file again after "refresh"
        resp2 = self.client.post("/api/upload", data={"case_id": test_case_id, "file": ("persist_test.csv", payload)})
        self.assertEqual(resp2.status_code, 400)
        json2 = resp2.get_json()
        self.assertTrue(json2.get("duplicate"))
        self.assertEqual(json2.get("error"), "Duplicate evidence detected. This file has already been ingested.")

        # 5. Verify timeline events count has not changed
        resp_events_after = self.client.get(f"/api/events?case_id={test_case_id}")
        events_after = resp_events_after.get_json().get("count", 0)
        self.assertEqual(events_before, events_after)

    def test_rapidly_clicking_ingestion_simulation(self):
        """Requirement 5 & 11: Rapidly clicking the ingestion button (concurrent / sequential rapid POSTs)."""
        import uuid
        test_case_id = f"CASE-RAPID-{uuid.uuid4().hex[:8]}"
        payload = b"id,timestamp,source,event_type,actor,object,severity,description\nEVT-RC1,2026-10-07T16:00:00,login,LOGIN_SUCCESS,alice,ws-1,low,Rapid test\n"

        # Simulate 5 rapid submissions of the same evidence file
        responses = []
        for _ in range(5):
            r = self.client.post("/api/upload", data={"case_id": test_case_id, "file": ("rapid_click.csv", payload)})
            responses.append(r)

        success_count = sum(1 for r in responses if r.status_code == 200)
        duplicate_count = sum(1 for r in responses if r.status_code == 400 and r.get_json().get("duplicate"))

        # Exactly 1 must succeed; the remaining 4 must be blocked as duplicates
        self.assertEqual(success_count, 1)
        self.assertEqual(duplicate_count, 4)

        # Evidence table must have exactly 1 file record
        resp_list = self.client.get(f"/api/evidence?case_id={test_case_id}")
        files = resp_list.get_json().get("files", [])
        self.assertEqual(len(files), 1)

    def test_upload_empty_file_rejected(self):
        """Verifies POST /api/upload rejects empty files with clear error."""
        data = {
            "case_id": "CASE-UPLOAD-EMPTY",
            "file": ("empty.csv", b"")
        }
        resp = self.client.post("/api/upload", data=data)
        self.assertEqual(resp.status_code, 400)
        res_json = resp.get_json()
        self.assertFalse(res_json.get("success"))
        self.assertIn("empty", res_json.get("error", "").lower())

    def test_upload_invalid_extension_rejected(self):
        """Verifies POST /api/upload rejects unsupported file extensions."""
        data = {
            "case_id": "CASE-UPLOAD-EXT",
            "file": ("payload.exe", b"binary payload")
        }
        resp = self.client.post("/api/upload", data=data)
        self.assertEqual(resp.status_code, 400)
        res_json = resp.get_json()
        self.assertFalse(res_json.get("success"))
        self.assertIn("unsupported", res_json.get("error", "").lower())

if __name__ == "__main__":
    unittest.main()
