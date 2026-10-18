"""
Automated tests for Investigation Time Machine in Digital Time Machine.
Verifies snapshot lifecycle, SHA-256 integrity verification, and milestone evolution comparison:
- Creating and retrieving a snapshot
- Comparing identical snapshots
- Detecting added and removed findings
- Detecting a changed finding status
- Comparing evidence references
- Preserving older snapshots after a new snapshot is created
- Detecting a modified/tampered snapshot
- Handling invalid IDs and empty cases
- REST API endpoints and UI route
"""

import unittest
import json
from app import app
from database.db import get_db_connection, execute_write, query_one
from services.case_service import load_demo_case, update_finding_status
from services.snapshot_service import (
    create_snapshot,
    get_snapshot,
    list_snapshots,
    compare_snapshots
)
from config import Config


class TestInvestigationTimeMachine(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.case_id = "CASE-TEST-TIMEMACHINE"
        load_demo_case(self.case_id)

    def test_create_and_retrieve_snapshot(self):
        """Verifies creating and retrieving a named snapshot with verified integrity."""
        snap = create_snapshot(
            case_id=self.case_id,
            name="Baseline Analysis",
            note="Initial forensic triage milestone"
        )

        self.assertIn("id", snap)
        self.assertTrue(snap["id"].startswith("SNAP-"))
        self.assertEqual(snap["name"], "Baseline Analysis")
        self.assertEqual(snap["note"], "Initial forensic triage milestone")
        self.assertEqual(snap["integrity_status"], "verified")
        self.assertTrue(snap["finding_count"] > 0)
        self.assertTrue(snap["evidence_file_count"] > 0)

        # Retrieve full snapshot
        retrieved = get_snapshot(snap["id"])
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved["id"], snap["id"])
        self.assertEqual(retrieved["integrity_status"], "verified")
        self.assertFalse(retrieved["is_tampered"])
        self.assertEqual(len(retrieved["findings"]), snap["finding_count"])
        self.assertEqual(len(retrieved["evidence_files"]), snap["evidence_file_count"])

    def test_compare_identical_snapshots(self):
        """Comparing two identical snapshots shows all findings Unchanged and 0 diffs."""
        s1 = create_snapshot(self.case_id, "Milestone A", "First copy")
        s2 = create_snapshot(self.case_id, "Milestone B", "Second copy")

        diff = compare_snapshots(self.case_id, s1["id"], s2["id"])
        summary = diff["summary"]

        self.assertEqual(summary["findings_added_count"], 0)
        self.assertEqual(summary["findings_removed_count"], 0)
        self.assertEqual(summary["findings_changed_count"], 0)
        self.assertEqual(summary["evidence_files_added_count"], 0)
        self.assertEqual(summary["evidence_files_removed_count"], 0)
        self.assertEqual(summary["newly_detected_contradictions_count"], 0)
        self.assertTrue(summary["findings_unchanged_count"] > 0)
        self.assertEqual(len(diff["unchanged_findings"]), summary["findings_unchanged_count"])

    def test_detect_added_and_removed_findings(self):
        """Detects newly added findings in Snapshot B and removed findings when reversed."""
        s_baseline = create_snapshot(self.case_id, "Baseline Triage")

        # Insert a new finding into case
        conn = get_db_connection(Config.DATABASE_PATH)
        execute_write(
            conn,
            """INSERT INTO correlation_findings
               (id, case_id, rule_id, rule_name, severity, supporting_event_ids, explanation, start_time, end_time, confidence, limitations, recommended_action, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                "FIND-NEW-EXTRACT-01",
                self.case_id,
                "RULE_CUSTOM",
                "New Suspicious Exfiltration Pattern",
                "critical",
                json.dumps(["EVT-020", "EVT-041"]),
                "Outbound data burst detected following executable download.",
                "2026-10-07T10:02:45",
                "2026-10-07T10:09:00",
                "observed_correlation",
                "None",
                "Isolate endpoint",
                "open"
            )
        )
        conn.close()

        s_post_finding = create_snapshot(self.case_id, "Post New Finding Extraction")

        # 1. Forward comparison: Baseline -> Post (Finding was Added)
        diff_forward = compare_snapshots(self.case_id, s_baseline["id"], s_post_finding["id"])
        self.assertEqual(diff_forward["summary"]["findings_added_count"], 1)
        added = diff_forward["added_findings"][0]
        self.assertEqual(added["finding_id"], "FIND-NEW-EXTRACT-01")
        self.assertEqual(added["diff_type"], "Added")
        self.assertIn("timeline_url", added)

        # 2. Reverse comparison: Post -> Baseline (Finding was Removed)
        diff_reverse = compare_snapshots(self.case_id, s_post_finding["id"], s_baseline["id"])
        self.assertEqual(diff_reverse["summary"]["findings_removed_count"], 1)
        removed = diff_reverse["removed_findings"][0]
        self.assertEqual(removed["finding_id"], "FIND-NEW-EXTRACT-01")
        self.assertEqual(removed["diff_type"], "Removed")
        self.assertIn("Removal does not prove the hypothesis was disproved", removed["attribution"])

    def test_detect_changed_finding_status(self):
        """Detects when an investigator modifies a finding status between snapshots."""
        s1 = create_snapshot(self.case_id, "Before Status Update")

        # Modify status of FIND-A-01 from open to under_review then resolved
        update_finding_status(self.case_id, "FIND-A-01", "resolved")

        s2 = create_snapshot(self.case_id, "After Resolution Milestone")

        diff = compare_snapshots(self.case_id, s1["id"], s2["id"])
        self.assertEqual(diff["summary"]["findings_changed_count"], 1)

        changed = diff["changed_findings"][0]
        self.assertEqual(changed["finding_id"], "FIND-A-01")
        self.assertEqual(changed["diff_type"], "Changed")
        self.assertEqual(changed["status"], "resolved")

        # Check mutation record
        status_change = next(c for c in changed["changes"] if c["field"] == "status")
        self.assertEqual(status_change["old_value"], "open")
        self.assertEqual(status_change["new_value"], "resolved")
        self.assertIn("Status modified by investigator review", changed["attribution"])

    def test_compare_evidence_references(self):
        """Detects new evidence files added or excluded between snapshots."""
        s1 = create_snapshot(self.case_id, "Prior to Supplemental Upload")

        # Add a supplemental evidence file record
        conn = get_db_connection(Config.DATABASE_PATH)
        execute_write(
            conn,
            """INSERT INTO evidence_files
               (case_id, filename, original_filename, file_type, sha256_hash, record_count, valid_count, invalid_count, imported_at, file_size_bytes)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                self.case_id,
                "supplemental_edr_audit.csv",
                "supplemental_edr_audit.csv",
                "csv",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                42,
                42,
                0,
                "2026-10-18T14:00:00",
                2048
            )
        )
        conn.close()

        s2 = create_snapshot(self.case_id, "After Supplemental Upload")

        diff = compare_snapshots(self.case_id, s1["id"], s2["id"])
        ev_diff = diff["evidence_diff"]

        self.assertEqual(len(ev_diff["added"]), 1)
        self.assertEqual(ev_diff["added"][0]["filename"], "supplemental_edr_audit.csv")
        self.assertEqual(diff["summary"]["evidence_files_added_count"], 1)

    def test_preserve_older_snapshots_immutability(self):
        """Verifies older snapshots are not overwritten or mutated when new snapshots are created."""
        s1 = create_snapshot(self.case_id, "Snapshot 1")
        s1_original = get_snapshot(s1["id"])

        # Create multiple subsequent snapshots
        s2 = create_snapshot(self.case_id, "Snapshot 2")
        update_finding_status(self.case_id, "FIND-A-01", "resolved")
        s3 = create_snapshot(self.case_id, "Snapshot 3")

        # Verify s1 remains completely intact and verified
        s1_recheck = get_snapshot(s1["id"])
        self.assertEqual(s1_recheck["id"], s1_original["id"])
        self.assertEqual(s1_recheck["name"], s1_original["name"])
        self.assertEqual(s1_recheck["integrity_hash"], s1_original["integrity_hash"])
        self.assertEqual(s1_recheck["integrity_status"], "verified")
        self.assertFalse(s1_recheck["is_tampered"])
        self.assertEqual(s1_recheck["finding_count"], s1_original["finding_count"])

    def test_detect_tampered_snapshot(self):
        """Verifies that unauthorized modifications to snapshot rows are detected by SHA-256 hash."""
        snap = create_snapshot(self.case_id, "Integrity Test Snapshot")

        # Direct database tampering simulation
        conn = get_db_connection(Config.DATABASE_PATH)
        execute_write(
            conn,
            "UPDATE snapshot_findings SET severity = 'critical' WHERE snapshot_id = ? AND finding_id = 'FIND-A-01'",
            (snap["id"],)
        )
        conn.close()

        tampered_snap = get_snapshot(snap["id"])
        self.assertEqual(tampered_snap["integrity_status"], "tampered")
        self.assertTrue(tampered_snap["is_tampered"])

    def test_invalid_snapshot_ids_and_empty_case_handling(self):
        """Verifies graceful handling of non-existent snapshots and empty names."""
        # Non-existent snapshot ID
        self.assertIsNone(get_snapshot("SNAP-NON-EXISTENT-ID"))

        # Empty snapshot name raises ValueError
        with self.assertRaises(ValueError):
            create_snapshot(self.case_id, "   ")

        # Non-existent case raises ValueError
        with self.assertRaises(ValueError):
            create_snapshot("CASE-NON-EXISTENT", "Test")

        # Comparison with invalid ID raises ValueError
        s1 = create_snapshot(self.case_id, "Valid Snapshot")
        with self.assertRaises(ValueError):
            compare_snapshots(self.case_id, s1["id"], "SNAP-INVALID-ID")

    def test_snapshots_rest_api_endpoints(self):
        """Verifies GET /api/snapshots, POST /api/snapshots, and GET /api/snapshots/compare."""
        # 1. Create via POST /api/snapshots
        resp_post = self.client.post("/api/snapshots", json={
            "case_id": self.case_id,
            "name": "API Milestone Snapshot",
            "note": "Created via REST API"
        })
        self.assertEqual(resp_post.status_code, 201)
        created_snap = resp_post.get_json()["snapshot"]
        snap_id = created_snap["id"]

        # 2. List via GET /api/snapshots
        resp_list = self.client.get(f"/api/snapshots?case_id={self.case_id}")
        self.assertEqual(resp_list.status_code, 200)
        list_data = resp_list.get_json()
        self.assertTrue(list_data["count"] > 0)
        self.assertIn(snap_id, [s["id"] for s in list_data["snapshots"]])

        # 3. Retrieve single via GET /api/snapshots/<id>
        resp_get = self.client.get(f"/api/snapshots/{snap_id}")
        self.assertEqual(resp_get.status_code, 200)
        get_data = resp_get.get_json()
        self.assertEqual(get_data["id"], snap_id)
        self.assertEqual(get_data["integrity_status"], "verified")

        # 4. Compare via GET /api/snapshots/compare
        # Create second snapshot
        resp_s2 = self.client.post("/api/snapshots", json={
            "case_id": self.case_id,
            "name": "Second API Milestone",
            "note": "Comparison target"
        })
        s2_id = resp_s2.get_json()["snapshot"]["id"]

        resp_cmp = self.client.get(f"/api/snapshots/compare?case_id={self.case_id}&snapshot_a_id={snap_id}&snapshot_b_id={s2_id}")
        self.assertEqual(resp_cmp.status_code, 200)
        cmp_data = resp_cmp.get_json()
        self.assertIn("summary", cmp_data)
        self.assertIn("unchanged_findings", cmp_data)

    def test_time_machine_ui_route(self):
        """Verifies GET /time-machine renders 200 OK with expected DOM containers."""
        resp = self.client.get(f"/time-machine?case_id={self.case_id}")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")
        self.assertIn("Investigation Time Machine", html)
        self.assertIn("selectSnapshotA", html)
        self.assertIn("savedSnapshotsTableBody", html)


if __name__ == "__main__":
    unittest.main()
