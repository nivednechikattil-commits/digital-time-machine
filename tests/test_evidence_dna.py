"""
Unit and integration test suite for Evidence DNA engine and API endpoints.
Verifies forensic lineage, database accuracy, unavailable evidence handling,
factual vs. inferred segregation, and regression resistance.
"""

import unittest
import json
from app import app
from config import Config
from database.db import get_db_connection, execute_write, query_one
from engine.evidence_dna import get_evidence_dna, parse_event_ids


class TestEvidenceDNA(unittest.TestCase):

    def setUp(self):
        self.client = app.test_client()
        self.case_id = Config.DEMO_CASE_ID

    def test_parse_event_ids_various_formats(self):
        """Verifies robust parsing of event IDs from lists, JSON strings, and empty values."""
        self.assertEqual(parse_event_ids(["EVT-001", "EVT-002"]), ["EVT-001", "EVT-002"])
        self.assertEqual(parse_event_ids('["EVT-001", "EVT-002"]'), ["EVT-001", "EVT-002"])
        self.assertEqual(parse_event_ids('EVT-001, EVT-002'), ["EVT-001", "EVT-002"])
        self.assertEqual(parse_event_ids("[]"), [])
        self.assertEqual(parse_event_ids(""), [])
        self.assertEqual(parse_event_ids(None), [])

    def test_evidence_dna_with_supporting_events(self):
        """
        Requirement 1, 2, 3: Test at least one finding with supporting events.
        Verify event IDs, timestamps, event types, source names, and rule match database.
        """
        dna = get_evidence_dna(self.case_id, "FIND-A-01")
        self.assertIsNotNone(dna)
        self.assertEqual(dna["finding_id"], "FIND-A-01")
        self.assertEqual(dna["evidence_status"], "available")
        self.assertTrue(dna["has_supporting_evidence"])
        self.assertEqual(dna["supporting_event_count"], 2)

        # Verify detection rule metadata
        inferred = dna["inferred_conclusions"]
        self.assertEqual(inferred["rule_id"], "RULE_A")
        self.assertEqual(inferred["rule_name"], "Suspicious Website Visit Preceding File Download")
        self.assertIn("explanation", inferred)
        self.assertTrue(len(inferred["explanation"]) > 0)
        self.assertIn("limitations", inferred)

        # Verify facts match database records strictly
        conn = get_db_connection(Config.DATABASE_PATH)
        facts = dna["recorded_facts"]
        self.assertEqual(len(facts), 2)

        for fact in facts:
            event_id = fact["event_id"]
            db_row = query_one(conn, "SELECT * FROM events WHERE case_id = ? AND id = ?", (self.case_id, event_id))
            self.assertIsNotNone(db_row, f"Event {event_id} must exist in SQLite database")
            
            # Exact field matches
            self.assertEqual(fact["timestamp"], db_row["timestamp"])
            self.assertEqual(fact["source"], db_row["source"])
            self.assertEqual(fact["event_type"], db_row["event_type"])
            self.assertEqual(fact["actor"], db_row["actor"])
            self.assertEqual(fact["target_object"], db_row["object"])
            self.assertEqual(fact["severity"], db_row["severity"])
            self.assertEqual(fact["evidence_ref"], db_row["evidence_ref"])
            self.assertEqual(fact["confidence"], "observed")

            # Navigation URLs
            self.assertIn(f"event_id={event_id}", fact["timeline_url"])
            self.assertIn(f"file={db_row['evidence_ref']}", fact["evidence_explorer_url"])

        conn.close()

    def test_evidence_dna_finding_with_no_linked_evidence(self):
        """
        Requirement 8: Test a finding with no linked evidence.
        Must report evidence as unavailable instead of inventing links or fake telemetry.
        """
        conn = get_db_connection(Config.DATABASE_PATH)
        unlinked_finding_id = "FIND-UNLINKED-TEST"
        
        # Insert a synthetic finding with empty supporting event list
        execute_write(
            conn,
            """INSERT OR REPLACE INTO correlation_findings
               (id, case_id, rule_id, rule_name, severity, supporting_event_ids, explanation, start_time, end_time, confidence, limitations, recommended_action)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                unlinked_finding_id,
                self.case_id,
                "RULE_ORPHAN",
                "Unlinked Forensic Hypothesis",
                "medium",
                "[]",
                "Hypothetical rule deduction lacking recorded supporting evidence.",
                "2026-10-07T10:00:00",
                "2026-10-07T10:00:00",
                "inferred",
                "No raw evidence available.",
                "Conduct further acquisition."
            )
        )
        conn.close()

        try:
            dna = get_evidence_dna(self.case_id, unlinked_finding_id)
            self.assertIsNotNone(dna)
            self.assertEqual(dna["evidence_status"], "unavailable")
            self.assertFalse(dna["has_supporting_evidence"])
            self.assertEqual(dna["supporting_event_count"], 0)
            self.assertEqual(len(dna["recorded_facts"]), 0)
            self.assertEqual(len(dna["supporting_events"]), 0)
            self.assertIn("unavailable", dna["status_message"].lower())
            
            # Ensure no invented event IDs
            self.assertEqual(dna["recorded_facts"], [])
        finally:
            # Clean up test finding
            conn = get_db_connection(Config.DATABASE_PATH)
            execute_write(conn, "DELETE FROM correlation_findings WHERE id = ?", (unlinked_finding_id,))
            conn.close()

    def test_evidence_dna_rest_api_endpoints(self):
        """Verifies GET /api/incidents/<id> and GET /api/incidents/<id>/evidence-dna."""
        resp = self.client.get(f"/api/incidents/FIND-A-01?case_id={self.case_id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["finding_id"], "FIND-A-01")
        self.assertEqual(data["evidence_status"], "available")
        self.assertEqual(len(data["recorded_facts"]), 2)

        # Test alias endpoint
        resp_alias = self.client.get(f"/api/incidents/FIND-A-01/evidence-dna?case_id={self.case_id}")
        self.assertEqual(resp_alias.status_code, 200)
        self.assertEqual(resp_alias.get_json()["finding_id"], "FIND-A-01")

        # Test 404 for unknown finding ID
        resp_404 = self.client.get(f"/api/incidents/NONEXISTENT-999?case_id={self.case_id}")
        self.assertEqual(resp_404.status_code, 404)

    def test_contradictory_or_missing_evidence_distinction(self):
        """
        Requirement 4: Show contradictory or missing evidence only when supported by dataset.
        FIND-C-04 involves USB which has an unclosed device lifecycle anomaly.
        FIND-D-05 has standard login logs without gaps.
        """
        # Finding C (USB proximate to copy) should detect unclosed USB lifecycle
        dna_c = get_evidence_dna(self.case_id, "FIND-C-04")
        self.assertIsNotNone(dna_c)
        self.assertTrue(dna_c["has_contradictions_or_gaps"])
        gap_types = [g["type"] for g in dna_c["contradictory_or_missing"]]
        self.assertIn("UNCLOSED_ARTIFACT_LIFECYCLE", gap_types)

        # Finding D (failed logins then success) should have clean dataset check
        dna_d = get_evidence_dna(self.case_id, "FIND-D-05")
        self.assertIsNotNone(dna_d)
        self.assertFalse(dna_d["has_contradictions_or_gaps"])
        self.assertIn("No contradictory telemetry", dna_d["dataset_gap_note"])

    def test_facts_vs_conclusions_distinction(self):
        """
        Requirement 7: Clearly distinguish recorded facts from inferred conclusions.
        """
        dna = get_evidence_dna(self.case_id, "FIND-B-03")
        self.assertIn("recorded_facts", dna)
        self.assertIn("inferred_conclusions", dna)

        # Recorded facts must all have confidence 'observed'
        for f in dna["recorded_facts"]:
            self.assertEqual(f["confidence"], "observed")

        # Inferred conclusions must reference detection rule
        self.assertEqual(dna["inferred_conclusions"]["rule_id"], "RULE_B")
        self.assertIn("limitations", dna["inferred_conclusions"])


if __name__ == "__main__":
    unittest.main()

