"""
Unit tests for services/evidence_service.py.
Tests SHA-256 hashing, duplicate prevention, and file ingestion diagnostics.
"""

import unittest
import os
import tempfile
from services.case_service import get_or_create_case
from services.evidence_service import import_evidence_file
from database.db import init_db
from config import Config

class TestEvidenceService(unittest.TestCase):

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.orig_db_path = Config.DATABASE_PATH
        Config.DATABASE_PATH = self.temp_file.name
        self.temp_file.close()
        init_db(Config.DATABASE_PATH)
        get_or_create_case("CASE-TEST", "Test Case")

    def tearDown(self):
        Config.DATABASE_PATH = self.orig_db_path
        if os.path.exists(self.temp_file.name):
            os.remove(self.temp_file.name)

    def test_import_and_duplicate_prevention(self):
        csv_content = b"""id,timestamp,source,event_type,actor,object,severity,description
EVT-1,2026-10-07T10:00:00,login,LOGIN_SUCCESS,alice,ws-1,low,desc
"""
        # First import should succeed
        res1 = import_evidence_file("CASE-TEST", csv_content, "evidence.csv")
        self.assertTrue(res1["success"])
        self.assertEqual(res1["accepted"], 1)
        self.assertIn("sha256", res1)

        # Second import with identical content should be rejected as duplicate
        res2 = import_evidence_file("CASE-TEST", csv_content, "evidence_copy.csv")
        self.assertFalse(res2["success"])
        self.assertTrue(res2.get("duplicate"))
        self.assertIn("Duplicate evidence detected", res2["error"])
        self.assertIn("existing_file", res2)
        self.assertEqual(res2["existing_file"]["sha256_hash"], res1["sha256"])

    def test_identical_contents_different_filenames_blocked(self):
        """Requirement 11: Uploading identical contents under different filenames must be blocked."""
        content = b"id,timestamp,source,event_type,actor,object,severity,description\nEVT-9,2026-10-07T12:00:00,login,LOGIN_SUCCESS,bob,ws-2,low,Test\n"
        res1 = import_evidence_file("CASE-TEST", content, "original_name.csv")
        self.assertTrue(res1["success"])

        # Identical bytes, different filename
        res2 = import_evidence_file("CASE-TEST", content, "renamed_file.csv")
        self.assertFalse(res2["success"])
        self.assertTrue(res2.get("duplicate"))
        self.assertEqual(res2["error"], "Duplicate evidence detected. This file has already been ingested.")

    def test_same_filename_different_contents_both_allowed(self):
        """Requirement 4 & 11: Two files with same filename but different SHA-256 hashes must both be stored."""
        content_v1 = b"id,timestamp,source,event_type,actor,object,severity,description\nEVT-10,2026-10-07T13:00:00,file,FILE_CREATE,alice,doc.txt,low,Create\n"
        content_v2 = b"id,timestamp,source,event_type,actor,object,severity,description\nEVT-11,2026-10-07T14:00:00,file,FILE_DELETE,alice,doc.txt,medium,Delete\n"

        res1 = import_evidence_file("CASE-TEST", content_v1, "audit.csv")
        self.assertTrue(res1["success"])
        hash1 = res1["sha256"]

        res2 = import_evidence_file("CASE-TEST", content_v2, "audit.csv")
        self.assertTrue(res2["success"])
        hash2 = res2["sha256"]

        self.assertNotEqual(hash1, hash2)

        # Verify database has both records as separate evidence items
        from database.db import get_db_connection, query_all
        conn = get_db_connection(Config.DATABASE_PATH)
        files = query_all(conn, "SELECT * FROM evidence_files WHERE case_id = 'CASE-TEST' AND original_filename = 'audit.csv'")
        conn.close()
        self.assertEqual(len(files), 2)
        hashes = [f["sha256_hash"] for f in files]
        self.assertIn(hash1, hashes)
        self.assertIn(hash2, hashes)

    def test_duplicate_upload_does_not_add_timeline_events(self):
        """Requirement 9: Prevent duplicate events from being added to timeline on duplicate upload."""
        from database.db import get_db_connection, query_one
        content = b"id,timestamp,source,event_type,actor,object,severity,description\nEVT-99,2026-10-07T15:00:00,login,LOGIN_SUCCESS,user1,ws-1,low,Login\n"
        res1 = import_evidence_file("CASE-TEST", content, "login.csv")
        self.assertTrue(res1["success"])

        conn = get_db_connection(Config.DATABASE_PATH)
        count_before = query_one(conn, "SELECT count(*) as c FROM events WHERE case_id = 'CASE-TEST'")["c"]
        conn.close()

        # Re-upload same file
        res2 = import_evidence_file("CASE-TEST", content, "login.csv")
        self.assertFalse(res2["success"])
        self.assertTrue(res2.get("duplicate"))

        conn = get_db_connection(Config.DATABASE_PATH)
        count_after = query_one(conn, "SELECT count(*) as c FROM events WHERE case_id = 'CASE-TEST'")["c"]
        conn.close()

        self.assertEqual(count_before, count_after, "Timeline events count must not increase on duplicate upload")

    def test_reject_unsupported_file_extension(self):
        bad_file = b"BINARY_PAYLOAD"
        res = import_evidence_file("CASE-TEST", bad_file, "malicious.exe")
        self.assertFalse(res["success"])
        self.assertIn("Unsupported file extension", res["error"])

if __name__ == "__main__":
    unittest.main()

