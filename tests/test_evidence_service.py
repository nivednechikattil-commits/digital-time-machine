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
        self.assertIn("Duplicate evidence file", res2["error"])

    def test_reject_unsupported_file_extension(self):
        bad_file = b"BINARY_PAYLOAD"
        res = import_evidence_file("CASE-TEST", bad_file, "malicious.exe")
        self.assertFalse(res["success"])
        self.assertIn("Unsupported file extension", res["error"])

if __name__ == "__main__":
    unittest.main()

