"""
Unit tests for database/db.py.
Tests SQLite initialization, schema enforcement, transactional queries, and case isolation.
"""

import unittest
import os
import tempfile
from database.db import get_db_connection, init_db, query_all, query_one, execute_write

class TestDatabase(unittest.TestCase):

    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db_path = self.temp_file.name
        self.temp_file.close()
        init_db(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_init_db_creates_tables(self):
        conn = get_db_connection(self.db_path)
        tables = query_all(conn, "SELECT name FROM sqlite_master WHERE type='table'")
        table_names = [t["name"] for t in tables]
        conn.close()

        self.assertIn("cases", table_names)
        self.assertIn("events", table_names)
        self.assertIn("evidence_files", table_names)
        self.assertIn("correlation_findings", table_names)
        self.assertIn("investigation_notes", table_names)

    def test_case_isolation(self):
        conn = get_db_connection(self.db_path)
        # Create Case A and Case B
        execute_write(conn, "INSERT INTO cases (id, name, created_at) VALUES ('CASE-A', 'Case Alpha', '2026-10-07T10:00:00')")
        execute_write(conn, "INSERT INTO cases (id, name, created_at) VALUES ('CASE-B', 'Case Beta', '2026-10-07T10:00:00')")

        # Insert Event into Case A
        execute_write(
            conn,
            """INSERT INTO events (id, case_id, timestamp, source, event_type, actor, object, severity, description, evidence_ref)
               VALUES ('EVT-A1', 'CASE-A', '2026-10-07T10:01:00', 'login', 'LOGIN_SUCCESS', 'alice', 'ws-1', 'low', 'desc', 'ref')"""
        )

        # Query events for Case B
        b_events = query_all(conn, "SELECT * FROM events WHERE case_id = 'CASE-B'")
        self.assertEqual(len(b_events), 0, "Case B must not see events from Case A")

        # Query events for Case A
        a_events = query_all(conn, "SELECT * FROM events WHERE case_id = 'CASE-A'")
        self.assertEqual(len(a_events), 1)
        self.assertEqual(a_events[0]["id"], "EVT-A1")

        conn.close()

if __name__ == "__main__":
    unittest.main()

