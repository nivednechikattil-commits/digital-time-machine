"""
Unit tests for parsers/csv_parser.py and parsers/json_parser.py.
Tests safe ingestion, error line tracking, and format support.
"""

import unittest
from parsers.csv_parser import parse_csv_content
from parsers.json_parser import parse_json_content

class TestParsers(unittest.TestCase):

    def test_parse_csv_success(self):
        csv_data = """id,timestamp,source,event_type,actor,object,severity,description
EVT-100,2026-10-07T10:00:00,login,LOGIN_SUCCESS,alice,workstation-01,low,User logged in
EVT-101,2026-10-07T10:05:00,browser,BROWSER_NAVIGATE,alice,http://test.com,medium,Visited site
"""
        valid, errors = parse_csv_content(csv_data, filename="test.csv")
        self.assertEqual(len(valid), 2)
        self.assertEqual(len(errors), 0)
        self.assertEqual(valid[0]["id"], "EVT-100")
        self.assertEqual(valid[1]["source"], "browser")

    def test_parse_csv_with_malformed_row(self):
        csv_data = """id,timestamp,source,event_type,actor,object,severity,description
EVT-100,2026-10-07T10:00:00,login,LOGIN_SUCCESS,alice,workstation-01,low,User logged in
EVT-101,INVALID_DATE,browser,BROWSER_NAVIGATE,alice,http://test.com,medium,Visited site
"""
        valid, errors = parse_csv_content(csv_data, filename="test.csv")
        self.assertEqual(len(valid), 1)
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0]["line_number"], 3)
        self.assertIn("Unsupported timestamp format", errors[0]["error"])

    def test_parse_json_array(self):
        json_data = """[
            {"id": "EVT-200", "timestamp": "2026-10-07T11:00:00", "source": "file", "event_type": "FILE_CREATE", "actor": "bob", "object": "doc.txt"},
            {"id": "EVT-201", "timestamp": "2026-10-07T11:05:00", "source": "network", "event_type": "TCP_CONNECT", "actor": "bob", "object": "10.0.0.1"}
        ]"""
        valid, errors = parse_json_content(json_data, filename="test.json")
        self.assertEqual(len(valid), 2)
        self.assertEqual(len(errors), 0)

    def test_parse_json_lines(self):
        jsonl_data = """{"id": "EVT-300", "timestamp": "2026-10-07T11:00:00", "source": "file", "event_type": "FILE_CREATE", "actor": "bob", "object": "doc.txt"}
{"id": "EVT-301", "timestamp": "2026-10-07T11:05:00", "source": "network", "event_type": "TCP_CONNECT", "actor": "bob", "object": "10.0.0.1"}"""
        valid, errors = parse_json_content(jsonl_data, filename="test.jsonl")
        self.assertEqual(len(valid), 2)
        self.assertEqual(len(errors), 0)

    def test_parse_json_invalid_root(self):
        valid, errors = parse_json_content("12345", filename="test.json")
        self.assertEqual(len(valid), 0)
        self.assertEqual(len(errors), 1)

if __name__ == "__main__":
    unittest.main()

