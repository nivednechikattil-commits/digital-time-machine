"""
Unit tests for engine/correlator.py.
Tests forensic correlation rules A through F and ensures limitations and supporting events are populated.
"""

import unittest
from engine.correlator import run_correlation_engine

class TestCorrelator(unittest.TestCase):

    def test_rule_a_website_download(self):
        events = [
            {"id": "E1", "timestamp": "2026-10-07T10:00:00", "source": "browser", "event_type": "BROWSER_NAVIGATE", "actor": "alice", "object": "http://training-domain.com/tool.exe", "severity": "high"},
            {"id": "E2", "timestamp": "2026-10-07T10:02:00", "source": "file", "event_type": "FILE_DOWNLOAD", "actor": "alice", "object": "tool.exe", "severity": "high"}
        ]
        findings = run_correlation_engine(events)
        rule_a = [f for f in findings if f["rule_id"] == "RULE_A"]
        self.assertTrue(len(rule_a) >= 1)
        self.assertIn("E1", rule_a[0]["supporting_event_ids"])
        self.assertIn("E2", rule_a[0]["supporting_event_ids"])
        self.assertIn("limitations", rule_a[0])

    def test_rule_b_file_access_then_copy(self):
        events = [
            {"id": "E1", "timestamp": "2026-10-07T10:00:00", "source": "file", "event_type": "FILE_ACCESS", "actor": "alice", "object": "db.csv", "severity": "medium"},
            {"id": "E2", "timestamp": "2026-10-07T10:05:00", "source": "file", "event_type": "FILE_COPY", "actor": "alice", "object": "db.csv", "severity": "high"}
        ]
        findings = run_correlation_engine(events)
        rule_b = [f for f in findings if f["rule_id"] == "RULE_B"]
        self.assertTrue(len(rule_b) >= 1)
        self.assertEqual(rule_b[0]["supporting_event_ids"], ["E1", "E2"])

    def test_rule_c_usb_near_file_copy(self):
        events = [
            {"id": "E1", "timestamp": "2026-10-07T10:10:00", "source": "usb", "event_type": "DEVICE_CONNECT", "actor": "alice", "object": "USB_DRIVE", "severity": "medium"},
            {"id": "E2", "timestamp": "2026-10-07T10:12:00", "source": "file", "event_type": "FILE_COPY", "actor": "alice", "object": "db.csv", "severity": "critical"}
        ]
        findings = run_correlation_engine(events)
        rule_c = [f for f in findings if f["rule_id"] == "RULE_C"]
        self.assertTrue(len(rule_c) >= 1)
        self.assertEqual(rule_c[0]["severity"], "critical")

    def test_rule_d_failed_logins_before_success(self):
        events = [
            {"id": "E1", "timestamp": "2026-10-07T10:00:00", "source": "login", "event_type": "LOGIN_FAILED", "actor": "alice", "object": "ws-1", "severity": "medium"},
            {"id": "E2", "timestamp": "2026-10-07T10:00:30", "source": "login", "event_type": "LOGIN_FAILED", "actor": "alice", "object": "ws-1", "severity": "medium"},
            {"id": "E3", "timestamp": "2026-10-07T10:01:00", "source": "login", "event_type": "LOGIN_SUCCESS", "actor": "alice", "object": "ws-1", "severity": "low"}
        ]
        findings = run_correlation_engine(events)
        rule_d = [f for f in findings if f["rule_id"] == "RULE_D"]
        self.assertTrue(len(rule_d) >= 1)
        self.assertIn("E1", rule_d[0]["supporting_event_ids"])
        self.assertIn("E3", rule_d[0]["supporting_event_ids"])

    def test_rule_e_download_access_network(self):
        events = [
            {"id": "E1", "timestamp": "2026-10-07T10:00:00", "source": "file", "event_type": "FILE_DOWNLOAD", "actor": "alice", "object": "tool.exe", "severity": "high"},
            {"id": "E2", "timestamp": "2026-10-07T10:05:00", "source": "file", "event_type": "FILE_ACCESS", "actor": "alice", "object": "data.bin", "severity": "high"},
            {"id": "E3", "timestamp": "2026-10-07T10:10:00", "source": "network", "event_type": "NETWORK_CONNECTION", "actor": "alice", "object": "1.2.3.4", "severity": "medium"}
        ]
        findings = run_correlation_engine(events)
        rule_e = [f for f in findings if f["rule_id"] == "RULE_E"]
        self.assertTrue(len(rule_e) >= 1)
        self.assertEqual(rule_e[0]["supporting_event_ids"], ["E1", "E2", "E3"])

if __name__ == "__main__":
    unittest.main()

