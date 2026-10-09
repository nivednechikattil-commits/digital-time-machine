"""
Unit tests for engine/state_reconstructor.py.
Tests historical point-in-time state reconstruction, session transitions, and future-event isolation.
"""

import unittest
from engine.state_reconstructor import reconstruct_system_state

class TestStateReconstructor(unittest.TestCase):

    def setUp(self):
        self.events = [
            {
                "id": "EVT-1",
                "timestamp": "2026-10-07T10:00:00",
                "source": "login",
                "event_type": "LOGIN_SUCCESS",
                "actor": "alice",
                "object": "workstation-01",
                "severity": "low",
                "details": "{}"
            },
            {
                "id": "EVT-2",
                "timestamp": "2026-10-07T10:05:00",
                "source": "browser",
                "event_type": "BROWSER_NAVIGATE",
                "actor": "alice",
                "object": "http://training-domain.com/tool.exe",
                "severity": "high",
                "details": "{}"
            },
            {
                "id": "EVT-3",
                "timestamp": "2026-10-07T10:10:00",
                "source": "usb",
                "event_type": "DEVICE_CONNECT",
                "actor": "alice",
                "object": "FlashDrive_32G",
                "severity": "medium",
                "details": '{"serial_number": "SN-1234", "mount_point": "E:\\\\"}'
            },
            {
                "id": "EVT-4",
                "timestamp": "2026-10-07T10:15:00",
                "source": "file",
                "event_type": "FILE_COPY",
                "actor": "alice",
                "object": "customers.csv",
                "severity": "critical",
                "details": '{"destination": "E:\\\\customers.csv"}'
            },
            {
                "id": "EVT-5",
                "timestamp": "2026-10-07T10:30:00",
                "source": "login",
                "event_type": "LOGOUT",
                "actor": "alice",
                "object": "workstation-01",
                "severity": "low",
                "details": "{}"
            }
        ]

    def test_reconstruct_at_midpoint(self):
        # Target timestamp at 10:12:00 (after USB connected, but before file copy and logout)
        state = reconstruct_system_state(self.events, target_timestamp="2026-10-07T10:12:00")
        
        self.assertEqual(state["events_applied_count"], 3)
        self.assertEqual(state["active_sessions"]["alice"]["status"], "ACTIVE")
        self.assertTrue(state["connected_devices"]["FlashDrive_32G"]["is_connected"])
        
        # File copy (EVT-4) occurred at 10:15:00, so customers.csv MUST NOT be in filesystem at 10:12:00!
        self.assertNotIn("customers.csv", state["file_system"])

    def test_reconstruct_after_logout(self):
        state = reconstruct_system_state(self.events, target_timestamp="2026-10-07T10:35:00")
        self.assertEqual(state["events_applied_count"], 5)
        self.assertEqual(state["active_sessions"]["alice"]["status"], "LOGGED_OUT")
        self.assertIn("customers.csv", state["file_system"])
        self.assertEqual(state["file_system"]["customers.csv"]["status"], "COPIED")

if __name__ == "__main__":
    unittest.main()

