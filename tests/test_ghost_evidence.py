"""
Unit tests for engine/ghost_evidence.py.
Tests detection of temporal coverage gaps, missing precursor artifacts, and unclosed device lifecycles.
"""

import unittest
from engine.ghost_evidence import detect_ghost_evidence

class TestGhostEvidence(unittest.TestCase):

    def test_detect_temporal_browser_gap(self):
        events = [
            {"id": "E1", "timestamp": "2026-10-07T10:00:00", "source": "browser", "event_type": "BROWSER_NAVIGATE", "actor": "alice", "object": "http://siteA.com"},
            {"id": "E2", "timestamp": "2026-10-07T10:45:00", "source": "browser", "event_type": "BROWSER_NAVIGATE", "actor": "alice", "object": "http://siteB.com"}
        ]
        anomalies = detect_ghost_evidence(events)
        gap = [a for a in anomalies if a["anomaly_type"] == "TEMPORAL_COVERAGE_GAP"]
        self.assertTrue(len(gap) >= 1)
        self.assertIn("Unrecorded Browser Navigation Window", gap[0]["title"])
        self.assertTrue(len(gap[0]["potential_benign_causes"]) > 0)

    def test_detect_unclosed_usb_device(self):
        events = [
            {"id": "E1", "timestamp": "2026-10-07T10:10:00", "source": "usb", "event_type": "DEVICE_CONNECT", "actor": "alice", "object": "Kingston_USB"}
        ]
        anomalies = detect_ghost_evidence(events)
        usb_anom = [a for a in anomalies if a["anomaly_type"] == "UNCLOSED_ARTIFACT_LIFECYCLE"]
        self.assertTrue(len(usb_anom) >= 1)
        self.assertIn("Kingston_USB", usb_anom[0]["title"])

if __name__ == "__main__":
    unittest.main()

