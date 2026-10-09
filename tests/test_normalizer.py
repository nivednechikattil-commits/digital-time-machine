"""
Unit tests for engine/normalizer.py.
Tests timestamp parsing, source/severity remapping, and schema validation.
"""

import unittest
from engine.normalizer import (
    normalize_timestamp,
    normalize_source,
    normalize_severity,
    validate_and_normalize_event
)

class TestNormalizer(unittest.TestCase):

    def test_normalize_timestamp_iso(self):
        self.assertEqual(normalize_timestamp("2026-10-07T10:01:00"), "2026-10-07T10:01:00")
        self.assertEqual(normalize_timestamp("2026-10-07 10:01:00"), "2026-10-07T10:01:00")

    def test_normalize_timestamp_epoch(self):
        # 1791367260 is 2026-10-07T10:01:00Z
        norm = normalize_timestamp(1791367260)
        self.assertEqual(norm, "2026-10-07T10:01:00")

    def test_normalize_timestamp_invalid(self):
        with self.assertRaises(ValueError):
            normalize_timestamp("not-a-timestamp")
        with self.assertRaises(ValueError):
            normalize_timestamp("")
        with self.assertRaises(ValueError):
            normalize_timestamp(None)

    def test_normalize_source(self):
        self.assertEqual(normalize_source("auth"), "login")
        self.assertEqual(normalize_source("web"), "browser")
        self.assertEqual(normalize_source("disk"), "file")
        self.assertEqual(normalize_source("net"), "network")
        self.assertEqual(normalize_source("device"), "usb")
        self.assertEqual(normalize_source("unknown_src"), "unknown_src")

    def test_normalize_severity(self):
        self.assertEqual(normalize_severity("info"), "low")
        self.assertEqual(normalize_severity("warning"), "medium")
        self.assertEqual(normalize_severity("alert"), "high")
        self.assertEqual(normalize_severity("critical"), "critical")
        self.assertEqual(normalize_severity("UNKNOWN"), "low")

    def test_validate_and_normalize_event_valid(self):
        raw = {
            "id": "EVT-999",
            "timestamp": "2026-10-07T12:00:00",
            "source": "web",
            "event_type": "browser_navigate",
            "actor": "alice",
            "object": "https://example.com",
            "severity": "warn"
        }
        res = validate_and_normalize_event(raw)
        self.assertEqual(res["id"], "EVT-999")
        self.assertEqual(res["timestamp"], "2026-10-07T12:00:00")
        self.assertEqual(res["source"], "browser")
        self.assertEqual(res["event_type"], "BROWSER_NAVIGATE")
        self.assertEqual(res["severity"], "medium")
        self.assertEqual(res["confidence"], "observed")
        self.assertEqual(res["is_inferred"], 0)

    def test_validate_and_normalize_event_missing_required(self):
        raw = {
            "timestamp": "2026-10-07T12:00:00",
            "source": "login"
            # Missing actor, object, event_type
        }
        with self.assertRaises(ValueError):
            validate_and_normalize_event(raw)

if __name__ == "__main__":
    unittest.main()

