#!/usr/bin/env python3
"""
Test runner for Digital Time Machine.
Discovers and executes all unit and integration test suites using unittest.
"""

import sys
import unittest
from pathlib import Path

# Add project root to sys.path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

def run_all_tests():
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=str(BASE_DIR / "tests"), pattern="test_*.py")
    
    print("=" * 70)
    print(" DIGITAL TIME MACHINE — AUTOMATED TEST SUITE")
    print(" Running forensic parsing, normalization, state, and API tests...")
    print("=" * 70)

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print("=" * 70)
    print(f"Tests run: {result.testsRun} | Failures: {len(result.failures)} | Errors: {len(result.errors)}")
    print("=" * 70)

    if result.wasSuccessful():
        print("[+] ALL TESTS PASSED.")
        return 0
    else:
        print("[-] SOME TESTS FAILED.")
        return 1

if __name__ == "__main__":
    sys.exit(run_all_tests())

