#!/usr/bin/env python3
"""closes the exact LCOV current-backup short-header branch."""
from pathlib import Path
import json
import unittest

ROOT = Path(__file__).resolve().parents[3]


class CriticalCryptoTruncationTests(unittest.TestCase):
    def test_exact_current_header_short_boundary_is_exercised(self):
        tests = (ROOT / "crates/offline-signer/src/crypto/unit_tests/container_framing_tests.rs").read_text()
        self.assertIn("BACKUP_CURRENT_HEADER_SIZE + TAG_SIZE - 1", tests)
        self.assertIn("truncated_current[..8].copy_from_slice(&BACKUP_CURRENT_MAGIC)", tests)
        self.assertIn("parse_backup_header(&truncated_current)", tests)
        self.assertIn("Err(FramingError::InvalidLength)", tests)

    def test_production_short_header_guard_and_hard_target_remain_intact(self):
        framing = (ROOT / "crates/offline-signer/src/crypto/container_framing.rs").read_text()
        self.assertIn("if input.len() < BACKUP_CURRENT_HEADER_SIZE + TAG_SIZE", framing)
        ratchets = (ROOT / "qa/checks/security/branch_ratchets.py").read_text()
        self.assertIn('config["target_branch_coverage_percent"]', ratchets)
        policy = json.loads((ROOT / "qa/checks/quality/crap/policy.json").read_text())
        crypto = policy["health"]["critical_domains"]["critical_crypto"]
        self.assertEqual(float(crypto["target_branch_coverage_percent"]), 100.0)



if __name__ == "__main__":
    unittest.main()
