#!/usr/bin/env python3
"""Regression tests for transactional wallet-activation enforcement."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/checks"))

from architecture.firmware.guards.wallet_session import (  # noqa: E402
    discards_wallet_activation_result,
)


class WalletActivationPolicyTests(unittest.TestCase):
    def test_rejects_discarded_activation_result(self) -> None:
        source = """
let _ = crate::services::wallet_session::activate_slot(
    ad,
    slot,
    CachePolicy::Invalidate,
);
"""
        self.assertTrue(discards_wallet_activation_result(source))

    def test_accepts_explicit_activation_handling(self) -> None:
        source = """
match crate::services::wallet_session::activate_slot(
    ad,
    slot,
    CachePolicy::Invalidate,
) {
    Ok(()) => continue_flow(),
    Err(error) => show_error(error.message()),
}
"""
        self.assertFalse(discards_wallet_activation_result(source))

    def test_ignores_discard_pattern_in_comments(self) -> None:
        source = """
// let _ = wallet_session::activate_slot(ad, slot, CachePolicy::Invalidate);
let result = wallet_session::activate_slot(ad, slot, CachePolicy::Invalidate);
"""
        self.assertFalse(discards_wallet_activation_result(source))


if __name__ == "__main__":
    unittest.main()
