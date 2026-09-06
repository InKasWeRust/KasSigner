#!/usr/bin/env python3
"""Security regression contract for the production BIP340 known-answer test."""

from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
SCHNORR = ROOT / "crates/offline-signer/src/crypto/schnorr.rs"
BOOT = ROOT / "apps/signer-firmware/src/runtime/unit_tests/boot.rs"

BIP340_VECTOR_0_SIGNATURE = bytes.fromhex(
    "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
    "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
)


def expected_signature_bytes() -> bytes:
    source = SCHNORR.read_text()
    match = re.search(
        r"pub const BIP340_VECTOR0_EXPECTED: Bip340KnownAnswer = Bip340KnownAnswer \{.*?signature: \[(.*?)\],\n\};",
        source,
        re.DOTALL,
    )
    if match is None:
        raise AssertionError("production BIP340 vector-0 expectation is missing")
    values = re.findall(r"0x([0-9a-fA-F]{2})", match.group(1))
    return bytes(int(value, 16) for value in values)


class Bip340KnownAnswerPolicyTests(unittest.TestCase):
    def test_production_known_answer_matches_published_vector_zero(self) -> None:
        self.assertEqual(expected_signature_bytes(), BIP340_VECTOR_0_SIGNATURE)

    def test_known_answer_is_data_driven_and_checks_signature_and_verification(self) -> None:
        source = SCHNORR.read_text()
        self.assertIn("pub fn bip340_known_answer(expected: &Bip340KnownAnswer) -> bool", source)
        self.assertIn("signature.bytes == expected.signature", source)
        self.assertIn("schnorr_verify(&expected.public_key_x", source)
        self.assertIn("&&", source[source.index("pub fn bip340_known_answer"):])

    def test_boot_uses_the_published_expectation(self) -> None:
        source = BOOT.read_text()
        self.assertIn("bip340_known_answer(", source)
        self.assertIn("BIP340_VECTOR0_EXPECTED", source)


if __name__ == "__main__":
    unittest.main()
