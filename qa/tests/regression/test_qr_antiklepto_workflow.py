#!/usr/bin/env python3
"""connected QR protocol + anti-klepto E2E tranche contracts."""
from __future__ import annotations

import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps/signer-firmware"
SCENARIOS = ROOT / "qa/config/workflow/production_e2e_scenarios.json"
MANIFEST = ROOT / "qa/config/workflow/production_e2e_manifest.json"


class QrProtocolAntiKleptoE2ETrancheTests(unittest.TestCase):
    def test_qr_runner_is_partitioned_and_connected(self) -> None:
        connected = FW / "src/runtime/workflow_tests/connected"
        root = (connected / "mod.rs").read_text()
        qr = connected / "qr_protocol"
        self.assertEqual({p.name for p in qr.glob("*.rs")}, {"mod.rs", "matrix.rs", "multiframe.rs"})
        self.assertIn("mod qr_protocol;", root)
        self.assertIn("(\"QR-PROTOCOL\", qr_protocol::exercise)", root)
        source = "\n".join(p.read_text() for p in sorted(qr.glob("*.rs")))
        for marker in (
            "QR CLASSIFIER 16/16 + MALFORMED/OVERSIZED PASS",
            "QR MULTIFRAME OUT-OF-ORDER/DUPLICATE/MIXED/MISSING/COMPLETE PASS",
            "QR CAMERA CAPTURE/DECODE HIL DEFERRED TO PERIPHERAL TRANCHE",
            "QR PROTOCOL MATRIX TRANCHE PASS",
        ):
            self.assertIn(marker, source)

    def test_multiframe_uses_real_session_bound_firmware_owner(self) -> None:
        source = (FW / "src/runtime/workflow_tests/connected/qr_protocol/multiframe.rs").read_text()
        camera = (FW / "src/runtime/interactions/camera_loop.rs").read_text()
        workflow = (FW / "src/runtime/interactions/camera_loop/workflow.rs").read_text()
        production = (FW / "src/runtime/interactions/camera_loop/multiframe.rs").read_text()
        self.assertIn("workflow_process_multiframe", source)
        self.assertIn('#[cfg(feature = "workflow-test-auto")]\nmod workflow;', camera)
        self.assertIn("super::multiframe::process_multiframe", workflow)
        self.assertIn("authorize_frame_session", production)
        self.assertIn("conflicting duplicate QR frame rejected", production)
        self.assertIn("verify_session", production)

    def test_anti_klepto_uses_normative_request_commitment_reveal_signed_flow(self) -> None:
        anti = (FW / "src/runtime/workflow_tests/connected/signing/anti_klepto.rs").read_text()
        workflow_test = (FW / "src/runtime/signing/workflow_test.rs").read_text()
        dispatch = (FW / "src/runtime/interactions/camera_loop/dispatch/anti_klepto.rs").read_text()
        for token in ("encode_request", "parse_commitment", "encode_reveal", "parse_signed"):
            self.assertIn(token, anti)
        self.assertIn("prepare_anti_klepto_commitment", workflow_test)
        self.assertIn("validate_reveal", dispatch)
        self.assertIn("finalize_reveal_signature", dispatch)
        self.assertIn("build_final_response", dispatch)
        self.assertIn("present_final_response(ad, None, proof_count)", dispatch)
        self.assertNotIn("authorize_reveal_time(ad", dispatch.split("workflow_process_reveal", 1)[1].split("fn process_request", 1)[0])
        for marker in (
            "ANTI-KLEPTO TRANSACTION-BINDING REJECT PASS",
            "ANTI-KLEPTO COMMITMENT 2/2 PASS",
            "ANTI-KLEPTO SESSION-MISMATCH/ROLLBACK PASS",
            "ANTI-KLEPTO HOST-SECRET REJECT PASS",
            "ANTI-KLEPTO REVEAL/SIGNED 2/2 PASS",
            "ANTI-KLEPTO REPLAY REJECT PASS",
            "ANTI-KLEPTO RTC/PERSISTENT FLOOR DEFERRED TO SECURITY HIL",
            "ANTI-KLEPTO TRANCHE PASS",
        ):
            self.assertIn(marker, anti)



if __name__ == "__main__":
    unittest.main()
