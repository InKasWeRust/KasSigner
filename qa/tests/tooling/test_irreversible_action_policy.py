#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import io
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
ACK_PATH = ROOT / "qa/checks/release/irreversible_action_ack.py"
POLICY_PATH = ROOT / "qa/checks/security/irreversible_action_policy.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TtyInput(io.StringIO):
    def isatty(self) -> bool:
        return True


class NonTtyInput(io.StringIO):
    def isatty(self) -> bool:
        return False


class IrreversibleActionPolicyTests(unittest.TestCase):
    def test_ack_requires_phrase_and_exact_device_on_interactive_terminal(self) -> None:
        ack = load(ACK_PATH, "irreversible_ack")
        output = io.StringIO()
        accepted = TtyInput(f"{ack.ACK_PHRASE}\n/dev/ttyACM0\n")
        self.assertTrue(
            ack.require_acknowledgement(
                "burn production eFuses", "/dev/ttyACM0", accepted, output
            )
        )
        self.assertIn("ACKNOWLEDGED", output.getvalue())

        wrong_device = TtyInput(f"{ack.ACK_PHRASE}\n/dev/ttyACM1\n")
        self.assertFalse(
            ack.require_acknowledgement(
                "burn production eFuses", "/dev/ttyACM0", wrong_device, io.StringIO()
            )
        )
        self.assertFalse(
            ack.require_acknowledgement(
                "burn production eFuses",
                "/dev/ttyACM0",
                NonTtyInput(f"{ack.ACK_PHRASE}\n/dev/ttyACM0\n"),
                io.StringIO(),
            )
        )

    def test_repository_policy_keeps_developer_and_user_consent_fail_closed(self) -> None:
        policy = load(POLICY_PATH, "irreversible_policy")
        errors, document = policy.audit()
        self.assertEqual(errors, [])
        self.assertTrue(document["healthy"])
        self.assertTrue(document["bootloader_pop_it_precedes_irreversible_call"])
        self.assertEqual(document["unauthorized_irreversible_source_calls"], [])
        self.assertIn(
            "docs/EFUSE_RUNBOOK.md", document["guarded_markdown_runbooks"]
        )
        self.assertTrue(all(document["user_consent"].values()))
        self.assertTrue(all(document["developer_acknowledgement"].values()))
        ack = load(ACK_PATH, "irreversible_ack_binding")
        self.assertEqual(ack.DEVICE_TOKEN, "{device}")

    def test_hardening_and_release_evidence_require_irreversible_policy(self) -> None:
        makefile = (ROOT / "Makefile").read_text()
        catalog = (ROOT / "qa/linux/runner/catalog.sh").read_text()
        self.assertIn("qa:\n\t$(MAKE_TASK) qa", makefile)
        self.assertIn("qa/checks/security/irreversible_action_policy.py", catalog)

        package = (ROOT / "qa/checks/security/package_artifacts.py").read_text()
        self.assertGreaterEqual(package.count('SECURITY_ROOT / "irreversible-action-policy.json"'), 2)

        release_doc = (ROOT / "qa/release/M5STACK_SECURITY_HIL.md").read_text()
        self.assertIn("I UNDERSTAND THIS IS IRREVERSIBLE", release_doc)
        self.assertIn("literal `{device}` token", release_doc)
        self.assertIn("**Pop It!** consent", release_doc)

        release_policy = (ROOT / "apps/signer-firmware/release-policy.env").read_text()
        values = dict(
            line.split("=", 1) for line in release_policy.splitlines()
            if line and not line.startswith("#") and "=" in line
        )
        self.assertGreaterEqual(int(values["KASSIGNER_UPDATE_SEQUENCE"]), 1)
        self.assertEqual(values["KASSIGNER_SECURITY_VERSION"], "1")

    def test_live_irreversible_command_requires_wrapper_reference(self) -> None:
        policy = load(POLICY_PATH, "irreversible_policy_scan")
        self.assertTrue(policy.IRREVERSIBLE_COMMAND.search("espefuse burn_efuse SECURE_VERSION 1"))
        self.assertTrue(
            policy.IRREVERSIBLE_COMMAND.search(
                "espefuse.py burn-key BLOCK_KEY0 key.bin HMAC_UP"
            )
        )
        self.assertFalse(policy.IRREVERSIBLE_COMMAND.search("espefuse summary"))

        with tempfile.TemporaryDirectory() as directory:
            raw = Path(directory) / "raw.sh"
            raw.write_text("espefuse --port /dev/ttyACM0 burn-efuse SECURE_BOOT_EN\n")
            self.assertFalse(policy.script_commands_are_guarded(raw))

            guarded = Path(directory) / "guarded.sh"
            guarded.write_text(
                "python3 qa/checks/release/irreversible_action_ack.py --device /dev/ttyACM0 -- "
                "espefuse --port {device} burn-efuse SECURE_BOOT_EN\n"
            )
            self.assertTrue(policy.script_commands_are_guarded(guarded))

    def test_copy_pasteable_runbook_commands_cannot_bypass_acknowledgement(self) -> None:
        policy = load(POLICY_PATH, "irreversible_policy_markdown")
        runbook = ROOT / "docs/EFUSE_RUNBOOK.md"
        self.assertEqual(policy.unguarded_markdown_blocks(runbook), [])

        with tempfile.TemporaryDirectory() as directory:
            unsafe = Path(directory) / "unsafe.md"
            unsafe.write_text(
                "```bash\n"
                "espefuse --port /dev/ttyACM0 burn-efuse SECURE_BOOT_EN\n"
                "```\n"
            )
            self.assertTrue(policy.unguarded_markdown_blocks(unsafe))


if __name__ == "__main__":
    unittest.main()
