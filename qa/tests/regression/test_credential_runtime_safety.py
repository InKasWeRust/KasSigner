from __future__ import annotations

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


class CredentialRuntimeSafetyTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(errors="strict")


    def test_credential_taps_are_owned_and_bottom_row_accepts_edge_slop(self) -> None:
        credential = self.read("apps/signer-firmware/src/runtime/interactions/persistence/credential.rs")
        screen = self.read("apps/signer-firmware/src/ui/screens/device/persistence.rs")
        self.assertIn("SecretAction::None => Some(false)", credential)
        self.assertIn("196..=232", screen)
        self.assertIn("credential domain", screen)

    def test_boot_diagnostics_cannot_wrap_or_absorb_runtime_panic_attribution(self) -> None:
        boot = self.read("apps/signer-firmware/src/runtime/unit_tests/boot.rs")
        self.assertIn("#[inline(never)]", boot)
        self.assertIn("camera_ok = camera_ok.saturating_add(1);", boot)
        self.assertIn("camera_total = camera_total.saturating_add(1);", boot)
        self.assertNotIn("camera_ok += 1", boot)
        self.assertNotIn("camera_total += 1", boot)

    def test_normal_build_warning_sources_are_not_live_in_normal_profile(self) -> None:
        task = "\n".join(self.read(path) for path in (
            "apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/task.rs",
            "apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/task/save.rs",
            "apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/task/unlock.rs",
        ))
        result = self.read("apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/result.rs")
        save = self.read("apps/signer-firmware/src/services/persistent_wallet/save/mod.rs")
        unlock = self.read("apps/signer-firmware/src/services/persistent_wallet/unlock/mod.rs")
        transport = self.read("apps/signer-firmware/src/runtime/interactions/sd/exports/kspt_export/crypto.rs")
        backup = self.read("apps/signer-firmware/src/services/backup/container.rs")
        self.assertIn("pub(in crate::runtime::event_loop::operation_engine::credential) struct SaveTask", task)
        self.assertIn("pub(in crate::runtime::event_loop::operation_engine::credential) struct UnlockTask", task)
        self.assertNotIn("kind: CredentialKind,\n    secret: SecretBuffer,\n    session:", task)
        self.assertNotIn("const fn credential_operation", result)
        self.assertIn('#[cfg(feature = "workflow-test-auto")]\n    pub fn save_with_credential', save)
        self.assertIn('#[cfg(feature = "workflow-test-auto")]\nimpl PersistentWallet', unlock)
        shared_unlock = unlock.split('#[cfg(feature = "workflow-test-auto")]\nenum UnlockAttempt', 1)[0]
        self.assertIn("fn trigger_duress(", shared_unlock)
        self.assertIn('#[cfg(test)]\npub(super) const LEGACY_MAGIC', transport)
        self.assertIn('#[cfg(test)]\nconst LEGACY_MAGIC', backup)


if __name__ == "__main__":
    unittest.main()
