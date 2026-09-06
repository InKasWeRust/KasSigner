from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]
SETTINGS = ROOT / "apps/signer-firmware/src/runtime/data/settings.rs"
DISPLAY = ROOT / "apps/signer-firmware/src/runtime/data/settings/persistent_display.rs"
AUDIO = ROOT / "apps/signer-firmware/src/runtime/data/settings/audio.rs"
WALLET = ROOT / "apps/signer-firmware/src/runtime/data/wallet.rs"


class FirmwareTypedStateOwnershipTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(errors="ignore")

    @staticmethod
    def struct_body(source: str, name: str) -> str:
        match = re.search(rf"struct\s+{name}\s*\{{(?P<body>.*?)\n\}}", source, re.S)
        if match is None:
            raise AssertionError(f"missing struct {name}")
        return match.group("body")

    def test_settings_state_no_longer_accumulates_boolean_fields(self):
        source = SETTINGS.read_text(errors="ignore")
        settings = self.struct_body(source, "SettingsState")
        display = self.struct_body(DISPLAY.read_text(errors="ignore"), "DisplayPreferences")
        audio = self.struct_body(AUDIO.read_text(errors="ignore"), "AudioPreferences")
        self.assertNotRegex(settings, r":\s*bool\b")
        self.assertLessEqual(len(re.findall(r":\s*bool\b", display)), 2)
        self.assertLessEqual(len(re.findall(r":\s*bool\b", audio)), 2)
        self.assertNotIn("#[allow(clippy::struct_excessive_bools)]", source)
        self.assertNotIn("#[expect(clippy::struct_excessive_bools)]", source)

    def test_seed_session_uses_typed_add_wallet_state_instead_of_parallel_bools(self):
        source = WALLET.read_text(errors="ignore")
        seed_session = self.struct_body(source, "SeedSession")
        self.assertLessEqual(len(re.findall(r":\s*bool\b", seed_session)), 3)
        self.assertIn("pub enum PendingAddWalletKind", source)
        self.assertIn("pub pending_add_wallet_kind: PendingAddWalletKind", seed_session)
        self.assertNotIn("pending_add_wallet: bool", seed_session)
        self.assertNotIn("pending_add_wallet_restore: bool", seed_session)
        self.assertNotIn("#[allow(clippy::struct_excessive_bools)]", source)
        self.assertNotIn("#[expect(clippy::struct_excessive_bools)]", source)

    def test_flag_mutations_flow_through_settings_state_boundaries(self):
        source = SETTINGS.read_text(errors="ignore")
        display = DISPLAY.read_text(errors="ignore")
        audio = AUDIO.read_text(errors="ignore")
        self.assertIn("pub(crate) const fn require_pin_after_dim(&self) -> bool", display)
        self.assertIn("pub(crate) const fn device_preferences_dirty(&self) -> bool", display)
        self.assertIn("pub(crate) const fn audio_muted(&self) -> bool", audio)
        self.assertIn("pub(crate) const fn startup_sound_enabled(&self) -> bool", audio)
        self.assertIn("pub(crate) fn toggle_startup_sound(&mut self)", audio)
        self.assertIn("pub(crate) fn apply_persisted_startup_sound(&mut self, enabled: bool)", audio)

        persistence = self.read("apps/signer-firmware/src/services/persistent_wallet/device/preferences.rs")
        dispatch = self.read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        settings_dispatch = self.read("apps/signer-firmware/src/runtime/event_loop/settings_dispatch.rs")
        self.assertIn("with_require_pin_after_dim(ad.settings.require_pin_after_dim())", persistence)
        self.assertIn("with_startup_sound(ad.settings.startup_sound_enabled())", persistence)
        self.assertIn("set_audio_muted($ad.settings.audio_muted())", dispatch)
        self.assertIn("if !ad.settings.device_preferences_dirty() { return; }", settings_dispatch)

        journal = self.read("apps/signer-firmware/src/services/persistent_wallet/journal.rs")
        self.assertIn("fn set_flag(value: &mut u8, mask: u8, enabled: bool)", journal)
        self.assertNotRegex(
            journal,
            r'#\[cfg\(feature = "m5stack"\)\]\s*fn set_flag\(value: &mut u8, mask: u8, enabled: bool\)',
        )

    def test_strict_struct_excessive_bools_lint_remains_enabled(self):
        lint = self.read("qa/checks/firmware/check_firmware_lints.py")
        self.assertIn('"-D", "clippy::struct_excessive_bools"', lint)


if __name__ == "__main__":
    unittest.main()
