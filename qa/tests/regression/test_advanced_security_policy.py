#!/usr/bin/env python3
"""Regression guards for irreversible advanced firmware security policies."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FIRMWARE = ROOT / "apps/signer-firmware/src"


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


class AdvancedSecurityPolicyTests(unittest.TestCase):
    def test_irreversible_persistence_has_no_disable_or_change_api(self) -> None:
        advanced = read("apps/signer-firmware/src/services/persistent_wallet/advanced.rs")
        self.assertIn("if self.security_policy.duress.enabled", advanced)
        self.assertIn("if self.security_policy.signing.not_before_unix != 0", advanced)
        self.assertIn("if self.security_policy.signing.weekly_enabled", advanced)
        self.assertGreaterEqual(advanced.count("PersistError::AdvancedAlreadyEnabled"), 3)

        production = "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in FIRMWARE.rglob("*.rs")
        )
        for forbidden in (
            "disable_duress",
            "disable_not_before",
            "disable_weekly",
            "change_duress",
            "change_not_before",
            "change_weekly",
        ):
            self.assertNotIn(forbidden, production)

    def test_duress_unlock_zeroizes_and_erases_internal_user_state(self) -> None:
        unlock = read("apps/signer-firmware/src/services/persistent_wallet/unlock/mod.rs") + read("apps/signer-firmware/src/services/persistent_wallet/unlock/asynchronous.rs")
        journal = read("apps/signer-firmware/src/services/persistent_wallet/journal.rs")
        self.assertIn("if self.duress_entered(kind, secret, liveness)?", unlock)
        self.assertIn("device_wipe::zeroize_volatile(ad)", unlock)
        self.assertIn("sd_backend::erase_files(i2c, delay).is_ok()", unlock)
        self.assertIn("journal::erase_all_user_data(&mut self.flash).is_ok()", unlock)
        self.assertIn("if sd_erased && internal_erased", unlock)
        self.assertIn("Err(PersistError::DeviceWipeFailed)", unlock)
        sd_backend = read("apps/signer-firmware/src/services/persistent_wallet/sd_backend.rs")
        self.assertIn("-> Result<(), PersistError>", sd_backend)
        self.assertIn('Ok(()) | Err("File not found")', sd_backend)
        self.assertIn('Err(_) => failed = true', sd_backend)
        self.assertIn('result.map_err(|_| PersistError::SdStorageWrite)', sd_backend)
        for sector in ("CONFIG_A", "CONFIG_B", "WALLET_A", "WALLET_B"):
            self.assertIn(f"flash::{sector}", journal)

    def test_policy_trailer_stripping_fails_closed(self) -> None:
        crypto = read("apps/signer-firmware/src/services/persistent_wallet/crypto.rs")
        record = read("apps/signer-firmware/src/services/persistent_wallet/crypto/record.rs")
        policy = read("apps/signer-firmware/src/services/persistent_wallet/security_policy.rs")
        self.assertIn("record.0[11] = 1", record)
        self.assertIn("policy_required: record.0[11] == 1", record)
        self.assertIn(
            "return if header.policy_required { DecodeResult::Corrupt } else { DecodeResult::Absent };",
            policy,
        )

    def test_time_policy_gates_normal_and_anti_klepto_signature_release(self) -> None:
        workflow = read("apps/signer-firmware/src/runtime/signing/workflow.rs")
        anti_klepto = read(
            "apps/signer-firmware/src/runtime/interactions/camera_loop/dispatch/anti_klepto.rs"
        )
        event_persistence = read("apps/signer-firmware/src/runtime/event_loop/persistence.rs")
        self.assertIn("signing_policy::authorize_transaction_time", workflow)
        self.assertIn("persistence.record_rtc_floor", workflow)
        self.assertIn("signing_policy::authorize_transaction_time", anti_klepto)
        self.assertGreaterEqual(anti_klepto.count("authorize_reveal_time(ad, i2c)"), 2)
        production_reveal = anti_klepto[anti_klepto.index("fn process_reveal("):anti_klepto.index("fn validate_reveal(")]
        before = production_reveal.find("authorize_reveal_time(ad, i2c)")
        finalization = production_reveal.find("finalize_reveal_signature_with_checkpoint(ad, &host_secret, liveness)")
        after = production_reveal.find("authorize_reveal_time(ad, i2c)", before + 1)
        self.assertTrue(0 <= before < finalization < after)
        self.assertIn("pending_rtc_floor_unix", anti_klepto)
        self.assertIn("rollback_added_signatures", event_persistence)
        self.assertIn("presentation::POLICY_SAVE", event_persistence)
        self.assertIn("presentation::show_error_spec", event_persistence)

    def test_rtc_floor_advancement_uses_one_snapshot_not_redundant_pair(self) -> None:
        advanced = read("apps/signer-firmware/src/services/persistent_wallet/advanced.rs")
        floor = advanced[advanced.index("pub fn record_rtc_floor"):advanced.index("fn persist_security_once")]
        once = advanced[advanced.index("fn persist_security_once"):advanced.index("fn persist_security_redundantly")]
        redundant = advanced[advanced.index("fn persist_security_redundantly"):]
        self.assertIn("persist_security_once(manager, i2c, delay)", floor)
        self.assertNotIn("persist_security_redundantly", floor)
        self.assertEqual(once.count("save_flash_snapshot(manager)"), 1)
        self.assertEqual(once.count("save_sd_snapshot(manager, i2c, delay)"), 1)
        self.assertGreaterEqual(redundant.count("save_flash_snapshot(manager)"), 2)

    def test_advanced_ui_uses_full_red_permanence_warning(self) -> None:
        screen = read("apps/signer-firmware/src/ui/screens/device/advanced_security.rs")
        redraw = read("apps/signer-firmware/src/ui/redraw/settings.rs")
        self.assertGreaterEqual(screen.count("self.display.clear(COLOR_DANGER)"), 2)
        self.assertIn('let undo = "CANNOT BE UNDONE";', screen)
        self.assertIn('let permanent = "FINAL CONFIRMATION";', screen)
        self.assertIn("Only full flash erase can remove it.", screen)
        self.assertIn("AdvancedDuressWarning", redraw)
        self.assertIn("AdvancedTimeLockWarning", redraw)
        self.assertIn("AdvancedWeeklyWarning", redraw)

    def test_rtc_power_loss_demotes_verification_and_routes_to_setup(self) -> None:
        clock = read("apps/signer-firmware/src/runtime/interactions/settings/advanced/clock.rs")
        time = read("apps/signer-firmware/src/runtime/interactions/settings/advanced/time.rs")
        overview = read("apps/signer-firmware/src/runtime/interactions/settings/advanced/overview.rs")
        self.assertIn("RtcReadError::LowVoltage", clock)
        self.assertIn("RtcVerification::Unverified", time)
        self.assertIn("crate::runtime::effects::route(ad, crate::runtime::navigation::route!(AdvancedRtcEntry))", time)
        self.assertIn("RTC low-voltage flag: verification cleared", time)
        recovery = time[time.index("fn handle_rtc_read_error"):time.index("fn finish_activation")]
        self.assertNotIn("show_rejection", recovery.split("return;", 1)[0])
        self.assertNotIn("read_now_unix", overview)
        self.assertNotIn("secure_time", overview)

    def test_time_policy_is_hardware_rtc_only(self) -> None:
        secure_time = read("apps/signer-firmware/src/services/secure_time.rs")
        rtc = read("apps/signer-firmware/src/hw/m5stack/rtc.rs")
        codec = read("crates/signer-firmware-core/src/time/bm8563.rs")
        self.assertIn('#[cfg(feature = "waveshare")]', secure_time)
        self.assertIn("Err(SecureTimeError::Unsupported)", secure_time)
        self.assertIn("const ADDRESS: u8 = 0x51", rtc)
        self.assertIn("rtc::decode_bm8563", rtc)
        self.assertIn("LOW_VOLTAGE_FLAG", codec)


if __name__ == "__main__":
    unittest.main()
