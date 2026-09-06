"""stage-5 bounded operation liveness and pre-watchdog recovery contracts."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps/signer-firmware/src"


class BoundedOperationLivenessTests(unittest.TestCase):
    def source(self, relative: str) -> str:
        return (FW / relative).read_text(encoding="utf-8")


    def test_cooperative_operations_have_pre_watchdog_stall_deadline(self) -> None:
        kind = self.source("runtime/data/presentation/kind.rs")
        operation = self.source("runtime/data/presentation/operation.rs")
        self.assertIn("20_000", kind)
        self.assertIn("75_000", kind)
        self.assertIn("180_000", kind)
        self.assertIn("Self::ConnectKasSee | Self::DeriveMultisigKpub | Self::SignTransaction", kind)
        self.assertIn("last_progress_at_ms", operation)
        self.assertIn("kind.stall_budget_ms()", operation)
        self.assertIn("kind.total_budget_ms()", operation)

    def test_timeout_cancels_work_before_showing_recoverable_error(self) -> None:
        engine = self.source("runtime/event_loop/operation_engine/mod.rs")
        self.assertIn("timed_out_operation(ad)", engine)
        self.assertIn("timeout_operation(engine, ad, kind)", engine)
        self.assertIn("cancel_stepped(ad, kind)", engine)
        self.assertIn("cancel_active_signing_operation(ad)", engine)
        self.assertIn("fail_recoverable_spec(ad, error)", engine)
        self.assertLess(engine.index("cancel_stepped(ad, kind)"), engine.index("fail_recoverable_spec(ad, error)"))

    def test_receive_change_has_own_bounded_liveness_contract(self) -> None:
        address = self.source("runtime/event_loop/runner/deferred/address_cache.rs")
        for token in (
            "ADDRESS_TOTAL_BUDGET_MS: u64 = 75_000",
            "ADDRESS_STALL_BUDGET_MS: u64 = 20_000",
            "timeout_if_stalled(ad)",
            "kpub_worker::cancel(generation)",
            "presentation::ADDRESS_TIMEOUT",
        ):
            self.assertIn(token, address)
        self.assertNotIn("software_reset", address)

    def test_signing_reports_forward_progress_per_completed_input(self) -> None:
        signing = self.source("runtime/signing/workflow.rs")
        workflow = self.source("runtime/signing/workflow_test.rs")
        self.assertIn("let completed = input_idx.saturating_add(1);", signing)
        self.assertIn("presentation::set_progress(ad, progress.min(100) as u8);", signing)
        self.assertIn("let completed = input_idx.saturating_add(1);", workflow)
        self.assertIn("presentation::set_progress(ad, progress.min(100) as u8);", workflow)
        self.assertIn("rollback_session(ad);", signing)
        self.assertIn("cancel_signing_operation", signing)

    def test_timeout_diagnostics_are_nonsecret_and_stable(self) -> None:
        errors = self.source("runtime/presentation/errors.rs")
        for code in ("OP-TIMEOUT-01", "OP-TIMEOUT-02", "OP-TIMEOUT-03", "OP-TIMEOUT-04"):
            self.assertIn(code, errors)
        for secret_word in ("seed phrase", "private key", "credential value"):
            self.assertNotIn(secret_word, errors.lower())

    def test_hardware_watchdog_remains_last_resort_and_recovery_is_visible(self) -> None:
        core = self.source("runtime/core_s3.rs")
        self.assertIn("const DEFAULT_WATCHDOG_MS: u32 = 30_000", core)
        self.assertIn("const CREDENTIAL_WATCHDOG_MS: u32 = 90_000", core)
        self.assertIn("Duration::from_millis(u64::from(timeout_ms))", core)
        self.assertIn('code: "SYS-WDT-01"', core)
        self.assertIn('detail: "Previous session stopped responding"', core)
        self.assertIn("draw_system_recovery_screen", core)
        self.assertNotIn("seed", core.split("SYS-WDT-01", 1)[1].split("}),", 1)[0].lower())

    def test_foreground_exclusive_credential_kdf_has_bounded_async_contract(self) -> None:
        kind = self.source("runtime/data/presentation/kind.rs")
        engine = self.source("runtime/event_loop/operation_engine/mod.rs")
        task = "\n".join(self.source(path) for path in (
            "runtime/event_loop/operation_engine/credential/task.rs",
            "runtime/event_loop/operation_engine/credential/task/save.rs",
            "runtime/event_loop/operation_engine/credential/task/unlock.rs",
        ))
        self.assertIn("OperationExecution::ForegroundExclusive", kind)
        self.assertIn("=> 85_000", kind)
        self.assertIn("OperationExecution::ForegroundExclusive", engine)
        self.assertIn("derive_async_save_key(", task)
        self.assertIn("request.derive(self.secret.as_slice(), liveness)", task)


if __name__ == "__main__":
    unittest.main()
