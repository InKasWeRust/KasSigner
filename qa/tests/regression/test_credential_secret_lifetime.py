from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class CredentialSecretLifetimeTests(unittest.TestCase):
    def test_first_foreground_kdf_is_deferred_until_after_outer_liveness(self) -> None:
        driver = read("apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/mod.rs")
        begin = driver[driver.index("if self.task.is_none()") : driver.index("let step = {")]
        self.assertIn("self.task = Some(task);", begin)
        self.assertIn("return;", begin)
        loop = read("apps/signer-firmware/src/runtime/event_loop/mod.rs")
        tail_service = loop.rfind("operation_engine::service(")
        tail_ack = loop.rfind("runner::acknowledge_runtime")
        self.assertGreater(tail_ack, tail_service)
        guard = loop.index("operation_engine::owns_exclusive_frame(&operation_engine)")
        self.assertLess(guard, loop.index("event_loop::audio::service"))

    def test_runtime_hil_has_a_real_watchdog_boundary_between_task_arm_and_kdf(self) -> None:
        connected = read(
            "apps/signer-firmware/src/runtime/workflow_tests/connected/onboarding/credentials.rs"
        )
        service = connected[
            connected.index("fn service_credential_operation("):
            connected.index("fn verify_invalid_pin_retry(")
        ]
        self.assertIn("operation_engine::service(", service)
        self.assertIn("watchdog_feed();", service)
        self.assertLess(service.index("operation_engine::service("), service.index("watchdog_feed();"))
        self.assertNotIn("arm_poll", service)

    def test_app_credential_copy_is_destroyed_at_task_capture(self) -> None:
        secret = read("apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/task/secret.rs")
        begin = read("apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/task/begin.rs")
        capture = secret[secret.index("fn take_from_app("):secret.index("fn as_slice(")]
        self.assertIn("ad.wallet.seeds.pp_input.reset();", capture)
        self.assertLess(capture.index("target.copy_from_slice(source)"), capture.index("pp_input.reset()"))
        self.assertIn("SecretBuffer::take_from_app(ad)?", begin)

    def test_derived_key_callers_scrub_their_stack_copy(self) -> None:
        save = read("apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/task/save.rs")
        unlock = read("apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/task/unlock.rs")
        self.assertLess(save.index("finish_async_save("), save.index("zeroize_bytes(&mut key);"))
        self.assertLess(unlock.index("apply_async_unlock_key("), unlock.index("zeroize_bytes(&mut key);"))


if __name__ == "__main__":
    unittest.main()
