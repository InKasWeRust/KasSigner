from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[3]
FW = ROOT / "apps" / "signer-firmware"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


class UnlockCredentialPrivacyTests(unittest.TestCase):
    def test_unlock_does_not_apply_creation_policy(self):
        asynchronous = read("apps/signer-firmware/src/services/persistent_wallet/unlock/asynchronous.rs")
        workflow = read("apps/signer-firmware/src/services/persistent_wallet/unlock/mod.rs")

        begin = asynchronous[asynchronous.index("pub(crate) fn begin_async_unlock"):asynchronous.index("pub(crate) fn next_async_unlock_kdf")]
        self.assertNotIn("credential_policy::validate", begin)
        self.assertIn("Unlock guesses are authentication inputs", begin)
        self.assertIn("super::unlock_secret_for_kdf(secret)", asynchronous)
        self.assertIn('if secret.is_empty() { b"\\0" } else { secret }', workflow)

        unlock_saved = workflow[workflow.index("pub fn unlock_saved"):workflow.index("fn unlock_from_sd")]
        self.assertNotIn("credential_policy::validate", unlock_saved)

    def test_unlock_policy_rejections_use_generic_invalid_credential_retry(self):
        result = read("apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/result.rs")
        state = read("apps/signer-firmware/src/runtime/data/storage/persistence.rs")

        self.assertIn("if is_credential_rejection(error)", result)
        self.assertIn("PersistError::PasswordTooShort", result)
        self.assertIn("PersistError::PasswordNeedsDigit", result)
        self.assertIn("commit_authentication_retry(ad, kind, operation, retry_ms)", result)
        self.assertIn('Self::WrongPassword => "Invalid password"', state)
        self.assertIn('Self::WrongPin => "Invalid PIN"', state)

    def test_creation_still_owns_detailed_password_policy_errors(self):
        interaction = read("apps/signer-firmware/src/runtime/interactions/persistence/credential.rs")
        save = read("apps/signer-firmware/src/services/persistent_wallet/save/mod.rs")

        setup = interaction[interaction.index("fn handle_setup_entry"):interaction.index("fn setup_back")]
        self.assertIn("validate(kind, secret)", setup)
        self.assertIn('"CRED-VALID-01"', setup)
        self.assertIn("credential_policy::validate(kind, secret)?", save)


if __name__ == "__main__":
    unittest.main()
