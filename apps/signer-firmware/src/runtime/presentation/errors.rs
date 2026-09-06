//! Stable Stage-4 recoverable/fatal error catalog.
//!
//! Codes are short enough for the device display and stable enough to report
//! without exposing secret material. Ordinary failures use recoverable modals;
//! only explicitly classified security/integrity failures use fatal handling.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ErrorSpec {
    pub(crate) message: &'static str,
    pub(crate) code: &'static str,
}

#[cfg(all(
    feature = "m5stack",
    not(feature = "hardware-tests"),
    any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto")
))]
pub(crate) const CAMERA_UNAVAILABLE: ErrorSpec = ErrorSpec { message: "Camera unavailable", code: "CAM-01" };
#[cfg(all(
    not(feature = "hardware-tests"),
    any(
        not(feature = "workflow-test-auto"),
        all(feature = "m5stack", feature = "workflow-runtime-auto")
    )
))]
pub(crate) const CAMERA_CAPTURE: ErrorSpec = ErrorSpec { message: "Camera capture failed", code: "CAM-02" };
#[cfg(all(
    not(feature = "hardware-tests"),
    any(
        not(feature = "workflow-test-auto"),
        all(feature = "m5stack", feature = "workflow-runtime-auto")
    )
))]
pub(crate) const CAMERA_MEMORY: ErrorSpec = ErrorSpec { message: "Camera memory unavailable", code: "CAM-03" };
pub(crate) const SD_WRITE: ErrorSpec = ErrorSpec { message: "SD write failed", code: "SD-WRITE-01" };
pub(crate) const STORAGE_SYNC: ErrorSpec = ErrorSpec { message: "Wallet save failed", code: "STORE-SYNC-01" };
pub(crate) const POLICY_SAVE: ErrorSpec = ErrorSpec { message: "Security policy save failed", code: "POLICY-SAVE-01" };
pub(crate) const QR_FRAME: ErrorSpec = ErrorSpec { message: "QR frame failed", code: "QR-FRAME-01" };
pub(crate) const SIGN_ENTROPY: ErrorSpec = ErrorSpec { message: "Signing entropy unavailable", code: "SIGN-ENTROPY-01" };
pub(crate) const SIGN_INPUT: ErrorSpec = ErrorSpec { message: "Input signing failed", code: "SIGN-INPUT-01" };
pub(crate) const SIGN_REVIEW: ErrorSpec = ErrorSpec { message: "Review authorization failed", code: "SIGN-REVIEW-01" };
pub(crate) const SIGN_KEY: ErrorSpec = ErrorSpec { message: "Wallet key unavailable", code: "SIGN-KEY-01" };
pub(crate) const SIGN_POLICY: ErrorSpec = ErrorSpec { message: "Signing policy rejected", code: "SIGN-POLICY-01" };
pub(crate) const SIGN_FINALIZE: ErrorSpec = ErrorSpec { message: "Transaction finalization failed", code: "SIGN-FINAL-01" };
pub(crate) const TX_IMPORT: ErrorSpec = ErrorSpec { message: "Transaction import failed", code: "TX-IMPORT-01" };
pub(crate) const TX_OWNERSHIP: ErrorSpec = ErrorSpec { message: "KasSee wallet does not match active wallet", code: "TX-OWN-01" };
pub(crate) const ANTI_KLEPTO: ErrorSpec = ErrorSpec { message: "Anti-klepto request rejected", code: "AK-01" };
pub(crate) const COVENANT: ErrorSpec = ErrorSpec { message: "Covenant request rejected", code: "COV-01" };
pub(crate) const PRIVATE_SWAP: ErrorSpec = ErrorSpec { message: "Private Swap request rejected", code: "SWAP-01" };
#[cfg(any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto"))]
pub(crate) const NAVIGATION: ErrorSpec = ErrorSpec { message: "Navigation error", code: "UI-NAV-01" };

// Stage-5 cooperative-operation timeout diagnostics. These are application
// deadlines that fire while the event loop is still alive, before TIMG0.
pub(crate) const OP_CONNECT_TIMEOUT: ErrorSpec = ErrorSpec { message: "KasSee derivation timed out", code: "OP-TIMEOUT-01" };
pub(crate) const OP_MULTISIG_TIMEOUT: ErrorSpec = ErrorSpec { message: "Multisig derivation timed out", code: "OP-TIMEOUT-02" };
pub(crate) const OP_SIGN_TIMEOUT: ErrorSpec = ErrorSpec { message: "Transaction signing timed out", code: "OP-TIMEOUT-03" };
pub(crate) const OP_CREDENTIAL_TIMEOUT: ErrorSpec = ErrorSpec { message: "Credential operation timed out", code: "OP-TIMEOUT-05" };
#[cfg(all(feature = "m5stack", not(feature = "hardware-tests")))]
pub(crate) const ADDRESS_TIMEOUT: ErrorSpec = ErrorSpec { message: "Address derivation timed out", code: "OP-TIMEOUT-04" };
#[cfg(all(feature = "m5stack", not(feature = "hardware-tests")))]
pub(crate) const ADDRESS_DERIVE: ErrorSpec = ErrorSpec { message: "Address derivation failed", code: "ADDR-DERIVE-01" };
