//! Stable host-facing protocol error categories.

use core::fmt;
use serde::{Deserialize, Serialize};

/// Stable categories callers may match without depending on human-readable text.
#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProtocolErrorKind {
    MalformedRequest,
    WrongNetwork,
    TransactionMismatch,
    PairingMismatch,
    Qr,
    Finalization,
    Derivation,
    Encoding,
    Decoding,
    Unsupported,
    Internal,
}

impl ProtocolErrorKind {
    const NAMES: [&'static str; 11] = [
        "malformedRequest",
        "wrongNetwork",
        "transactionMismatch",
        "pairingMismatch",
        "qr",
        "finalization",
        "derivation",
        "encoding",
        "decoding",
        "unsupported",
        "internal",
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        Self::NAMES[self as usize]
    }
}

/// Public host-side protocol error with a stable category and diagnostic detail.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtocolError {
    pub kind: ProtocolErrorKind,
    pub message: String,
}

impl ProtocolError {
    #[must_use]
    pub fn new(kind: ProtocolErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> ProtocolErrorKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn malformed(message: impl Into<String>) -> Self {
        Self::new(ProtocolErrorKind::MalformedRequest, message)
    }

    pub(crate) fn wrong_network(message: impl Into<String>) -> Self {
        Self::new(ProtocolErrorKind::WrongNetwork, message)
    }

    pub(crate) fn transaction_mismatch(message: impl Into<String>) -> Self {
        Self::new(ProtocolErrorKind::TransactionMismatch, message)
    }

    pub(crate) fn pairing_mismatch(message: impl Into<String>) -> Self {
        Self::new(ProtocolErrorKind::PairingMismatch, message)
    }

    pub(crate) fn qr(message: impl Into<String>) -> Self {
        Self::new(ProtocolErrorKind::Qr, message)
    }

    pub(crate) fn finalization(message: impl Into<String>) -> Self {
        Self::new(ProtocolErrorKind::Finalization, message)
    }

    pub(crate) fn derivation(message: impl Into<String>) -> Self {
        Self::new(ProtocolErrorKind::Derivation, message)
    }

    pub(crate) fn encoding(message: impl Into<String>) -> Self {
        Self::new(ProtocolErrorKind::Encoding, message)
    }

    pub(crate) fn decoding(message: impl Into<String>) -> Self {
        Self::new(ProtocolErrorKind::Decoding, message)
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for ProtocolError {}

pub type ProtocolResult<T> = Result<T, ProtocolError>;
