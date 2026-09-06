//! Stable public error categories for wallet integrations.

use core::fmt;
use serde::{Deserialize, Serialize};

use kassigner_protocol::{ProtocolError, ProtocolErrorKind};

#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SdkErrorKind {
    MalformedRequest,
    WrongNetwork,
    TransactionMismatch,
    PairingMismatch,
    PairingReplay,
    Qr,
    Finalization,
    Derivation,
    RandomnessUnavailable,
    Encoding,
    Decoding,
    Unsupported,
    Internal,
}

impl SdkErrorKind {
    const NAMES: [&'static str; 13] = [
        "malformedRequest",
        "wrongNetwork",
        "transactionMismatch",
        "pairingMismatch",
        "pairingReplay",
        "qr",
        "finalization",
        "derivation",
        "randomnessUnavailable",
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

#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SdkError {
    pub kind: SdkErrorKind,
    pub message: String,
}

impl SdkError {
    #[must_use]
    pub fn new(kind: SdkErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    #[must_use]
    pub const fn kind(&self) -> SdkErrorKind {
        self.kind
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn pairing_replay(message: impl Into<String>) -> Self {
        Self::new(SdkErrorKind::PairingReplay, message)
    }

    pub(crate) fn randomness(message: impl Into<String>) -> Self {
        Self::new(SdkErrorKind::RandomnessUnavailable, message)
    }

    pub(crate) fn malformed(message: impl Into<String>) -> Self {
        Self::new(SdkErrorKind::MalformedRequest, message)
    }
}

const PROTOCOL_KIND_MAP: [SdkErrorKind; 11] = [
    SdkErrorKind::MalformedRequest,
    SdkErrorKind::WrongNetwork,
    SdkErrorKind::TransactionMismatch,
    SdkErrorKind::PairingMismatch,
    SdkErrorKind::Qr,
    SdkErrorKind::Finalization,
    SdkErrorKind::Derivation,
    SdkErrorKind::Encoding,
    SdkErrorKind::Decoding,
    SdkErrorKind::Unsupported,
    SdkErrorKind::Internal,
];

fn map_protocol_kind(kind: ProtocolErrorKind) -> SdkErrorKind {
    PROTOCOL_KIND_MAP[kind as usize]
}

impl From<ProtocolError> for SdkError {
    fn from(error: ProtocolError) -> Self {
        Self::new(map_protocol_kind(error.kind()), error.message().to_owned())
    }
}

impl fmt::Display for SdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.message)
    }
}

impl std::error::Error for SdkError {}

pub type SdkResult<T> = Result<T, SdkError>;
