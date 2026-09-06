/// Errors during KSPT parsing, signing, or serialization.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PsktError {
    /// Buffer too short.
    BufferTooShort,
    /// Invalid magic bytes.
    InvalidMagic,
    /// Unsupported format generation.
    UnsupportedVersion,
    /// Too many inputs.
    TooManyInputs,
    /// Too many outputs.
    TooManyOutputs,
    /// Script is too long.
    ScriptTooLong,
    /// Payload is too long.
    PayloadTooLong,
    /// Invalid SigHash type.
    InvalidSigHashType,
    /// Output buffer is too small.
    OutputBufferTooSmall,
    /// No inputs are present or no owned input could be signed.
    NoInputs,
    /// No outputs are present.
    NoOutputs,
    /// Header contains unsupported flag bits.
    InvalidFlags,
    /// Valid envelope was followed by unconsumed data.
    TrailingData,
    /// Public transaction fields are internally inconsistent.
    InvalidModel,
    /// An input declares more signatures than the fixed-capacity model supports.
    TooManySignatures,
    /// Signature slots are missing, duplicated, or otherwise inconsistent.
    InvalidSignatureState,
    /// A stealth or covenant trailer is malformed or duplicated.
    InvalidTrailer,
    /// An input or output index is outside the declared transaction bounds.
    InvalidInputIndex,
    /// BIP32 key derivation failed.
    DerivationFailed,
    /// Schnorr signing failed.
    SigningFailed,
    /// Aggregate input values exceed the u64 monetary domain.
    InputAmountOverflow,
    /// Aggregate output values exceed the u64 monetary domain.
    OutputAmountOverflow,
    /// Aggregate outputs exceed aggregate inputs.
    OutputsExceedInputs,
}
