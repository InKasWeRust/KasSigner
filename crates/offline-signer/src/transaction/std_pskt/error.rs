//! Errors reported by PSKT envelope, syntax, parsing, and serialization.

/// Error type for PSKT parse and serialize operations.
///
/// Existing variants retain their original order because the enum is
/// `repr(u8)` and consumed across the offline-signer boundary. New variants
/// are appended so existing discriminants remain stable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PskError {
    // Envelope.
    /// Payload too short to contain a magic prefix.
    TooShort,
    /// Magic prefix is not `PSKB` or `PSKT`.
    BadMagic,
    /// Envelope declares PSKT shape but its body is empty or truncated.
    TruncatedEnvelope,

    // Hex decoding.
    /// Hex string has odd length.
    OddHexLength,
    /// Character outside lowercase `0-9a-f`.
    BadHexChar,
    /// Hex-decode scratch buffer is too small.
    ScratchBufferTooSmall,

    // JSON and schema shape.
    /// The next JSON token does not match the schema.
    UnexpectedToken,
    /// A required schema field is missing.
    MissingField,
    /// A schema field appears more than once.
    DuplicateField,
    /// The declared input set cannot be represented or allocated.
    TooManyInputs,
    /// The transaction exceeds the fixed output capacity.
    TooManyOutputs,
    /// An input exceeds the fixed partial-signature capacity.
    TooManyPartialSigs,
    /// The fixed scope-aware preservation budget is exhausted.
    TooManyUnknownRegions,

    // Semantic validation.
    /// `sighashType` is not SIGHASH_ALL.
    InvalidSighashType,
    /// An ECDSA signature was supplied where Kaspa requires Schnorr.
    InvalidSignatureType,
    /// A public key has the wrong encoded length or prefix.
    InvalidPubkeyLen,
    /// A script exceeds `MAX_SCRIPT_SIZE`.
    InvalidScriptLen,
    /// A script public key lacks its two-byte version prefix.
    ShortScriptPubkey,
    /// The PSKT or transaction format revision is unsupported.
    VersionNotSupported,
    /// Declared input or output counts disagree with the parsed arrays.
    CountMismatch,
    /// A PSKB bundle contains more than one PSKT element.
    BundleMultiElement,

    // Serialization.
    /// The output buffer is too small for the serialized payload.
    OutputBufferTooSmall,

    // Appended after the original variants to preserve existing discriminants.
    /// Decoded JSON cannot be represented by the u16 preservation offsets.
    JsonTooLarge,
    /// A skipped JSON value exceeded the bounded nesting stack.
    JsonNestingTooDeep,
    /// Covenant binding is malformed or references a nonexistent input.
    InvalidCovenantBinding,
    /// Aggregate input values exceed the u64 monetary domain.
    InputAmountOverflow,
    /// Aggregate output values exceed the u64 monetary domain.
    OutputAmountOverflow,
    /// Aggregate outputs exceed aggregate inputs.
    OutputsExceedInputs,
}
