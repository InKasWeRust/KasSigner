// KasSigner — BIP340 Schnorr signatures over secp256k1.
//
// This module is intentionally a thin, no_std wrapper around RustCrypto's
// audited `k256::schnorr` implementation. Firmware signing tools, transaction
// signing, and firmware verification all call this exact implementation so the
// challenge hash, nonce derivation, parsing rules, and verification semantics
// cannot drift between packages.

use k256::schnorr::{Signature as K256Signature, SigningKey, VerifyingKey};

/// Schnorr signature: 64 bytes (`R.x || s`) as defined by BIP340.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchnorrSignature {
    pub bytes: [u8; 64],
}

impl SchnorrSignature {
    /// R component (x-coordinate of the nonce point, first 32 bytes).
    pub fn r_bytes(&self) -> [u8; 32] {
        let mut r = [0u8; 32];
        r.copy_from_slice(&self.bytes[..32]);
        r
    }

    /// s component (scalar, last 32 bytes).
    pub fn s_bytes(&self) -> [u8; 32] {
        let mut s = [0u8; 32];
        s.copy_from_slice(&self.bytes[32..]);
        s
    }
}

/// Errors returned by BIP340 signing and verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchnorrError {
    /// The private key is zero, out of range, or otherwise invalid.
    InvalidPrivateKey,
    /// The signing operation rejected the supplied key/message/randomness.
    SigningFailed,
    /// The public key or signature is malformed, or verification failed.
    InvalidSignature,
}

impl core::fmt::Display for SchnorrError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPrivateKey => "invalid BIP340 private key",
            Self::SigningFailed => "BIP340 signing failed",
            Self::InvalidSignature => "invalid BIP340 public key or signature",
        })
    }
}

/// Sign an already-computed 32-byte message hash using BIP340.
///
/// The auxiliary-randomness input is fixed to zero to provide deterministic,
/// reproducible signatures. This is the standard BIP340 deterministic mode,
/// not RFC6979 and not a project-specific challenge construction.
pub fn schnorr_sign(
    private_key: &[u8; 32],
    message: &[u8; 32],
) -> Result<SchnorrSignature, SchnorrError> {
    schnorr_sign_with_aux_rand(private_key, message, &[0u8; 32])
}

/// Sign an already-computed 32-byte message hash using explicit BIP340
/// auxiliary randomness.
///
/// This entry point exists for standards vectors and callers that can supply a
/// reviewed 32-byte auxiliary random value. Host-side deterministic tooling may
/// use [`schnorr_sign`]; device transaction signing must supply checked entropy.
pub fn schnorr_sign_with_aux_rand(
    private_key: &[u8; 32],
    message: &[u8; 32],
    aux_rand: &[u8; 32],
) -> Result<SchnorrSignature, SchnorrError> {
    let signing_key =
        SigningKey::from_bytes(private_key).map_err(|_| SchnorrError::InvalidPrivateKey)?;
    let signature = signing_key
        .sign_raw(message, aux_rand)
        .map_err(|_| SchnorrError::SigningFailed)?;
    Ok(SchnorrSignature {
        bytes: signature.to_bytes(),
    })
}

#[inline(never)]
fn parse_verifying_key(pubkey_x: &[u8; 32]) -> Result<VerifyingKey, SchnorrError> {
    VerifyingKey::from_bytes(pubkey_x).map_err(|_| SchnorrError::InvalidSignature)
}

#[inline(never)]
fn parse_signature(signature: &SchnorrSignature) -> Result<K256Signature, SchnorrError> {
    K256Signature::try_from(signature.bytes.as_slice()).map_err(|_| SchnorrError::InvalidSignature)
}

#[inline(never)]
fn verify_parsed_signature(
    verifying_key: &VerifyingKey,
    message: &[u8; 32],
    signature: &K256Signature,
) -> Result<(), SchnorrError> {
    // Keep RustCrypto's audited curve-verification routine as an upstream call
    // instead of letting firmware LTO inline its working set into this stricter
    // first-party frame. The global compiled-frame gate still measures the k256
    // routine itself against the independent 16 KiB whole-image ceiling.
    type VerifyRaw = fn(&VerifyingKey, &[u8], &K256Signature) -> Result<(), k256::schnorr::Error>;
    let verify: VerifyRaw = core::hint::black_box(VerifyingKey::verify_raw);
    verify(verifying_key, message, signature).map_err(|_| SchnorrError::InvalidSignature)
}

/// Verify a BIP340 signature over an already-computed 32-byte message hash.
///
/// The stages stay out-of-line intentionally: the firmware build uses LTO, and
/// folding key parsing, signature parsing, and curve verification into one
/// first-party wrapper can exceed the compiled 8 KiB frame budget.
#[inline(never)]
pub fn schnorr_verify(
    pubkey_x: &[u8; 32],
    message: &[u8; 32],
    signature: &SchnorrSignature,
) -> Result<(), SchnorrError> {
    let verifying_key = parse_verifying_key(pubkey_x)?;
    let parsed = parse_signature(signature)?;
    verify_parsed_signature(&verifying_key, message, &parsed)
}

/// Expected public values for a published BIP340 signing known-answer vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bip340KnownAnswer {
    pub public_key_x: [u8; 32],
    pub signature: [u8; 64],
}

const BIP340_VECTOR0_PRIVATE_KEY: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
];
const BIP340_VECTOR0_MESSAGE: [u8; 32] = [0u8; 32];
const BIP340_VECTOR0_AUX_RAND: [u8; 32] = [0u8; 32];

/// Published BIP340 test vector 0 expected values.
///
/// The expectation is data rather than being hidden inside the KAT function so
/// tests can deliberately corrupt one field. This makes a whole-function
/// `return true` mutation observable instead of mathematically untestable.
pub const BIP340_VECTOR0_EXPECTED: Bip340KnownAnswer = Bip340KnownAnswer {
    public_key_x: [
        0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34, 0x4f, 0x85, 0xf8, 0x9d, 0x52,
        0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83, 0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0,
        0x36, 0xf9,
    ],
    signature: [
        0xe9, 0x07, 0x83, 0x1f, 0x80, 0x84, 0x8d, 0x10, 0x69, 0xa5, 0x37, 0x1b, 0x40, 0x24, 0x10,
        0x36, 0x4b, 0xdf, 0x1c, 0x5f, 0x83, 0x07, 0xb0, 0x08, 0x4c, 0x55, 0xf1, 0xce, 0x2d, 0xca,
        0x82, 0x15, 0x25, 0xf6, 0x6a, 0x4a, 0x85, 0xea, 0x8b, 0x71, 0xe4, 0x82, 0xa7, 0x4f, 0x38,
        0x2d, 0x2c, 0xe5, 0xeb, 0xee, 0xe8, 0xfd, 0xb2, 0x17, 0x2f, 0x47, 0x7d, 0xf4, 0x90, 0x0d,
        0x31, 0x05, 0x36, 0xc0,
    ],
};

/// Evaluate published BIP340 vector 0 against caller-supplied expected values.
///
/// Production passes [`BIP340_VECTOR0_EXPECTED`]. Tests corrupt the expected
/// public key and signature independently, which makes both comparisons and a
/// whole-function `true` replacement observable to mutation testing.
pub fn bip340_known_answer(expected: &Bip340KnownAnswer) -> bool {
    known_answer_matches(
        schnorr_sign_with_aux_rand(
            &BIP340_VECTOR0_PRIVATE_KEY,
            &BIP340_VECTOR0_MESSAGE,
            &BIP340_VECTOR0_AUX_RAND,
        ),
        expected,
    )
}

fn known_answer_matches(
    signature: Result<SchnorrSignature, SchnorrError>,
    expected: &Bip340KnownAnswer,
) -> bool {
    let Ok(signature) = signature else {
        return false;
    };
    signature.bytes == expected.signature
        && schnorr_verify(&expected.public_key_x, &BIP340_VECTOR0_MESSAGE, &signature).is_ok()
}

#[cfg(any(test, feature = "verbose-boot"))]
#[path = "unit_tests/schnorr_tests.rs"]
pub mod unit_tests;
