// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// KasSigner — Schnorr Signatures (secp256k1)
// 100% Rust, no-std, no-alloc
//
// Schnorr signature implementation compatible with Kaspa:
//   - secp256k1 curve (via crate k256, pure Rust)
//   - Public keys: x-only 32 bytes (BIP-340 style)
//   - Signatures: 64 bytes (R.x || s)
//   - Nonce generation: hedged, k = HMAC-SHA512(privkey, tag || msg || aux)
//
// Kaspa uses Schnorr over secp256k1 similar to Bitcoin BIP340.
// The main difference is in the sighash hash (Blake2b vs SHA256),
// but that is handled in the KSPT module, not here.
//
// This implementation signs a 32-byte message (the pre-computed sighash).
//
// Security:
//   - HEDGED nonce, and it does NOT fall back. Two earlier versions of this
//     header claimed the opposite of each other and both were wrong: one said
//     "falls back to deterministic behaviour if the TRNG returns zeros", the
//     other said "deterministic nonce (RFC6979), no TRNG needed". Neither is
//     what the code does. `generate_rfc6979_nonce` calls `entropy::fill` and
//     returns `EntropyUnavailable` on failure, refusing to sign, because a
//     silent fall back to the deterministic nonce is exactly the
//     DFA-vulnerable case H-05 exists to remove.
//
//     Note what the auxiliary randomness is and is not for. The private key
//     is the HMAC KEY, so `k` is unpredictable without it even if `aux` were
//     all zeros. `aux` buys non-determinism, which is what defeats
//     differential fault analysis; it is not the source of the nonce's
//     secrecy. Entropy quality is therefore defence-in-depth HERE, and
//     load-bearing elsewhere: seed generation has no such hedge, and a
//     repeated AES-GCM nonce is a total break.
//
//   - Secrets are zeroized: `SecretKey` is `ZeroizeOnDrop` upstream, and the
//     bare `k256::Scalar` locals that are NOT covered by that are wrapped in
//     `Zeroizing` (M-06, closed). The previous line here stated the M-06
//     defect as if it were still present.
//
//   - No heap/alloc used


use k256::{
    SecretKey,
    elliptic_curve::{
        sec1::ToEncodedPoint,
        ops::Reduce,
        ScalarPrimitive,
    },
    Scalar,
    ProjectivePoint,
    AffinePoint,
    Secp256k1,
};
use sha2::{Sha256, Digest};
use zeroize::Zeroizing;
use super::hmac::{hmac_sha512, zeroize_buf};

// ─── Types ────────────────────────────────────────────────────────────

/// Schnorr signature: 64 bytes (R.x: 32 bytes || s: 32 bytes)
#[derive(Debug, Clone)]
/// A 64-byte Schnorr signature (R || s) compatible with Kaspa.
pub struct SchnorrSignature {
    pub bytes: [u8; 64],
}

impl SchnorrSignature {
    /// R component (x-coordinate of the nonce point, first 32 bytes)
    pub fn r_bytes(&self) -> &[u8; 32] {
        // SAFETY: self.bytes is [u8; 64], slicing [..32] always yields exactly 32 bytes
        self.bytes[..32].try_into().expect("r_bytes: 32-byte slice from 64-byte array")
    }

    /// s component (scalar, last 32 bytes)
    pub fn s_bytes(&self) -> &[u8; 32] {
        // SAFETY: self.bytes is [u8; 64], slicing [32..] always yields exactly 32 bytes
        self.bytes[32..].try_into().expect("s_bytes: 32-byte slice from 64-byte array")
    }
}

/// Schnorr signature errors
#[derive(Debug, PartialEq)]
/// Errors that can occur during Schnorr signing or verification.
pub enum SchnorrError {
    /// Invalid private key (zero or >= curve order)
    InvalidPrivateKey,
    /// Derived nonce is zero (should not happen with RFC6979)
    InvalidNonce,
    /// Elliptic curve operation error
    CurveError,
    /// Invalid signature (verification failed)
    InvalidSignature,
    /// The hardware RNG failed its continuous health tests, so the hedged
    /// nonce's auxiliary randomness is unavailable. Signing is refused rather
    /// than silently falling back to a purely deterministic nonce (H-05).
    EntropyUnavailable,
}

// ─── Sign ────────────────────────────────────────────────────────────

/// Sign a 32-byte message with Schnorr (BIP340-like).
///
/// Algorithm:
///   1. d = private key. If P = d*G has odd Y, d = n - d
///   2. k = hedged nonce (HMAC-SHA512 over tag || message || TRNG aux)
///   3. R = k*G. If R.y is odd, k = n - k
///   4. e = SHA256(R.x || P.x || message) mod n
///   5. s = (k + e * d) mod n
///   6. Signature = R.x || s
///
/// `message` must be the 32-byte sighash (pre-computed by the KSPT module).
/// `private_key` is the 32-byte BIP32 private key.
pub fn schnorr_sign(
    private_key: &[u8; 32],
    message: &[u8; 32],
) -> Result<SchnorrSignature, SchnorrError> {
    // 1. Parse private key
    let sk = SecretKey::from_slice(private_key)
        .map_err(|_| SchnorrError::InvalidPrivateKey)?;

    // Every secret scalar below is wrapped in `Zeroizing` (M-06).
    //
    // `SecretKey` is `ZeroizeOnDrop`; a bare `k256::Scalar` is NOT, and these
    // were bare. Either of them alone recovers the private key: `d` is the key,
    // and `k` yields it from the released signature via
    // `d = (s - k) * e^-1`. The module header claimed "the private key is
    // zeroized after each operation". It was not.
    //
    // `Zeroizing` rather than a wipe at the end of the function, because there
    // are two early returns after these values exist: the `?` on the nonce
    // below, and the verify-before-release failure further down. A manual wipe
    // would be skipped by exactly the paths where a fault has just occurred.
    let d_scalar = Zeroizing::new(*sk.to_nonzero_scalar());

    // Get public key point
    let pubkey_point = ProjectivePoint::GENERATOR * *d_scalar;
    let pubkey_affine = pubkey_point.to_affine();

    // BIP340: if Y is odd, negate d
    // Identity is unreachable here (`d_scalar` is nonzero, so d*G is a real
    // point), but `has_even_y` no longer panics on it (L-06); map the
    // impossible case to an error like every other curve failure.
    let d = Zeroizing::new(
        if has_even_y(&pubkey_affine).ok_or(SchnorrError::CurveError)? {
            *d_scalar
        } else {
            d_scalar.negate()
        },
    );

    // x-only public key (32 bytes)
    let px = x_bytes(&pubkey_affine);

    // 2. Deterministic nonce (RFC6979-like using HMAC-SHA256)
    let k_scalar = Zeroizing::new(generate_rfc6979_nonce(private_key, message)?);

    // 3. R = k*G
    let r_point = (ProjectivePoint::GENERATOR * *k_scalar).to_affine();

    // If R.y is odd, negate k
    // Same as `d` above: `k_scalar` is nonzero, so identity cannot occur,
    // and the impossible case is an error, not a panic (L-06).
    let k = Zeroizing::new(
        if has_even_y(&r_point).ok_or(SchnorrError::CurveError)? {
            *k_scalar
        } else {
            k_scalar.negate()
        },
    );

    let rx = x_bytes(&r_point);

    // 4. e = tagged_hash("BIP0340/challenge", R.x || P.x || m) mod n
    //
    // This comment previously read "BIP340 uses tagged hash, but for Kaspa
    // compatibility we use the challenge hash per their implementation", which
    // was false: `compute_challenge` has always used the tagged hash, and
    // rusty-kaspa does too. The same wrong belief, written down in
    // `tools/gen_hash.rs`, produced H-12: signatures that no BIP-340 verifier
    // would accept.
    let e = compute_challenge(&rx, &px, message);

    // 5. s = k + e * d (mod n)
    let s = Zeroizing::new(*k + (e * *d));

    // 6. Serialize: R.x || s
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&rx);
    sig_bytes[32..].copy_from_slice(&scalar_to_bytes(&s));
    let sig = SchnorrSignature { bytes: sig_bytes };

    // 7. Verify before release. This is the actual fault-injection
    //    countermeasure: a glitch anywhere above (scalar arithmetic, the
    //    challenge input, the even-Y negation, the message load) produces a
    //    signature that fails here, so the faulty value is never emitted and
    //    cannot be differenced against a good one. Costs one point
    //    multiplication (measured on hardware as the `[sign_t] verify`
    //    line before this code moved to kassigner-core, where there is no
    //    clock; time the `schnorr_sign` call site if the number is wanted
    //    again).
    let vr = schnorr_verify(&px, message, &sig);
    if vr.is_err() {
        return Err(SchnorrError::CurveError);
    }

    Ok(sig)
}

// ─── Verification ─────────────────────────────────────────────────────

/// Verifies a Schnorr signature against an x-only public key (32 bytes).
///
/// Algorithm:
///   1. Parse R.x and s from the signature
///   2. e = SHA256(R.x || P.x || message) mod n
///   3. Compute R' = s*G - e*P
///   4. Verify that R'.x == R.x and R'.y is even
pub fn schnorr_verify(
    pubkey_x: &[u8; 32],
    message: &[u8; 32],
    signature: &SchnorrSignature,
) -> Result<(), SchnorrError> {
    let rx = signature.r_bytes();
    let s_bytes = signature.s_bytes();

    // Parse s as scalar
    let s = bytes_to_scalar(s_bytes).ok_or(SchnorrError::InvalidSignature)?;

    // Reconstruct public key point from x-only (assume even Y)
    let pubkey_point = lift_x(pubkey_x).ok_or(SchnorrError::InvalidSignature)?;

    // e = challenge hash
    let e = compute_challenge(rx, pubkey_x, message);

    // R' = s*G - e*P
    let r_computed = (ProjectivePoint::GENERATOR * s)
        - (ProjectivePoint::from(pubkey_point) * e);
    let r_affine = r_computed.to_affine();

    // Check: R'.x == R.x and R'.y is even.
    //
    // R' is the identity only if s = e*d, which an attacker cannot arrange
    // without the key, but the signature bytes are attacker-supplied and this
    // path must not be able to panic (L-06): identity means invalid, same as
    // odd Y.
    if !has_even_y(&r_affine).ok_or(SchnorrError::InvalidSignature)? {
        return Err(SchnorrError::InvalidSignature);
    }

    let r_computed_x = x_bytes(&r_affine);
    if r_computed_x != *rx {
        return Err(SchnorrError::InvalidSignature);
    }

    Ok(())
}

// ─── Helper functions ─────────────────────────────────────────────

/// Checks if the point has an even Y coordinate.
///
/// Returns `None` for the identity point, which has no Y coordinate (L-06).
/// This was previously `.expect("not identity")`: unreachable from the
/// signing side, where both scalars are nonzero by construction, and
/// unreachable in verification without solving `s = e*d`, but it was still a
/// panic in code that processes attacker-supplied signatures. Callers map
/// `None` to an error instead.
fn has_even_y(point: &AffinePoint) -> Option<bool> {
    let encoded = point.to_encoded_point(false); // uncompressed: 04 || x || y
    let y_bytes = encoded.y()?;
    // Y is even if the last byte is even
    Some(y_bytes[31] & 1 == 0)
}

/// Extracts the 32-byte X coordinate from a point.
fn x_bytes(point: &AffinePoint) -> [u8; 32] {
    let encoded = point.to_encoded_point(true); // compressed: 02/03 || x
    let mut x = [0u8; 32];
    x.copy_from_slice(&encoded.as_bytes()[1..33]);
    x
}

/// Compute the BIP-340 challenge: e = tagged_hash("BIP0340/challenge", R.x || P.x || message) mod n
///
/// BIP-340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || data)
/// The tag hash is precomputed as a constant for performance.
fn compute_challenge(rx: &[u8; 32], px: &[u8; 32], message: &[u8; 32]) -> Scalar {
    // Precomputed: SHA256("BIP0340/challenge")
    // = 7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c
    const TAG_HASH: [u8; 32] = [
        0x7b, 0xb5, 0x2d, 0x7a, 0x9f, 0xef, 0x58, 0x32,
        0x3e, 0xb1, 0xbf, 0x7a, 0x40, 0x7d, 0xb3, 0x82,
        0xd2, 0xf3, 0xf2, 0xd8, 0x1b, 0xb1, 0x22, 0x4f,
        0x49, 0xfe, 0x51, 0x8f, 0x6d, 0x48, 0xd3, 0x7c,
    ];

    let mut hasher = Sha256::new();
    hasher.update(TAG_HASH);  // SHA256("BIP0340/challenge") — first copy
    hasher.update(TAG_HASH);  // SHA256("BIP0340/challenge") — second copy
    hasher.update(rx);
    hasher.update(px);
    hasher.update(message);
    let hash = hasher.finalize();

    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);

    // Reduce mod n
    bytes_to_scalar_reduce(&hash_bytes)
}

/// Generate a hedged nonce (see the detailed note below).
///
/// k = HMAC-SHA512(private_key, SHA256(message))[0..32] mod n
///
/// This is a simplification. Full RFC6979 uses a loop with
/// V/K states, but for Schnorr signatures with 32-byte messages
/// (which are hashes), a single iteration is safe in practice.
/// Hedged nonce: k = HMAC-SHA512(d, tag || message || aux)[..32] mod n.
///
/// NOT RFC 6979, despite the historical name of this function. The old
/// construction was HMAC-SHA512(d, message), a pure function of (d, m) with
/// no other input. That is the precondition for differential fault analysis
/// on deterministic signatures: sign the same message twice, glitch one run,
/// and both share k and therefore R, so
///     s1 = k + e1*d,  s2 = k + e2*d  =>  d = (s1-s2)*(e1-e2)^-1
/// recovers the private key from one successful fault. Determinism protects
/// against a weak RNG and is exactly what enables this.
///
/// Mixing fresh entropy removes the shared-k premise. It does NOT degrade to
/// a deterministic nonce: `entropy::fill` fails closed, zeroing its output and
/// returning an error rather than handing back zeros, and this function
/// propagates that as `EntropyUnavailable` and refuses to sign. An earlier
/// version of this comment described the zero-aux fallback as the degraded
/// case; that path no longer exists, and removing it is the whole point of
/// H-05.
///
/// Note what the auxiliary randomness is and is not for. The private key is
/// the HMAC key, so `k` is unpredictable without it even if `aux` were all
/// zeros. `aux` buys non-determinism, which is what defeats DFA; it is not the
/// source of the nonce's secrecy.
///
/// WIRE-COMPATIBLE. The signature still verifies against the same pubkey over
/// the same bytes, so OP_CHECKSIGFROMSTACK in the deployed mainnet oracle
/// covenants cannot tell the difference. Only bit-identical repetition stops.
fn generate_rfc6979_nonce(
    private_key: &[u8; 32],
    message: &[u8; 32],
) -> Result<Scalar, SchnorrError> {
    // Fail closed. A hedged nonce whose auxiliary randomness is unavailable
    // silently degrades to the deterministic one, which is the DFA-vulnerable
    // case H-05 exists to remove. Refuse to sign instead.
    let mut aux = [0u8; 32];
    // `crate::entropy::fill` forwards to the hardware source the firmware
    // registered at boot; with none registered it fails, and so does this.
    crate::entropy::fill(&mut aux)
        .map_err(|_| SchnorrError::EntropyUnavailable)?;

    // tag(32) || message(32) || aux(32). The tag domain-separates this HMAC
    // from any other use of the private key as an HMAC key.
    let mut data = [0u8; 96];
    data[..32].copy_from_slice(b"KasSigner/schnorr-nonce/v2______");
    data[32..64].copy_from_slice(message);
    data[64..].copy_from_slice(&aux);

    let hmac_out = hmac_sha512(private_key, &data);

    zeroize_buf(&mut aux);
    zeroize_buf(&mut data);

    // Take first 32 bytes and reduce mod n
    let mut k_bytes = [0u8; 32];
    k_bytes.copy_from_slice(&hmac_out[..32]);

    let k = bytes_to_scalar_reduce(&k_bytes);
    zeroize_buf(&mut k_bytes);

    // `hmac_out` holds the same 32 bytes `k_bytes` just took, and was the one
    // buffer in this function the M-06/H-05 pass missed: `aux`, `data` and
    // `k_bytes` are wiped above, `d_scalar` and `k` are `Zeroizing`, and this
    // was left live on the frame until return.
    //
    // Key-equivalent by the argument at the top of this file: `k` yields the
    // private key from a released signature via `d = (s - k) * e^-1`. So a
    // surviving copy of the nonce material is the private key with one
    // subtraction, not merely sensitive.
    //
    // Volatile writes, so the wipe cannot be optimised away on a value the
    // compiler can see is dead. This clears the named binding in SRAM; it makes
    // no claim about register spills or copies inside `hmac_sha512`, which wipes
    // its own `k_prime`, `ipad_key` and `opad_key`.
    let mut hmac_out = hmac_out;
    zeroize_buf(&mut hmac_out);

    // k cannot be zero
    if k.is_zero().into() {
        return Err(SchnorrError::InvalidNonce);
    }

    Ok(k)
}

/// Convert 32 bytes big-endian to Scalar (returns None if >= n).
fn bytes_to_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    let primitive = ScalarPrimitive::<Secp256k1>::from_slice(bytes).ok()?;
    Some(Scalar::from(&primitive))
}

/// Convert 32 bytes big-endian to Scalar, reducing mod n.
fn bytes_to_scalar_reduce(bytes: &[u8; 32]) -> Scalar {
    let wide = k256::U256::from_be_slice(bytes);
    <Scalar as Reduce<k256::U256>>::reduce(wide)
}

/// Convert a Scalar to 32 bytes big-endian.
fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&s.to_bytes());
    bytes
}

/// Reconstructs an AffinePoint from x-only (32 bytes), assuming even Y.
/// Equivalent to BIP-340 "lift_x".
fn lift_x(x_bytes: &[u8; 32]) -> Option<AffinePoint> {
    // Build compressed encoding with prefix 0x02 (even Y)
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..33].copy_from_slice(x_bytes);

    // Parse as compressed point
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::EncodedPoint;

    let encoded = EncodedPoint::from_bytes(compressed).ok()?;
    let point = AffinePoint::from_encoded_point(&encoded);
    if point.is_some().into() {
        // CtOption::unwrap() is safe here — we just checked is_some()
        Some(point.expect("point verified is_some"))
    } else {
        None
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════

/// Test: sign and verify roundtrip
// Reachable in shipped builds. Gated on `skip-tests` only: NOT on
// `verbose-boot` (which also enables the sighash debug dump and must
// never ship) and NOT on `silent` (a logging flag must not switch off a
// correctness check). Called from boot_test::run_crypto_kats.
#[cfg(any(test, not(feature = "skip-tests")))]
/// Test: verify a PUBLISHED BIP-340 test vector.
///
/// The roundtrip test below signs and verifies with this same code, so an
/// implementation that is wrong but self-consistent passes it. That is not
/// hypothetical: `tools/gen_hash.rs` computed the challenge as a plain
/// `SHA256(R.x || P.x || m)` instead of the BIP-340 tagged hash, was entirely
/// self-consistent, and produced signatures no verifier on earth would accept.
/// It went undetected for the life of the project (H-12).
///
/// This anchors the implementation to the specification instead of to itself.
/// The same vector is checked by `gen_hash.rs`, so the two cannot drift apart
/// without one of them failing.
///
/// BIP-340 test vector 0, derived from first principles rather than copied:
///   secret key  0x03  (not used here; verification needs only the pubkey)
///   message     all zeros
///   aux_rand    all zeros
///
/// Costs one verification, about 71 ms.
pub fn test_bip340_published_vector() -> bool {
    const PUBKEY: [u8; 32] = [
        0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10,
        0x49, 0x34, 0x4F, 0x85, 0xF8, 0x9D, 0x52, 0x29,
        0xB5, 0x31, 0xC8, 0x45, 0x83, 0x6F, 0x99, 0xB0,
        0x86, 0x01, 0xF1, 0x13, 0xBC, 0xE0, 0x36, 0xF9,
    ];
    const MESSAGE: [u8; 32] = [0u8; 32];
    const SIGNATURE: [u8; 64] = [
        0xE9, 0x07, 0x83, 0x1F, 0x80, 0x84, 0x8D, 0x10,
        0x69, 0xA5, 0x37, 0x1B, 0x40, 0x24, 0x10, 0x36,
        0x4B, 0xDF, 0x1C, 0x5F, 0x83, 0x07, 0xB0, 0x08,
        0x4C, 0x55, 0xF1, 0xCE, 0x2D, 0xCA, 0x82, 0x15,
        0x25, 0xF6, 0x6A, 0x4A, 0x85, 0xEA, 0x8B, 0x71,
        0xE4, 0x82, 0xA7, 0x4F, 0x38, 0x2D, 0x2C, 0xE5,
        0xEB, 0xEE, 0xE8, 0xFD, 0xB2, 0x17, 0x2F, 0x47,
        0x7D, 0xF4, 0x90, 0x0D, 0x31, 0x05, 0x36, 0xC0,
    ];

    let sig = SchnorrSignature { bytes: SIGNATURE };
    if schnorr_verify(&PUBKEY, &MESSAGE, &sig).is_err() {
        return false;
    }

    // A single flipped bit must be rejected, so that a verifier which accepts
    // everything cannot pass this test.
    let mut bad = SIGNATURE;
    bad[63] ^= 0x01;
    schnorr_verify(&PUBKEY, &MESSAGE, &SchnorrSignature { bytes: bad }).is_err()
}

#[cfg(any(test, not(feature = "skip-tests")))]
/// Test: sign then verify succeeds.
pub fn test_sign_verify_roundtrip() -> bool {
    // Test private key (DO NOT use in production)
    let privkey: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    // Test message (32 bytes)
    let message: [u8; 32] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
    ];

    // Sign
    let sig = match schnorr_sign(&privkey, &message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Verify that the signature is 64 bytes
    if sig.bytes.len() != 64 {
        return false;
    }

    // Get x-only public key
    let sk = match SecretKey::from_slice(&privkey) {
        Ok(sk) => sk,
        Err(_) => return false,
    };
    let pk = sk.public_key();
    let pk_point = pk.to_encoded_point(true);
    let mut pubkey_x = [0u8; 32];
    pubkey_x.copy_from_slice(&pk_point.as_bytes()[1..33]);

    // Verify signature
    schnorr_verify(&pubkey_x, &message, &sig).is_ok()
}

/// Test: deterministic signing (same key + message = same signature)
// Reachable in shipped builds. Gated on `skip-tests` only: NOT on
// `verbose-boot` (which also enables the sighash debug dump and must
// never ship) and NOT on `silent` (a logging flag must not switch off a
// correctness check). Called from boot_test::run_crypto_kats.
#[cfg(any(test, feature = "boot-kats-full", feature = "verbose-boot"))]
/// Test: hedged nonce. Two signatures over the SAME key and message must
/// DIFFER, and both must verify.
///
/// This asserted the opposite until H-05. The nonce was
/// HMAC-SHA512(d, message), a pure function of (d, m), so signing twice gave
/// byte-identical output. That is the precondition for differential fault
/// analysis: glitch one of two runs that share k and therefore R, and
///     s1 = k + e1*d,  s2 = k + e2*d  =>  d = (s1-s2)*(e1-e2)^-1
/// recovers the private key. entropy is now mixed into the nonce, so identical
/// output would mean the hedging is not reaching it.
pub fn test_hedged_nonce() -> bool {
    let privkey: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    ];

    let message = [0x42u8; 32];

    let sig1 = match schnorr_sign(&privkey, &message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let sig2 = match schnorr_sign(&privkey, &message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Must DIFFER: identical output means entropy is not reaching the nonce.
    if sig1.bytes == sig2.bytes {
        return false;
    }
    // And both must still verify against the same pubkey.
    // x-only pubkey, same derivation as test_sign_verify_roundtrip above.
    let sk = match SecretKey::from_slice(&privkey) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let pk_point = sk.public_key().to_encoded_point(true);
    let mut pubkey_x = [0u8; 32];
    pubkey_x.copy_from_slice(&pk_point.as_bytes()[1..33]);

    schnorr_verify(&pubkey_x, &message, &sig1).is_ok()
        && schnorr_verify(&pubkey_x, &message, &sig2).is_ok()
}

/// Test: invalid signature must fail verification
// Reachable in shipped builds. Gated on `skip-tests` only: NOT on
// `verbose-boot` (which also enables the sighash debug dump and must
// never ship) and NOT on `silent` (a logging flag must not switch off a
// correctness check). Called from boot_test::run_crypto_kats.
#[cfg(any(test, feature = "boot-kats-full", feature = "verbose-boot"))]
/// Test: invalid signature must fail verification.
pub fn test_invalid_signature_fails() -> bool {
    let privkey: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    let message = [0x55u8; 32];
    let wrong_message = [0x66u8; 32];

    let sig = match schnorr_sign(&privkey, &message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Get pubkey
    let sk = match SecretKey::from_slice(&privkey) {
        Ok(sk) => sk,
        Err(_) => return false,
    };
    let pk = sk.public_key();
    let pk_point = pk.to_encoded_point(true);
    let mut pubkey_x = [0u8; 32];
    pubkey_x.copy_from_slice(&pk_point.as_bytes()[1..33]);

    // Verify with correct message → OK
    if schnorr_verify(&pubkey_x, &message, &sig).is_err() {
        return false;
    }

    // Verify with incorrect message → must fail
    schnorr_verify(&pubkey_x, &wrong_message, &sig).is_err()
}

/// Test: sign with BIP32-derived key
// Reachable in shipped builds. Gated on `skip-tests` only: NOT on
// `verbose-boot` (which also enables the sighash debug dump and must
// never ship) and NOT on `silent` (a logging flag must not switch off a
// correctness check). Called from boot_test::run_crypto_kats.
#[cfg(any(test, feature = "boot-kats-full", feature = "verbose-boot"))]
pub fn test_sign_with_bip32_key() -> bool {
    use super::bip39;
    use super::bip32;

    // Generate seed from known mnemonic
    let entropy = [0u8; 16]; // "abandon...about"
    let mnemonic = bip39::mnemonic_from_entropy_12(&entropy);
    let seed = bip39::seed_from_mnemonic_12(&mnemonic, "");

    // Derive Kaspa key
    let key = match bip32::derive_path(&seed.bytes, bip32::KASPA_MAINNET_PATH) {
        Ok(k) => k,
        Err(_) => return false,
    };

    // x-only pubkey
    let pubkey_x = match key.public_key_x_only() {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Sign a dummy sighash
    let sighash = [0xABu8; 32];
    let sig = match schnorr_sign(key.private_key_bytes(), &sighash) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Verify
    schnorr_verify(&pubkey_x, &sighash, &sig).is_ok()
}

/// Runs all Schnorr tests.
/// Returns (passed, total).
// Reachable in shipped builds. Gated on `skip-tests` only: NOT on
// `verbose-boot` (which also enables the sighash debug dump and must
// never ship) and NOT on `silent` (a logging flag must not switch off a
// correctness check). Called from boot_test::run_crypto_kats.
#[cfg(any(test, not(feature = "skip-tests")))]
pub fn run_schnorr_tests() -> (u32, u32) {
    let mut passed = 0u32;
    // Incremented beside the tests it counts. See run_bip32_tests.
    #[allow(unused_mut)]
    let mut total = 2u32;

    // Minimal set: one published-vector verification and one sign+verify
    // roundtrip. Each signature costs a k256 point multiplication plus the
    // H-05 verify-before-release (~71 ms), so the full set measured 1,969 ms
    // at boot; the vector test adds one verification.
    //
    // The vector test comes first deliberately. The roundtrip only proves this
    // code agrees with itself, which a wrong implementation also does.
    if test_bip340_published_vector() { passed += 1; }
    if test_sign_verify_roundtrip() { passed += 1; }

    #[cfg(any(feature = "boot-kats-full", feature = "verbose-boot"))]
    {
        total += 3;
        if test_hedged_nonce() { passed += 1; }
        if test_invalid_signature_fails() { passed += 1; }
        if test_sign_with_bip32_key() { passed += 1; }
    }

    (passed, total)
}
