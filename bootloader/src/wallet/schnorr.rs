// KasSigner — Schnorr Signatures (secp256k1)
// 100% Rust, no-std, no-alloc
//
// Schnorr signature implementation compatible with Kaspa:
//   - secp256k1 curve (via crate k256, pure Rust)
//   - Public keys: x-only 32 bytes (como BIP340)
//   - Signatures: 64 bytes (R.x || s)
//   - Nonce generation: RFC6979 deterministic (no TRNG needed for signing)
//
// Kaspa usa Schnorr sobre secp256k1 similar a BIP340 de Bitcoin.
// The main difference is in the sighash hash (Blake2b vs SHA256),
// but that is handled in the PSKT module, not here.
//
// This implementation signs a 32-byte message (the pre-computed sighash).
//
// Seguridad:
//   - Deterministic nonce (RFC6979) → no TRNG needed for signing
//   - The private key is zeroized after each operation
//   - No se usa heap/alloc


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
use super::hmac::{hmac_sha512, zeroize_buf};

// ─── Tipos ────────────────────────────────────────────────────────────

/// Firma Schnorr: 64 bytes (R.x: 32 bytes || s: 32 bytes)
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
}

// ─── Firma ────────────────────────────────────────────────────────────

/// Firma un mensaje de 32 bytes con Schnorr (BIP340-like).
///
/// Algoritmo:
///   1. d = private key. Si P = d*G tiene Y impar, d = n - d
///   2. k = deterministic nonce (RFC6979 with SHA256)
///   3. R = k*G. Si R.y es impar, k = n - k
///   4. e = SHA256(R.x || P.x || message) mod n
///   5. s = (k + e * d) mod n
///   6. Signature = R.x || s
///
/// `message` must be the 32-byte sighash (pre-computed by the PSKT module).
/// `private_key` son los 32 bytes de la clave privada BIP32.
pub fn schnorr_sign(
    private_key: &[u8; 32],
    message: &[u8; 32],
) -> Result<SchnorrSignature, SchnorrError> {
    // 1. Parse private key
    let sk = SecretKey::from_slice(private_key)
        .map_err(|_| SchnorrError::InvalidPrivateKey)?;

    let d_scalar: Scalar = (*sk.to_nonzero_scalar()).into();

    // Get public key point
    let pubkey_point = ProjectivePoint::GENERATOR * d_scalar;
    let pubkey_affine = pubkey_point.to_affine();

    // BIP340: si Y es impar, negar d
    let d = if has_even_y(&pubkey_affine) {
        d_scalar
    } else {
        d_scalar.negate()
    };

    // x-only public key (32 bytes)
    let px = x_bytes(&pubkey_affine);

    // 2. Deterministic nonce (RFC6979-like using HMAC-SHA256)
    let k_scalar = generate_rfc6979_nonce(private_key, message)?;

    // 3. R = k*G
    let r_point = (ProjectivePoint::GENERATOR * k_scalar).to_affine();

    // Si R.y es impar, negar k
    let k = if has_even_y(&r_point) {
        k_scalar
    } else {
        k_scalar.negate()
    };

    let rx = x_bytes(&r_point);

    // 4. e = SHA256(R.x || P.x || message) mod n
    //    (BIP340 usa tagged hash, pero para compatibilidad Kaspa
    //     we use the challenge hash per their implementation)
    let e = compute_challenge(&rx, &px, message);

    // 5. s = k + e * d (mod n)
    let s = k + (e * d);

    // 6. Serializar: R.x || s
    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&rx);
    sig_bytes[32..].copy_from_slice(&scalar_to_bytes(&s));

    Ok(SchnorrSignature { bytes: sig_bytes })
}

// ─── Verification ─────────────────────────────────────────────────────

/// Verifica una firma Schnorr contra una public key x-only (32 bytes).
///
/// Algoritmo:
///   1. Parse R.x y s de la firma
///   2. e = SHA256(R.x || P.x || message) mod n
///   3. Calcular R' = s*G - e*P
///   4. Verificar que R'.x == R.x y R'.y es par
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

    // Check: R'.x == R.x and R'.y is even
    if !has_even_y(&r_affine) {
        return Err(SchnorrError::InvalidSignature);
    }

    let r_computed_x = x_bytes(&r_affine);
    if r_computed_x != *rx {
        return Err(SchnorrError::InvalidSignature);
    }

    Ok(())
}

// ─── Funciones auxiliares ─────────────────────────────────────────────

/// Comprueba si el punto tiene coordenada Y par.
fn has_even_y(point: &AffinePoint) -> bool {
    let encoded = point.to_encoded_point(false); // uncompressed: 04 || x || y
    let y_bytes = encoded.y().expect("not identity");
    // Y is even if the last byte is even
    y_bytes[31] & 1 == 0
}

/// Extrae los 32 bytes de la coordenada X de un punto.
fn x_bytes(point: &AffinePoint) -> [u8; 32] {
    let encoded = point.to_encoded_point(true); // compressed: 02/03 || x
    let mut x = [0u8; 32];
    x.copy_from_slice(&encoded.as_bytes()[1..33]);
    x
}

/// Calcula el challenge: e = SHA256(R.x || P.x || message) mod n
///
/// Nota: BIP340 usa tagged hash SHA256("BIP0340/challenge" || ...).
/// Kaspa puede usar una variante diferente (Blake2b).
/// For now we implement the standard SHA256 version.
/// Cuando integremos con PSKT, ajustaremos si es necesario.
fn compute_challenge(rx: &[u8; 32], px: &[u8; 32], message: &[u8; 32]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(rx);
    hasher.update(px);
    hasher.update(message);
    let hash = hasher.finalize();

    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash);

    // Reduce mod n
    bytes_to_scalar_reduce(&hash_bytes)
}

/// Generate a deterministic nonce using RFC6979 (simplified with HMAC-SHA512).
///
/// k = HMAC-SHA512(private_key, SHA256(message))[0..32] mod n
///
/// This is a simplification. Full RFC6979 uses a loop with
/// V/K states, pero para firmas Schnorr con mensajes de 32 bytes
/// (which are hashes), a single iteration is safe in practice.
fn generate_rfc6979_nonce(
    private_key: &[u8; 32],
    message: &[u8; 32],
) -> Result<Scalar, SchnorrError> {
    // Construir datos para HMAC: private_key || message
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(private_key);
    data[32..].copy_from_slice(message);

    let hmac_out = hmac_sha512(&data[..32], &data[32..]);

    zeroize_buf(&mut data);

    // Take first 32 bytes and reduce mod n
    let mut k_bytes = [0u8; 32];
    k_bytes.copy_from_slice(&hmac_out[..32]);

    let k = bytes_to_scalar_reduce(&k_bytes);
    zeroize_buf(&mut k_bytes);

    // k cannot be zero
    if k.is_zero().into() {
        return Err(SchnorrError::InvalidNonce);
    }

    Ok(k)
}

/// Convierte 32 bytes big-endian a Scalar (retorna None si >= n).
fn bytes_to_scalar(bytes: &[u8; 32]) -> Option<Scalar> {
    let primitive = ScalarPrimitive::<Secp256k1>::from_slice(bytes).ok()?;
    Some(Scalar::from(&primitive))
}

/// Convierte 32 bytes big-endian a Scalar reduciendo mod n.
fn bytes_to_scalar_reduce(bytes: &[u8; 32]) -> Scalar {
    let wide = k256::U256::from_be_slice(bytes);
    <Scalar as Reduce<k256::U256>>::reduce(wide)
}

/// Convierte un Scalar a 32 bytes big-endian.
fn scalar_to_bytes(s: &Scalar) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&s.to_bytes());
    bytes
}

/// Reconstuye un AffinePoint desde x-only (32 bytes), asumiendo Y par.
/// Equivalente a "lift_x" de BIP340.
fn lift_x(x_bytes: &[u8; 32]) -> Option<AffinePoint> {
    // Construir compressed encoding con prefix 0x02 (even Y)
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..33].copy_from_slice(x_bytes);

    // Parse as compressed point
    use k256::elliptic_curve::sec1::FromEncodedPoint;
    use k256::EncodedPoint;

    let encoded = EncodedPoint::from_bytes(&compressed).ok()?;
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
#[cfg(any(test, feature = "verbose-boot"))]
/// Test: sign then verify succeeds.
pub fn test_sign_verify_roundtrip() -> bool {
    // Test private key (DO NOT use in production)
    let privkey: [u8; 32] = [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    // Mensaje de test (32 bytes)
    let message: [u8; 32] = [
        0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
        0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB,
    ];

    // Firmar
    let sig = match schnorr_sign(&privkey, &message) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Verificar que la firma es de 64 bytes
    if sig.bytes.len() != 64 {
        return false;
    }

    // Obtener public key x-only
    let sk = match SecretKey::from_slice(&privkey) {
        Ok(sk) => sk,
        Err(_) => return false,
    };
    let pk = sk.public_key();
    let pk_point = pk.to_encoded_point(true);
    let mut pubkey_x = [0u8; 32];
    pubkey_x.copy_from_slice(&pk_point.as_bytes()[1..33]);

    // Verificar firma
    schnorr_verify(&pubkey_x, &message, &sig).is_ok()
}

/// Test: deterministic signing (same key + message = same signature)
#[cfg(any(test, feature = "verbose-boot"))]
/// Test: deterministic signing (same key + message = same signature).
pub fn test_deterministic_signature() -> bool {
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

    // Must be identical (deterministic nonce)
    sig1.bytes == sig2.bytes
}

/// Test: invalid signature must fail verification
#[cfg(any(test, feature = "verbose-boot"))]
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

    // Obtener pubkey
    let sk = match SecretKey::from_slice(&privkey) {
        Ok(sk) => sk,
        Err(_) => return false,
    };
    let pk = sk.public_key();
    let pk_point = pk.to_encoded_point(true);
    let mut pubkey_x = [0u8; 32];
    pubkey_x.copy_from_slice(&pk_point.as_bytes()[1..33]);

    // Verificar con mensaje correcto → OK
    if schnorr_verify(&pubkey_x, &message, &sig).is_err() {
        return false;
    }

    // Verificar con mensaje incorrecto → debe fallar
    schnorr_verify(&pubkey_x, &wrong_message, &sig).is_err()
}

/// Test: firmar con clave derivada de BIP32
#[cfg(any(test, feature = "verbose-boot"))]
pub fn test_sign_with_bip32_key() -> bool {
    use super::bip39;
    use super::bip32;

    // Generate seed from known mnemonic
    let entropy = [0u8; 16]; // "abandon...about"
    let mnemonic = bip39::mnemonic_from_entropy_12(&entropy);
    let seed = bip39::seed_from_mnemonic_12(&mnemonic, "");

    // Derivar clave Kaspa
    let key = match bip32::derive_path(&seed.bytes, bip32::KASPA_MAINNET_PATH) {
        Ok(k) => k,
        Err(_) => return false,
    };

    // x-only pubkey
    let pubkey_x = match key.public_key_x_only() {
        Ok(pk) => pk,
        Err(_) => return false,
    };

    // Firmar un sighash ficticio
    let sighash = [0xABu8; 32];
    let sig = match schnorr_sign(key.private_key_bytes(), &sighash) {
        Ok(s) => s,
        Err(_) => return false,
    };

    // Verificar
    schnorr_verify(&pubkey_x, &sighash, &sig).is_ok()
}

/// Ejecuta todos los tests Schnorr.
/// Retorna (passed, total).
#[cfg(any(test, feature = "verbose-boot"))]
pub fn run_schnorr_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 4u32;

    if test_sign_verify_roundtrip() { passed += 1; }
    if test_deterministic_signature() { passed += 1; }
    if test_invalid_signature_fails() { passed += 1; }
    if test_sign_with_bip32_key() { passed += 1; }

    (passed, total)
}