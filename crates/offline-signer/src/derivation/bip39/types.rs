use zeroize::{Zeroize, ZeroizeOnDrop};

// BIP39 public value types.

#[derive(Debug, PartialEq)]
/// Errors during mnemonic generation or validation (BIP39).
pub enum Bip39Error {
    /// Invalid entropy length (must be 16 or 32 bytes)
    InvalidEntropyLength,
    /// Mnemonic checksum mismatch
    InvalidChecksum,
    /// Invalid word count (must be 12 or 24)
    InvalidWordCount,
    /// Palabra no encontrada en la wordlist
    WordNotFound,
}

// ─── Tipos ────────────────────────────────────────────────────────────

/// 12-word mnemonic (128 bits of entropy)
/// Stores wordlist indices (0-2047), not words as strings
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic12 {
    /// BIP39 wordlist indices (each 0..2047)
    pub indices: [u16; 12],
}

impl Mnemonic12 {
    pub fn zeroize(&mut self) {
        <Self as Zeroize>::zeroize(self);
    }
}

/// 24-word mnemonic (256 bits of entropy)
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic24 {
    pub indices: [u16; 24],
}

impl Mnemonic24 {
    pub fn zeroize(&mut self) {
        <Self as Zeroize>::zeroize(self);
    }
}

/// Seed BIP39 de 512 bits (64 bytes)
/// Result of PBKDF2-HMAC-SHA512
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Seed {
    pub bytes: [u8; 64],
}

impl Seed {
    /// Securely zeroize the seed
    pub fn zeroize(&mut self) {
        <Self as Zeroize>::zeroize(self);
    }
}
