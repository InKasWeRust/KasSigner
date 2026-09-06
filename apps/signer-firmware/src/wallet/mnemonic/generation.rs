// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Pure mnemonic generation helpers used by the seed-creation workflows.

use super::DiceCollector;
use shared_signer::bytes::zeroize_bytes;

/// Generate a 12- or 24-word mnemonic from caller-supplied entropy.
///
/// The returned array always has 24 slots; only the first `word_count` entries
/// are meaningful. Callers own entropy collection and zeroization.
pub fn generate_from_entropy(word_count: u8, entropy: &[u8]) -> [u16; 24] {
    let mut indices = [0u16; 24];
    if word_count == 12 {
        let mut source = [0u8; 16];
        source.copy_from_slice(&entropy[..16]);
        let mnemonic = offline_signer::OfflineSigner::new().generate_wallet_12(&source);
        indices[..12].copy_from_slice(&mnemonic.indices);
        zeroize_bytes(&mut source);
    } else {
        let mut source = [0u8; 32];
        source.copy_from_slice(&entropy[..32]);
        let mnemonic = offline_signer::OfflineSigner::new().generate_wallet_24(&source);
        indices.copy_from_slice(&mnemonic.indices);
        zeroize_bytes(&mut source);
    }
    indices
}

/// Generate a 12- or 24-word mnemonic from a completed dice collector.
///
/// The collector is zeroized before this function returns.
pub fn generate_from_dice(word_count: u8, dice: &mut DiceCollector) -> [u16; 24] {
    let indices = if word_count == 12 {
        let mut entropy = dice.extract_entropy_16();
        let result = generate_from_entropy(12, &entropy);
        zeroize_bytes(&mut entropy);
        result
    } else {
        let mut entropy = dice.extract_entropy_32();
        let result = generate_from_entropy(24, &entropy);
        zeroize_bytes(&mut entropy);
        result
    };
    dice.zeroize();
    indices
}
