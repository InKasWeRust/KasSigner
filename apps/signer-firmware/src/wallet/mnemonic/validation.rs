//! Pure BIP39 validation and checksum completion.

pub fn validate(indices: &[u16; 24], word_count: u8) -> bool {
    if word_count == 12 {
        let mut words = [0u16; 12];
        words.copy_from_slice(&indices[..12]);
        let mnemonic = offline_signer::derivation::bip39::Mnemonic12 { indices: words };
        offline_signer::derivation::bip39::validate_mnemonic_12(&mnemonic).is_ok()
    } else if word_count == 24 {
        let mnemonic = offline_signer::derivation::bip39::Mnemonic24 { indices: *indices };
        offline_signer::derivation::bip39::validate_mnemonic_24(&mnemonic).is_ok()
    } else {
        false
    }
}

pub fn complete_last_word(indices: &[u16; 24], word_count: u8) -> Option<u16> {
    match word_count {
        12 => {
            let mut words = [0u16; 11];
            words.copy_from_slice(&indices[..11]);
            Some(super::calc_last_word_12(&words))
        }
        24 => {
            let mut words = [0u16; 23];
            words.copy_from_slice(&indices[..23]);
            Some(super::calc_last_word_24(&words))
        }
        _ => None,
    }
}
