use crate::{
    crypto::schnorr,
    derivation::{bip32, bip39, xpub},
    transaction::{kspt, model, std_pskt},
};
use shared_signer::{PsktParsed, TxInputFormat};

/// Coordinates wallet derivation and transaction signing without owning UI,
/// hardware, storage, or transport concerns.
#[derive(Debug, Default, Clone, Copy)]
pub struct OfflineSigner;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TransactionEnvelopeError {
    Kspt(kspt::PsktError),
    Pskt(std_pskt::PskError),
}

impl OfflineSigner {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    #[must_use]
    pub fn generate_wallet_12(&self, entropy: &[u8; 16]) -> bip39::Mnemonic12 {
        bip39::mnemonic_from_entropy_12(entropy)
    }

    #[must_use]
    pub fn generate_wallet_24(&self, entropy: &[u8; 32]) -> bip39::Mnemonic24 {
        bip39::mnemonic_from_entropy_24(entropy)
    }

    pub fn restore_wallet_12(
        &self,
        mnemonic: &bip39::Mnemonic12,
        passphrase: &str,
    ) -> Result<bip39::Seed, bip39::Bip39Error> {
        bip39::validate_mnemonic_12(mnemonic)?;
        Ok(bip39::seed_from_mnemonic_12(mnemonic, passphrase))
    }

    pub fn restore_wallet_24(
        &self,
        mnemonic: &bip39::Mnemonic24,
        passphrase: &str,
    ) -> Result<bip39::Seed, bip39::Bip39Error> {
        bip39::validate_mnemonic_24(mnemonic)?;
        Ok(bip39::seed_from_mnemonic_24(mnemonic, passphrase))
    }

    pub fn export_watch_account(
        &self,
        seed: &[u8; 64],
        output: &mut [u8; xpub::KPUB_MAX_LEN],
    ) -> Result<usize, bip32::Bip32Error> {
        xpub::derive_and_serialize_kpub(seed, output)
    }

    pub fn review_transaction(
        &self,
        format: TxInputFormat,
        wire: &[u8],
        scratch: &mut [u8],
        transaction: &mut model::Transaction,
        parsed: &mut PsktParsed,
    ) -> Result<(), TransactionEnvelopeError> {
        match format {
            TxInputFormat::KsptCompact => {
                kspt::parse_compact_kspt(wire, transaction).map_err(TransactionEnvelopeError::Kspt)
            }
            TxInputFormat::PsktPskb | TxInputFormat::PsktSingle => {
                std_pskt::parse_pskt(wire, scratch, transaction, parsed)
                    .map_err(TransactionEnvelopeError::Pskt)
            }
        }
    }

    pub fn sign_transaction(
        &self,
        transaction: &model::Transaction,
        private_key: &[u8; 32],
        sighash_type: model::SigHashType,
    ) -> Result<kspt::SignedResponse, kspt::PsktError> {
        kspt::sign_transaction(transaction, private_key, sighash_type)
    }

    /// Sign reviewed human-readable message bytes using an explicit
    /// KasSigner message-signing domain. This API intentionally does not
    /// accept a precomputed digest, preventing transaction sighashes from
    /// crossing into the message-signing protocol.
    pub fn sign_user_message_with_entropy(
        &self,
        private_key: &[u8; 32],
        message: &[u8],
        signing_entropy: &[u8; 32],
    ) -> Result<schnorr::SchnorrSignature, schnorr::SchnorrError> {
        crate::crypto::message::sign_message_with_entropy(private_key, message, signing_entropy)
    }
}

#[cfg(test)]
mod unit_tests;
