use crate::{
    account::bip32,
    account::{
        balance::{self, BalanceInfo},
        utxo::UtxoEntry,
    },
    network::{queries, submission},
    protocol::{
        pskt,
        schnorr::bip340_verify,
        transaction::{consensus::ConsensusTransaction, signed_kspt},
    },
    transaction_builder, WalletData,
};
use std::vec::Vec;

/// The single online business facade. Browser bindings translate arguments
/// into these operations; focused modules retain derivation, RPC, planning,
/// serialization, and broadcast algorithms.
#[derive(Debug, Default, Clone, Copy)]
pub struct WatchWallet;

impl WatchWallet {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    pub fn import_account(&self, kpub: &str, network_prefix: &str) -> Result<WalletData, String> {
        bip32::import_kpub(kpub, network_prefix)
    }

    pub fn import_raw_account(
        &self,
        payload: &[u8],
        network_prefix: &str,
    ) -> Result<WalletData, String> {
        bip32::import_kpub_raw(payload, network_prefix)
    }

    pub async fn synchronize_balance(
        &self,
        wallet: &WalletData,
        websocket_url: &str,
    ) -> Result<BalanceInfo, String> {
        let utxos = queries::utxos::fetch_all(websocket_url, wallet).await?;
        balance::summarize_balance(wallet, &utxos)
    }

    pub async fn synchronize_utxos(
        &self,
        wallet: &WalletData,
        websocket_url: &str,
    ) -> Result<Vec<UtxoEntry>, String> {
        queries::utxos::fetch_all(websocket_url, wallet).await
    }

    /// Fetch a complete wallet UTXO set for manual coin control by reconciling
    /// bounded address batches instead of relying on one aggregate node reply.
    pub async fn synchronize_utxos_complete(
        &self,
        wallet: &WalletData,
        websocket_url: &str,
    ) -> Result<Vec<UtxoEntry>, String> {
        queries::utxos::fetch_all_complete(websocket_url, wallet).await
    }

    pub async fn build_transaction(
        &self,
        wallet: &WalletData,
        destination: &str,
        amount: u64,
        fee: u64,
        websocket_url: &str,
    ) -> Result<String, String> {
        transaction_builder::create_send(wallet, destination, amount, fee, websocket_url).await
    }

    pub async fn build_selected_transaction(
        &self,
        wallet: &WalletData,
        destination: &str,
        amount: u64,
        fee: u64,
        indices: &[usize],
        websocket_url: &str,
    ) -> Result<String, String> {
        transaction_builder::create_send_selected(
            wallet,
            destination,
            amount,
            fee,
            indices,
            websocket_url,
        )
        .await
    }

    pub async fn build_consolidation(
        &self,
        wallet: &WalletData,
        fee: u64,
        websocket_url: &str,
    ) -> Result<String, String> {
        transaction_builder::create_consolidation(wallet, fee, websocket_url).await
    }

    pub async fn build_multisig_transaction(
        &self,
        request: transaction_builder::MultisigTransactionRequest<'_>,
    ) -> Result<String, String> {
        transaction_builder::create_multisig(request).await
    }

    pub fn build_pskb_with_utxos(
        &self,
        wallet: &WalletData,
        destination: &str,
        amount: u64,
        fee: u64,
        selected: Vec<UtxoEntry>,
    ) -> Result<String, String> {
        transaction_builder::create_pskb_with_utxos(wallet, destination, amount, fee, selected)
    }

    pub fn build_pskb_with_explicit_change(
        &self,
        destination: &str,
        amount: u64,
        fee: u64,
        selected: Vec<UtxoEntry>,
        change_address: &str,
        change_index: u32,
    ) -> Result<String, String> {
        transaction_builder::create_pskb_with_utxos_and_change(
            destination,
            amount,
            fee,
            selected,
            change_address,
            change_index,
        )
    }

    pub fn verify_message(
        &self,
        public_key: &[u8; 32],
        message_hash: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<bool, String> {
        bip340_verify(public_key, message_hash, signature)
    }

    pub async fn finalize_and_broadcast(
        &self,
        signed_envelope_hex: &str,
        websocket_url: &str,
    ) -> Result<String, String> {
        let finalized = pskt::finalize_to_consensus(signed_envelope_hex)?;
        self.submit_transaction(&finalized.into_consensus_transaction(), websocket_url)
            .await
    }

    pub async fn broadcast(
        &self,
        signed_transaction_hex: &str,
        websocket_url: &str,
    ) -> Result<String, String> {
        let transaction = signed_kspt::decode_signed_kspt(signed_transaction_hex)?;
        self.submit_transaction(&transaction, websocket_url).await
    }

    pub(crate) async fn submit_transaction(
        &self,
        transaction: &ConsensusTransaction,
        websocket_url: &str,
    ) -> Result<String, String> {
        submission::submit(websocket_url, transaction).await
    }
}

#[cfg(test)]
mod unit_tests;
