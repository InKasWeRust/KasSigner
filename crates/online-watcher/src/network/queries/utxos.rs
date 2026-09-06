use std::collections::HashSet;

use crate::{
    account::bip32::WalletData,
    account::utxo::UtxoEntry,
    infrastructure::BrowserWebSocketTransport,
    network::{
        codec::{requests::utxo, responses},
        wrpc::operation::Operation,
    },
};

pub async fn fetch_all(websocket_url: &str, wallet: &WalletData) -> Result<Vec<UtxoEntry>, String> {
    let addresses = wallet
        .receive_addresses
        .iter()
        .chain(wallet.change_addresses.iter())
        .cloned()
        .collect::<Vec<_>>();
    fetch_for_addresses(websocket_url, &addresses).await
}

const COMPLETE_SCAN_BATCH_ADDRESSES: usize = 8;

/// Fetch the wallet UTXO set in bounded address batches for user-visible coin control.
///
/// This deliberately does not trust one large multi-address reply: every batch must
/// succeed and all returned outpoints are unioned by exact transaction id + index.
pub async fn fetch_all_complete(
    websocket_url: &str,
    wallet: &WalletData,
) -> Result<Vec<UtxoEntry>, String> {
    let addresses = wallet
        .receive_addresses
        .iter()
        .chain(wallet.change_addresses.iter())
        .cloned()
        .collect::<Vec<_>>();
    fetch_complete_for_addresses(websocket_url, &addresses).await
}

async fn fetch_complete_for_addresses(
    websocket_url: &str,
    addresses: &[String],
) -> Result<Vec<UtxoEntry>, String> {
    let mut complete = Vec::new();
    let mut seen = HashSet::new();
    for batch in addresses.chunks(COMPLETE_SCAN_BATCH_ADDRESSES) {
        let entries = fetch_for_addresses(websocket_url, batch).await?;
        append_unique_outpoints(&mut complete, &mut seen, entries);
    }
    Ok(complete)
}

pub(crate) fn append_unique_outpoints(
    destination: &mut Vec<UtxoEntry>,
    seen: &mut HashSet<(String, u32)>,
    entries: Vec<UtxoEntry>,
) {
    for entry in entries {
        let key = (entry.tx_id.clone(), entry.index);
        if seen.insert(key) {
            destination.push(entry);
        }
    }
}

pub async fn fetch_for_address(
    websocket_url: &str,
    address: &str,
) -> Result<Vec<UtxoEntry>, String> {
    fetch_for_addresses(websocket_url, &[address.to_owned()]).await
}

pub(crate) async fn fetch_for_addresses(
    websocket_url: &str,
    addresses: &[String],
) -> Result<Vec<UtxoEntry>, String> {
    let payload = utxo::encode(addresses).map_err(String::from)?;
    let transport = BrowserWebSocketTransport::new(websocket_url).map_err(String::from)?;
    let response = transport
        .call(Operation::GetUtxosByAddresses, &payload)
        .await
        .map_err(String::from)?;
    responses::utxo::decode(&response).map_err(String::from)
}
