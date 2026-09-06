//! KasSee compatibility facade over protocol-owned watch-only BIP32 primitives.

pub(crate) use kassigner_protocol::compat::ExtPubKey;
pub use kassigner_protocol::WalletData;

pub(crate) fn decode_kpub_text(
    kpub_text: &str,
) -> Result<[u8; shared_signer::account_key::ACCOUNT_KEY_PAYLOAD_LEN], String> {
    kassigner_protocol::compat::decode_kpub_text(kpub_text)
}

pub fn import_kpub(kpub_text: &str, prefix: &str) -> Result<WalletData, String> {
    kassigner_protocol::compat::import_kpub(kpub_text, prefix)
}

pub fn import_kpub_raw(payload: &[u8], prefix: &str) -> Result<WalletData, String> {
    kassigner_protocol::compat::import_kpub_raw(payload, prefix)
}

pub fn extend_addresses(
    wallet: &WalletData,
    extra_receive: u32,
    extra_change: u32,
    prefix: &str,
) -> Result<WalletData, String> {
    kassigner_protocol::compat::extend_addresses(wallet, extra_receive, extra_change, prefix)
}
