use crate::wasm_api::utilities::common::{js_error, network_to_prefix};
use crate::{protocol::pskt, WatchWallet};
use wasm_bindgen::prelude::*;

/// Inspect a hex payload (output of the multi-frame QR decoder) and
/// return the detected format as a short string: "pskb", "pskt", or
/// "unknown". JS uses this to route a decoded payload to either the
/// PSKT review screen (this module) or the compact KSPT return flow.
#[wasm_bindgen]
pub fn pskt_detect(wire_hex: &str) -> String {
    match pskt::detect_format_hex(wire_hex) {
        pskt::PsktFormat::Pskb => "pskb".into(),
        pskt::PsktFormat::PsktSingle => "pskt".into(),
        pskt::PsktFormat::Unknown => "unknown".into(),
    }
}

/// Parse a PSKT/PSKB payload into a review summary (JSON string).
///
/// `network` is one of "mainnet", "testnet-10/11/12", "simnet",
/// "devnet" — used to format decoded output addresses for display.
#[wasm_bindgen]
pub fn pskt_summary(wire_hex: &str, network: &str) -> Result<String, JsValue> {
    let prefix = network_to_prefix(network);
    let summary = pskt::parse_summary(wire_hex, prefix).map_err(js_error)?;
    serde_json::to_string(&summary).map_err(|error| js_error(error.to_string()))
}

/// Re-emit a PSKB/PSKT as a compact KSPT "partial" hex blob for relay to
/// KasSigner over QR. Does NOT require M sigs — accepts 0..=N partial
/// sigs per input. Flags byte = 0x00 (partial).
///
#[wasm_bindgen]
pub fn pskt_relay_to_kspt(wire_hex: &str, network: &str) -> Result<String, JsValue> {
    pskt::relay_pskb_as_kspt_hex_for_network(wire_hex, network).map_err(js_error)
}

/// Inverse of `pskt_relay_to_kspt`: merge the partial sigs from a
/// device-returned compact KSPT blob into the canonical PSKB and return
/// the updated PSKB wire hex. Idempotent — existing sigs are not
/// clobbered.
///
/// Accepts `flags = 0x00` (partial) and `flags = 0x01` (fully signed)
/// equally. Caller must still check whether the merged PSKB has ≥M
/// sigs before finalizing/broadcasting.
#[wasm_bindgen]
pub fn pskt_merge_signed_kspt(
    signed_kspt_hex: &str,
    pskb_wire_hex: &str,
) -> Result<String, JsValue> {
    pskt::merge_signed_kspt_into_pskb(signed_kspt_hex, pskb_wire_hex).map_err(js_error)
}

/// PSKT-native finalize + broadcast. Walks the PSKB JSON once,
/// assembles a consensus Transaction directly (sig_scripts per input,
/// with partial sigs + redeem script for P2SH multisig), and submits
/// via Borsh wRPC. No KSPT intermediate format, no shim — PSKB JSON
/// in, Kaspa consensus transaction out, TX ID returned on acceptance.
#[wasm_bindgen]
pub async fn pskt_finalize_and_broadcast(wire_hex: &str, ws_url: &str) -> Result<String, JsValue> {
    WatchWallet::new()
        .finalize_and_broadcast(wire_hex, ws_url)
        .await
        .map_err(js_error)
}
