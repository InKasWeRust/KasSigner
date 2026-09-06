// KasSee Web — KIP-10 covenant WASM exports.
// Split out of lib.rs; behaviour unchanged. License: GPL-3.0.

//! wasm-bindgen exports for the KIP-10 covenant suite: address builders and
//! PSKB spend constructors for every covenant type.

#[cfg(test)]
use crate::wasm_api::utilities::common::js_error;
use wasm_bindgen::prelude::*;

#[cfg(test)]
fn extract_csv_sequence_string(script: &[u8]) -> Result<u64, String> {
    crate::protocol::script::extract_csv_sequence(script).map(|value| value.unwrap_or(0))
}

#[cfg(test)]
fn extract_cltv_locktime_string(script: &[u8]) -> Result<u64, String> {
    crate::protocol::script::extract_cltv_locktime(script).map(|value| value.unwrap_or(0))
}

#[cfg(test)]
fn extract_csv_sequence(script: &[u8]) -> Result<u64, JsValue> {
    extract_csv_sequence_string(script).map_err(js_error)
}

#[cfg(test)]
fn extract_cltv_locktime(script: &[u8]) -> Result<u64, JsValue> {
    extract_cltv_locktime_string(script).map_err(js_error)
}

mod global_thread;
mod logging;
#[cfg(test)]
mod sweep;

mod families;

pub use families::*;

#[cfg(test)]
mod unit_tests;
