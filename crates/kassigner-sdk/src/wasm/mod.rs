//! `wasm-bindgen` facade for the friendly Rust SDK.

use js_sys::{Object, Reflect};
use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::prelude::*;

use super::{
    KasSigner as RustKasSigner, Network, SdkError, SdkErrorKind, SignedPskt, SigningRequest,
    SDK_VERSION,
};

fn to_json<T: Serialize>(value: &T) -> Result<String, JsValue> {
    serde_json::to_string(value)
        .map_err(|error| js_error(SdkError::new(SdkErrorKind::Internal, error.to_string())))
}

fn from_json<T: DeserializeOwned>(value: &str) -> Result<T, JsValue> {
    serde_json::from_str(value).map_err(|error| {
        js_error(SdkError::new(
            SdkErrorKind::MalformedRequest,
            error.to_string(),
        ))
    })
}

fn parse_network(value: &str) -> Result<Network, JsValue> {
    Network::parse(value)
        .map_err(SdkError::from)
        .map_err(js_error)
}

fn js_error(error: SdkError) -> JsValue {
    let object = Object::new();
    let _ = Reflect::set(
        &object,
        &JsValue::from_str("kind"),
        &JsValue::from_str(error.kind().as_str()),
    );
    let _ = Reflect::set(
        &object,
        &JsValue::from_str("message"),
        &JsValue::from_str(error.message()),
    );
    object.into()
}

#[wasm_bindgen]
pub struct KasSigner {
    inner: RustKasSigner,
}

#[wasm_bindgen]
impl KasSigner {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: RustKasSigner::new(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn version(&self) -> String {
        SDK_VERSION.to_string()
    }

    pub fn limits(&self) -> Result<String, JsValue> {
        to_json(&self.inner.limits())
    }

    #[wasm_bindgen(js_name = pairNormal)]
    pub fn pair_normal(&mut self, account_payload: &str, network: &str) -> Result<String, JsValue> {
        let network = parse_network(network)?;
        self.inner
            .pair_normal(account_payload, network)
            .map_err(js_error)
            .and_then(|value| to_json(&value))
    }

    #[wasm_bindgen(js_name = createPrivacyPairingRequest)]
    pub fn create_privacy_pairing_request(
        &mut self,
        receive_start: u32,
        receive_count: u8,
        change_start: u32,
        change_count: u8,
    ) -> Result<String, JsValue> {
        self.inner
            .create_privacy_pairing_request(
                receive_start,
                receive_count,
                change_start,
                change_count,
            )
            .map_err(js_error)
            .and_then(|value| to_json(&value))
    }

    #[wasm_bindgen(js_name = pairPrivacy)]
    pub fn pair_privacy(&mut self, response_hex: &str, network: &str) -> Result<String, JsValue> {
        let network = parse_network(network)?;
        self.inner
            .pair_privacy(response_hex, network)
            .map_err(js_error)
            .and_then(|value| to_json(&value))
    }

    pub fn prepare(&self, pskt_hex: &str, network: &str) -> Result<String, JsValue> {
        let network = parse_network(network)?;
        self.inner
            .prepare(pskt_hex, network)
            .map_err(js_error)
            .and_then(|value| to_json(&value))
    }

    pub fn complete(&self, request_json: &str, response_hex: &str) -> Result<String, JsValue> {
        let request: SigningRequest = from_json(request_json)?;
        self.inner
            .complete(&request, response_hex)
            .map_err(js_error)
            .and_then(|value| to_json(&value))
    }

    pub fn finalize(&self, signed_json: &str) -> Result<String, JsValue> {
        let signed: SignedPskt = from_json(signed_json)?;
        self.inner.finalize(&signed).map_err(js_error)
    }

    #[wasm_bindgen(js_name = acceptQrFrame)]
    pub fn accept_qr_frame(&mut self, frame_hex: &str) -> Result<Option<String>, JsValue> {
        let frame = hex::decode(frame_hex).map_err(|error| {
            js_error(SdkError::new(
                SdkErrorKind::MalformedRequest,
                format!("invalid QR frame hex: {error}"),
            ))
        })?;
        self.inner
            .accept_qr_frame(&frame)
            .map(|value| value.map(hex::encode))
            .map_err(js_error)
    }

    #[wasm_bindgen(js_name = resetQrDecoder)]
    pub fn reset_qr_decoder(&mut self) {
        self.inner.reset_qr_decoder();
    }

    #[wasm_bindgen(js_name = qrDecoderProgress)]
    pub fn qr_decoder_progress(&self) -> Result<String, JsValue> {
        to_json(&self.inner.qr_decoder_progress())
    }

    #[wasm_bindgen(js_name = accountFingerprint)]
    pub fn account_fingerprint(&self) -> Option<String> {
        self.inner.account_fingerprint().map(str::to_owned)
    }
}
