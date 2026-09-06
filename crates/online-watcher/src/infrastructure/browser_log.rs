/// Browser console adapter used by domain/application code without exposing
/// `web_sys` throughout the crate.
#[cfg(target_arch = "wasm32")]
pub(crate) fn info(message: impl AsRef<str>) {
    use wasm_bindgen::JsValue;

    web_sys::console::log_1(&JsValue::from_str(message.as_ref()));
}

/// Host builds exercise the same domain code during unit and coverage tests,
/// but browser logging has no meaningful native destination. Keep the adapter
/// as a no-op rather than crossing the wasm-bindgen ABI on non-wasm targets.
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn info(message: impl AsRef<str>) {
    let _ = message.as_ref();
}
