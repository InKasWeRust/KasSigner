// KasSigner — Universal covenant-sign request/reveal dispatch.

use super::super::AppData;
use crate::runtime::data::CovenantSigningMode;

pub(super) fn process_raw(data: &[u8], len: usize, ad: &mut AppData, liveness: &mut (impl FnMut() + ?Sized)) {
    process(&data[..len.min(data.len())], ad, liveness);
}

pub(super) fn process_hex(data: &[u8], len: usize, ad: &mut AppData, liveness: &mut (impl FnMut() + ?Sized)) {
    let input = &data[..len.min(data.len())];
    let Ok(mut decoded) = crate::services::memory::zeroed_bytes(input.len() / 2) else {
        reject(ad, "Not enough memory");
        return;
    };
    let Ok(decoded_len) = signer_firmware_core::qr::classification::decode_hex(input, &mut decoded) else {
        reject(ad, "Invalid covenant message"); return;
    };
    process(&decoded[..decoded_len], ad, liveness);
    shared_signer::bytes::zeroize_bytes(&mut decoded);
}

fn process(wire: &[u8], ad: &mut AppData, liveness: &mut (impl FnMut() + ?Sized)) {
    if wire.starts_with(&shared_signer::covenant_sign::REVEAL_MAGIC) {
        process_reveal(wire, ad, liveness);
    } else {
        process_request(wire, ad, liveness);
    }
}

fn process_request(wire: &[u8], ad: &mut AppData, liveness: &mut (impl FnMut() + ?Sized)) {
    match crate::services::covenant_sign::prepare_request(ad, wire, liveness) {
        Ok(()) => {
            let route = match ad.signing.covenant.mode {
                CovenantSigningMode::KeyInfo => crate::runtime::navigation::route!(CovenantKeyResult),
                CovenantSigningMode::Known | CovenantSigningMode::BindKnown => crate::runtime::navigation::route!(CovenantSignReview),
                CovenantSigningMode::Opaque | CovenantSigningMode::BindOpaque => crate::runtime::navigation::route!(CovenantSignOpaqueWarning),
                CovenantSigningMode::None => { reject(ad, "Invalid covenant request"); return; }
            };
            crate::runtime::effects::route(ad, route);
            crate::runtime::effects::redraw(ad);
        }
        Err(error) => reject(ad, error.message()),
    }
}

fn process_reveal(wire: &[u8], ad: &mut AppData, liveness: &mut (impl FnMut() + ?Sized)) {
    match crate::services::covenant_sign::finalize_reveal(ad, wire, liveness) {
        Ok(()) => { crate::runtime::effects::route(ad, crate::runtime::navigation::route!(CovenantSignResult)); crate::runtime::effects::redraw(ad); }
        Err(error) => { ad.signing.covenant.reset(); reject(ad, error.message()); }
    }
}

fn reject(ad: &mut AppData, message: &str) {
    ad.signing.covenant.reset();
    crate::log!("   Covenant request rejected: {}", message);
    crate::runtime::presentation::show_error_spec_previous(ad, crate::runtime::presentation::COVENANT);
}
