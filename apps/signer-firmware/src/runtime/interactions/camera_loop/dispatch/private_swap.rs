//! Private Swap v2 QR request/reveal dispatch.

use super::super::AppData;
use crate::runtime::data::PrivateSwapMode;

pub(super) fn process_raw(data: &[u8], len: usize, ad: &mut AppData, liveness: &mut (impl FnMut() + ?Sized)) {
    process(&data[..len.min(data.len())], ad, liveness);
}

pub(super) fn process_hex(data: &[u8], len: usize, ad: &mut AppData, liveness: &mut (impl FnMut() + ?Sized)) {
    let input = &data[..len.min(data.len())];
    let Ok(mut decoded) = crate::services::memory::zeroed_bytes(input.len() / 2) else {
        reject(ad, "Not enough memory");
        return;
    };
    let Ok(count) = signer_firmware_core::qr::classification::decode_hex(
        input,
        &mut decoded,
    ) else {
        reject(ad, "Invalid Private Swap message");
        return;
    };
    process(&decoded[..count], ad, liveness);
    shared_signer::bytes::zeroize_bytes(&mut decoded);
}

fn process(wire: &[u8], ad: &mut AppData, liveness: &mut (impl FnMut() + ?Sized)) {
    if wire.starts_with(&shared_signer::covenant_sign::private_swap::REVEAL_MAGIC) {
        match crate::services::private_swap::finalize_reveal(ad, wire, liveness) {
            Ok(()) => {
                crate::runtime::effects::route(
                    ad,
                    crate::runtime::navigation::route!(PrivateSwapResult),
                );
                crate::runtime::effects::redraw(ad);
            }
            Err(error) => reject(ad, error.message()),
        }
        return;
    }

    match crate::services::private_swap::prepare_request(ad, wire, liveness) {
        Ok(()) => {
            let route = match ad.signing.private_swap.mode {
                PrivateSwapMode::KeyInfo => {
                    crate::runtime::navigation::route!(PrivateSwapKeyResult)
                }
                PrivateSwapMode::Bind
                | PrivateSwapMode::PreSign
                | PrivateSwapMode::Complete => {
                    crate::runtime::navigation::route!(PrivateSwapReview)
                }
                PrivateSwapMode::None => {
                    reject(ad, "Invalid Private Swap request");
                    return;
                }
            };
            crate::runtime::effects::route(ad, route);
            crate::runtime::effects::redraw(ad);
        }
        Err(error) => reject(ad, error.message()),
    }
}

fn reject(ad: &mut AppData, message: &str) {
    ad.signing.private_swap.reset();
    crate::log!("   Private Swap rejected: {}", message);
    crate::runtime::presentation::show_error_spec_previous(
        ad,
        crate::runtime::presentation::PRIVATE_SWAP,
    );
}
