//! Direct KasSigner privacy-pairing request handling.
//!
//! The scanned wallet request contains explicit receive/change ranges. The
//! signer derives only those public keys and returns them as a QR payload; it
//! persists no host cursor and never exports account-level public derivation.

use crate::hw::display;
use crate::runtime::data::{AppData, OutgoingQrPurpose};
use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};

pub(super) fn process(
    data: &[u8],
    len: usize,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    let input = &data[..len.min(data.len())];
    let request = match shared_signer::pairing::parse_request(input) {
        Ok(request) => request,
        Err(_) => {
            show_rejection(boot_display, delay, "Invalid pairing request", 1_500, ErrorSound::Silent);
            return;
        }
    };
    let account = match crate::runtime::signing::derive_active_account_key_with_checkpoint(ad, liveness) {
        Ok(account) => account,
        Err(_) => {
            show_rejection(boot_display, delay, "HD wallet required", 1_500, ErrorSound::Silent);
            return;
        }
    };
    if prepare_response(ad, &account, request, liveness).is_err() {
        show_rejection(boot_display, delay, "Pairing derivation failed", 1_500, ErrorSound::Silent);
        return;
    }
    ad.qr.outgoing.close_state = Some(crate::runtime::navigation::continuation!(MainMenu));
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ShowQR));
}

fn prepare_response(
    ad: &mut AppData,
    account: &offline_signer::derivation::bip32::ExtendedPrivKey,
    request: shared_signer::pairing::AddressBatchRequest,
    liveness: &mut (impl FnMut() + ?Sized),
) -> Result<(), ()> {
    let required = request.response_len();
    ad.qr.outgoing.ensure_len(required)?;
    ad.qr.outgoing.clear();
    let compressed = account.public_key_compressed().map_err(|_| ())?;
    let fingerprint = shared_signer::pairing::account_fingerprint(
        &compressed,
        account.chain_code_bytes(),
    );
    let mut cursor = shared_signer::pairing::encode_response_header(
        request,
        fingerprint,
        &mut ad.qr.outgoing.buffer[..required],
    )
    .map_err(|_| ())?;
    cursor = derive_chain_keys_into(
        &mut ad.qr.outgoing.buffer,
        cursor,
        account,
        request.receive_start,
        request.receive_count,
        false,
        liveness,
    )?;
    cursor = derive_chain_keys_into(
        &mut ad.qr.outgoing.buffer,
        cursor,
        account,
        request.change_start,
        request.change_count,
        true,
        liveness,
    )?;
    if cursor != required {
        return Err(());
    }
    ad.qr.outgoing.length = cursor;
    ad.qr.outgoing.purpose = OutgoingQrPurpose::None;
    ad.qr.outgoing.frame = 0;
    ad.qr.outgoing.frame_count = 0;
    ad.qr.outgoing.manual_frames = false;
    ad.qr.presentation.large = false;
    ad.qr.presentation.mode = 0;
    Ok(())
}

fn derive_chain_keys_into(
    output: &mut [u8],
    mut cursor: usize,
    account: &offline_signer::derivation::bip32::ExtendedPrivKey,
    start: u32,
    count: u8,
    change: bool,
    liveness: &mut (impl FnMut() + ?Sized),
) -> Result<usize, ()> {
    for offset in 0..u32::from(count) {
        liveness();
        let index = start.checked_add(offset).ok_or(())?;
        let key = if change {
            offline_signer::derivation::bip32::derive_change_key(account, index)
        } else {
            offline_signer::derivation::bip32::derive_address_key(account, index)
        }
        .map_err(|_| ())?;
        liveness();
        let public_key = key.public_key_x_only().map_err(|_| ())?;
        let end = cursor.checked_add(public_key.len()).ok_or(())?;
        output.get_mut(cursor..end).ok_or(())?.copy_from_slice(&public_key);
        cursor = end;
    }
    Ok(cursor)
}
