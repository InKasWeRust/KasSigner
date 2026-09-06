use crate::{runtime::data::AppData};

pub(super) fn reset(ad: &mut AppData) {
    ad.qr.outgoing.purpose = crate::runtime::data::OutgoingQrPurpose::None;
    ad.qr.outgoing.frame_count = 0;
    ad.qr.outgoing.frame = 0;
    ad.qr.presentation.large = false;
    ad.qr.outgoing.manual_frames = false;
}

pub(super) fn log_response(ad: &AppData) {
    log!("   Signed response: {} bytes", ad.qr.outgoing.length);
    if ad.qr.outgoing.length == 0 {
        return;
    }
    let bytes = &ad.qr.outgoing.buffer[..ad.qr.outgoing.length];
    let Some(hex_len) = bytes.len().checked_mul(2) else { return; };
    let Ok(mut hex) = crate::services::memory::zeroed_bytes(hex_len) else { return; };
    for (index, byte) in bytes.iter().copied().enumerate() {
        hex[index * 2] = nybble(byte >> 4);
        hex[index * 2 + 1] = nybble(byte & 0x0F);
    }
    if let Ok(text) = core::str::from_utf8(&hex) {
        log!("   KSSN_HEX_START");
        log!("{}", text);
        log!("   KSSN_HEX_END");
    }
}

fn nybble(value: u8) -> u8 {
    if value < 10 { b'0' + value } else { b'a' + value - 10 }
}
