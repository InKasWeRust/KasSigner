use embedded_graphics::prelude::DrawTarget;
use crate::{
    hw::display,
    runtime::data::AppData,
};

const FRAME_BUFFER_LEN: usize = 134;

pub(super) fn draw_payload(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>) {
    if ad.qr.outgoing.length == 0 {
        boot_display.draw_error_back_screen("Signing Failed");
        return;
    }

    if crate::runtime::qr_presentation::is_single_frame(ad) {
        boot_display.draw_qr_screen(&ad.qr.outgoing.buffer[..ad.qr.outgoing.length]);
        return;
    }

    draw_multi_frame(ad, boot_display);
}

fn draw_multi_frame(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>) {
    let payload_limit = crate::runtime::qr_presentation::payload_limit(ad);
    let frame_count = ad.qr.outgoing.length.div_ceil(payload_limit);
    if frame_count > shared_signer::qr_frame::MAX_FRAMES {
        boot_display.draw_error_back_screen("Payload Too Large");
        return;
    }
    let multisig = is_multisig(ad);
    initialize_signature_status(ad, multisig);
    let frame_index = ad.qr.outgoing.frame as usize;
    let balanced_payload = ad.qr.outgoing.length.div_ceil(frame_count);
    let offset = frame_index * balanced_payload;
    let fragment_len = ad
        .qr
        .outgoing
        .length
        .saturating_sub(offset)
        .min(balanced_payload);
    let Some(frame) = build_frame(ad, frame_index, frame_count, offset, fragment_len) else {
        boot_display.draw_error_back_screen("QR Frame Failed");
        return;
    };

    if frame_index == 0 {
        boot_display.display.clear(crate::ui::display::COLOR_BG).ok();
    }
    boot_display.draw_qr_screen_left(&frame.bytes[..frame.display_len]);
    draw_frame_counter(boot_display, frame_index, frame_count);
    if multisig {
        boot_display.draw_sig_status(
            ad.signing.transaction.signatures_present,
            ad.signing.transaction.signatures_required,
        );
    }
}

struct Frame {
    bytes: [u8; FRAME_BUFFER_LEN],
    display_len: usize,
}

fn build_frame(
    ad: &AppData,
    frame_index: usize,
    frame_count: usize,
    offset: usize,
    fragment_len: usize,
) -> Option<Frame> {
    let mut bytes = [0u8; FRAME_BUFFER_LEN];
    let identifier = shared_signer::qr_frame::session_id(
        &ad.qr.outgoing.buffer[..ad.qr.outgoing.length],
    );
    let display_len = shared_signer::qr_frame::encode_frame(
        &identifier,
        frame_index as u8,
        frame_count as u8,
        &ad.qr.outgoing.buffer[offset..offset + fragment_len],
        &mut bytes,
    )
    .ok()?;
    Some(Frame { bytes, display_len })
}

fn draw_frame_counter(
    boot_display: &mut display::BootDisplay<'_>,
    frame_index: usize,
    frame_count: usize,
) {
    let mut counter: heapless::String<8> = heapless::String::new();
    core::fmt::Write::write_fmt(
        &mut counter,
        format_args!("{}/{}", frame_index + 1, frame_count),
    )
    .ok();
    boot_display.draw_frame_counter(&counter);
}

fn is_multisig(ad: &AppData) -> bool {
    (0..ad.signing.transaction.active.num_inputs).any(|index| {
        let (script_type, _) =
            offline_signer::transaction::kspt::analyze_input_script(&ad.signing.transaction.active, index);
        matches!(
            script_type,
            offline_signer::transaction::model::ScriptType::Multisig
                | offline_signer::transaction::model::ScriptType::P2SH
        )
    })
}

fn initialize_signature_status(ad: &mut AppData, multisig: bool) {
    if !multisig || ad.signing.transaction.signatures_required != 0 {
        return;
    }
    let (present, required) =
        offline_signer::transaction::kspt::signature_status(&ad.signing.transaction.active);
    ad.signing.transaction.signatures_present = present;
    ad.signing.transaction.signatures_required = required;
}
