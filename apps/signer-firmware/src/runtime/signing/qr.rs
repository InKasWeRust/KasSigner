// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Signed multi-frame QR presentation lifecycle.

use crate::hw::display;
use crate::runtime::data::AppData;

// ─── Multi-frame signed QR cycling ───

/// Cycle the signed QR display animation (alternating QR codes for multi-input).
#[inline(never)]
pub fn cycle_signed_qr(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
) {
        if let crate::runtime::input::AppState::ShowQR = ad.navigation.app.state {
            if ad.qr.outgoing.frame_count > 1 && !ad.qr.outgoing.manual_frames {
                // Auto-cycle: Phone/KasSee = ~400ms, KasSigner = ~2s
                let cycle_interval = if ad.qr.presentation.via_density { 2000u32 } else { 400u32 };
                if ad.runtime.idle_ticks % cycle_interval != 0 {
                    return;
                }
                ad.qr.outgoing.frame = (ad.qr.outgoing.frame + 1) % ad.qr.outgoing.frame_count;
                let n_frames = ad.qr.outgoing.frame_count as usize;
                let balanced = (ad.qr.outgoing.length + n_frames - 1) / n_frames;
                let offset = ad.qr.outgoing.frame as usize * balanced;
                let remaining = ad.qr.outgoing.length.saturating_sub(offset);
                let frag_len = remaining.min(balanced);
                if frag_len > 0 {
                    let mut frame_buf = [0u8; 134];
                    let identifier = shared_signer::qr_frame::session_id(
                        &ad.qr.outgoing.buffer[..ad.qr.outgoing.length],
                    );
                    let Ok(qr_len) = shared_signer::qr_frame::encode_frame(
                        &identifier,
                        ad.qr.outgoing.frame,
                        ad.qr.outgoing.frame_count,
                        &ad.qr.outgoing.buffer[offset..offset + frag_len],
                        &mut frame_buf,
                    ) else {
                        crate::runtime::presentation::show_error_spec_previous(
                            ad, crate::runtime::presentation::QR_FRAME,
                        );
                        return;
                    };
                    // Match the unified redraw ShowQR logic:
                    // multi-frame QRs always use the left-aligned layout
                    // so the right info column stays available for the
                    // FRAMES counter. SIGNER badge only for multisig.
                    let is_multisig = (0..ad.signing.transaction.active.num_inputs).any(|i| {
                        let (st, _) = offline_signer::transaction::kspt::analyze_input_script(&ad.signing.transaction.active, i);
                        st == offline_signer::transaction::model::ScriptType::Multisig
                            || st == offline_signer::transaction::model::ScriptType::P2SH
                    });
                    boot_display.draw_qr_screen_left(&frame_buf[..qr_len]);
                    let mut fc_buf: heapless::String<8> = heapless::String::new();
                    core::fmt::Write::write_fmt(&mut fc_buf,
                        format_args!("{}/{}", ad.qr.outgoing.frame + 1, ad.qr.outgoing.frame_count)).ok();
                    boot_display.draw_frame_counter(&fc_buf);
                    if is_multisig {
                        boot_display.draw_sig_status(
                            ad.signing.transaction.signatures_present, ad.signing.transaction.signatures_required);
                    }
                }
            }
        }
}
