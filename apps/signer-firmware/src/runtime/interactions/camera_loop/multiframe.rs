// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Session-bound multi-frame QR accumulation and assembly.

use super::dispatch::process_confirmed_qr;
use super::state::{CameraSessionState, MultiFrameState, MF_BUF_SIZE, MF_MAX_FRAMES, MF_SLOT_SIZE};
use super::{display, sound, AppData};

#[inline(never)]
pub(super) fn process_multiframe(
    session: &mut CameraSessionState,
    data: &[u8],
    length: usize,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    let frame = match shared_signer::qr_frame::parse_frame(
        &data[..length.min(data.len())],
    ) {
        Ok(frame) => frame,
        Err(_) => return,
    };
    let frame_index = usize::from(frame.frame_index);
    let total = usize::from(frame.total_frames);
    if total > MF_MAX_FRAMES || frame.fragment.len() > MF_SLOT_SIZE {
        return;
    }

    let multiframe = &mut session.multiframe;
    if !multiframe.ensure_buffer() {
        log!("   multi-frame buffer allocation failed");
        return;
    }
    if shared_signer::security::authorize_frame_session(
        multiframe.session_active,
        &multiframe.session_id,
        multiframe.total,
        &frame.session_id,
        frame.total_frames,
    )
    .is_err()
    {
        log!("   Mixed multi-frame QR session rejected");
        sound::error();
        return;
    }
    if !multiframe.session_active {
        multiframe.session_id = frame.session_id;
        multiframe.session_active = true;
        multiframe.total = frame.total_frames;
    }

    let slot_offset = frame_index * MF_SLOT_SIZE;
    let end = slot_offset + frame.fragment.len();
    if end > MF_BUF_SIZE {
        return;
    }
    if multiframe.received[frame_index] {
        let prior_size = usize::from(multiframe.fragment_sizes[frame_index]);
        let prior = &multiframe.buffer()[slot_offset..slot_offset + prior_size];
        if prior != frame.fragment {
            log!("   conflicting duplicate QR frame rejected");
            sound::error();
        }
        return;
    }

    multiframe.buffer_mut()[slot_offset..end].copy_from_slice(frame.fragment);
    multiframe.fragment_sizes[frame_index] = frame.fragment.len() as u16;
    multiframe.received[frame_index] = true;
    sound::qr_found();

    let received_count = multiframe.received[..total]
        .iter()
        .filter(|received| **received)
        .count();
    log!(
        "   → Frame {}/{} ({} bytes), {}/{}",
        frame_index + 1,
        total,
        frame.fragment.len(),
        received_count,
        total,
    );
    draw_mf_counter(boot_display, &multiframe.received, frame.total_frames);

    if !multiframe.received[..total].iter().all(|received| *received) {
        return;
    }

    process_complete_session(multiframe, total, ad, boot_display, delay, i2c, liveness);
}

fn process_complete_session(
    multiframe: &mut MultiFrameState,
    total: usize,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    let Ok(mut assembled) = crate::services::memory::zeroed_bytes(MF_BUF_SIZE) else {
        log!("   multiframe assembly: PSRAM allocation failed");
        sound::error();
        multiframe.reset();
        return;
    };
    let mut position = 0usize;
    for index in 0..total {
        let slot = index * MF_SLOT_SIZE;
        let size = usize::from(multiframe.fragment_sizes[index]);
        assembled[position..position + size]
            .copy_from_slice(&multiframe.buffer()[slot..slot + size]);
        position += size;
    }
    let expected_session = multiframe.session_id;
    if !shared_signer::qr_frame::verify_session(
        &assembled[..position],
        &expected_session,
    ) {
        log!("   assembled QR session digest mismatch");
        sound::error();
        multiframe.reset();
        return;
    }

    log!("   → Complete QR session: {} frames, {} bytes", total, position);
    multiframe.reset();
    if ad.signing.anti_klepto.phase == crate::runtime::data::AntiKleptoPhase::AwaitingReveal {
        boot_display.draw_loading_wait_screen("Finalizing signature...");
    } else {
        boot_display.draw_loading_screen("Processing QR...");
    }
    log!("   QR processing UI shown after multi-frame assembly");
    process_confirmed_qr(&assembled[..position], position, ad, boot_display, delay, i2c, liveness);
}

/// Draw one progress dot per expected frame, up to the 64-frame protocol maximum.
#[inline(never)]
fn draw_mf_counter(
    boot_display: &mut display::BootDisplay<'_>,
    received: &[bool; MF_MAX_FRAMES],
    total: u8,
) {
    use embedded_graphics::pixelcolor::Rgb565;
    use embedded_graphics::prelude::*;
    use embedded_graphics::primitives::{PrimitiveStyle, Rectangle};

    const DOTS_PER_ROW: usize = 32;
    const DOT_SIZE: u32 = 4;
    const GAP: i32 = 4;
    const TOP_Y: i32 = 224;
    const SECOND_Y: i32 = 233;

    let total_clamped = (total as usize).min(MF_MAX_FRAMES);
    if total_clamped == 0 {
        return;
    }

    Rectangle::new(
        embedded_graphics::geometry::Point::new(0, 221),
        embedded_graphics::geometry::Size::new(320, 19),
    )
    .into_styled(PrimitiveStyle::with_fill(Rgb565::BLACK))
    .draw(&mut boot_display.display)
    .ok();

    draw_mf_row(
        boot_display,
        received,
        0,
        total_clamped.min(DOTS_PER_ROW),
        if total_clamped <= DOTS_PER_ROW { 229 } else { TOP_Y },
        DOT_SIZE,
        GAP,
    );
    if total_clamped > DOTS_PER_ROW {
        draw_mf_row(
            boot_display,
            received,
            DOTS_PER_ROW,
            total_clamped - DOTS_PER_ROW,
            SECOND_Y,
            DOT_SIZE,
            GAP,
        );
    }
}

fn draw_mf_row(
    boot_display: &mut display::BootDisplay<'_>,
    received: &[bool; MF_MAX_FRAMES],
    start: usize,
    count: usize,
    y: i32,
    dot_size: u32,
    gap: i32,
) {
    use embedded_graphics::pixelcolor::Rgb565;
    use embedded_graphics::prelude::*;
    use embedded_graphics::primitives::{Circle, PrimitiveStyle};

    if count == 0 {
        return;
    }
    let total_width = count as i32 * dot_size as i32 + (count as i32 - 1) * gap;
    let x_start = (320 - total_width) / 2;
    let teal = crate::ui::display::KASPA_TEAL;
    let pending = Rgb565::new(6, 12, 6);
    for offset in 0..count {
        let index = start + offset;
        let x = x_start + offset as i32 * (dot_size as i32 + gap);
        let color = if received[index] { teal } else { pending };
        Circle::new(
            embedded_graphics::geometry::Point::new(x, y),
            dot_size,
        )
        .into_styled(PrimitiveStyle::with_fill(color))
        .draw(&mut boot_display.display)
        .ok();
    }
}

/// Check whether decoded bytes use the session-bound multi-frame envelope.
#[inline(always)]
pub(super) fn is_multiframe(data: &[u8], length: usize) -> bool {
    shared_signer::qr_frame::is_session_frame(&data[..length.min(data.len())])
}
