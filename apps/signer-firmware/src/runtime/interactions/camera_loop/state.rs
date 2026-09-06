// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Explicit camera-session ownership.
//!
//! A single session object owns frame buffers, decoder status, and
//! multi-frame assembly state and is passed through the camera façade.

extern crate alloc;
use alloc::vec::Vec;

pub(super) const FRAME_WIDTH: usize = 320;
pub(super) const FRAME_HEIGHT: usize = 240;
pub(super) const DB_SIZE: usize = FRAME_WIDTH * FRAME_HEIGHT;
pub(super) const CROP_WIDTH: usize = 240;
pub(super) const CROP_HEIGHT: usize = 180;
pub(super) const CROP_SIZE: usize = CROP_WIDTH * CROP_HEIGHT;

// Sixty-four slots cover the protocol maximum. Each fragment length is encoded
// in one byte, so a slot holds at most 255 payload bytes.
pub(super) const MF_MAX_FRAMES: usize = shared_signer::qr_frame::MAX_FRAMES;
pub(super) const MF_SLOT_SIZE: usize = u8::MAX as usize;
pub(super) const MF_BUF_SIZE: usize = MF_MAX_FRAMES * MF_SLOT_SIZE;

pub(super) struct FrameState {
    pub(super) number: u32,
    db: Vec<u8>,
    crop: Vec<u8>,
}

impl FrameState {
    fn ensure_buffers(&mut self) -> bool {
        ensure_zeroed_len(&mut self.db, DB_SIZE)
            && ensure_zeroed_len(&mut self.crop, CROP_SIZE)
    }

    pub(super) fn db_ptr(&mut self) -> *mut u8 {
        self.db.as_mut_ptr()
    }

    pub(super) fn crop_ptr(&mut self) -> *mut u8 {
        self.crop.as_mut_ptr()
    }
}

pub(super) struct QrDecoderState {
    pub(super) cooldown: u32,
    pub(super) finders_beeped: bool,
    pub(super) error_showing: bool,
    pub(super) guide_version: u8,
}

impl QrDecoderState {
    fn reset(&mut self) {
        self.cooldown = 0;
        self.finders_beeped = false;
        self.error_showing = false;
        self.guide_version = 0;
    }
}

pub(super) struct MultiFrameState {
    buffer: Vec<u8>,
    pub(super) received: [bool; MF_MAX_FRAMES],
    pub(super) fragment_sizes: [u16; MF_MAX_FRAMES],
    pub(super) session_id: [u8; shared_signer::qr_frame::SESSION_ID_LEN],
    pub(super) session_active: bool,
    pub(super) total: u8,
}

impl MultiFrameState {
    pub(super) fn ensure_buffer(&mut self) -> bool {
        ensure_zeroed_len(&mut self.buffer, MF_BUF_SIZE)
    }

    pub(super) fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub(super) fn buffer_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    pub(super) fn reset(&mut self) {
        self.total = 0;
        self.session_active = false;
        shared_signer::bytes::zeroize_bytes(&mut self.session_id);
        shared_signer::bytes::zeroize_bytes(&mut self.buffer);
        self.received.fill(false);
        self.fragment_sizes.fill(0);
    }
}

/// Mutable state for one camera/QR session.
///
/// It is created by the event loop and passed explicitly to every camera-cycle
/// operation. The object remains small until the first camera entry, when its
/// PSRAM-backed vectors are allocated.
pub struct CameraSessionState {
    pub(super) frame: FrameState,
    pub(super) decoder: QrDecoderState,
    pub(super) multiframe: MultiFrameState,
    active_screen: Option<crate::runtime::input::AppState>,
    capture_failures: u8,
    #[cfg(feature = "waveshare")]
    sensor_is_ov2640: bool,
}

impl CameraSessionState {
    #[cfg(feature = "waveshare")]
    pub const fn new(sensor_is_ov2640: bool) -> Self {
        let mut session = Self::empty();
        session.sensor_is_ov2640 = sensor_is_ov2640;
        session
    }

    #[cfg(feature = "m5stack")]
    pub const fn new() -> Self {
        Self::empty()
    }

    const fn empty() -> Self {
        Self {
            frame: FrameState { number: 0, db: Vec::new(), crop: Vec::new() },
            decoder: QrDecoderState {
                cooldown: 0,
                finders_beeped: false,
                error_showing: false,
                guide_version: 0,
            },
            multiframe: MultiFrameState {
                buffer: Vec::new(),
                received: [false; MF_MAX_FRAMES],
                fragment_sizes: [0; MF_MAX_FRAMES],
                session_id: [0; shared_signer::qr_frame::SESSION_ID_LEN],
                session_active: false,
                total: 0,
            },
            active_screen: None,
            capture_failures: 0,
            #[cfg(feature = "waveshare")]
            sensor_is_ov2640: false,
        }
    }

    #[cfg(feature = "waveshare")]
    pub(crate) const fn is_ov2640(&self) -> bool {
        self.sensor_is_ov2640
    }

    pub(super) fn ensure_frame_buffers(&mut self) -> bool {
        self.frame.ensure_buffers()
    }

    pub(super) fn enter_screen(&mut self, state: crate::runtime::input::AppState) -> bool {
        if self.active_screen == Some(state) { return false; }
        self.active_screen = Some(state);
        self.capture_failures = 0;
        true
    }

    pub(crate) fn leave_screen(&mut self) {
        self.active_screen = None;
        self.capture_failures = 0;
    }

    #[cfg(feature = "m5stack")]
    pub(super) fn capture_succeeded(&mut self) {
        self.capture_failures = 0;
    }

    #[cfg(feature = "m5stack")]
    pub(super) fn capture_failed(&mut self) -> bool {
        self.capture_failures = self.capture_failures.saturating_add(1);
        self.capture_failures >= 3
    }

    pub(super) fn reset_scan(&mut self) {
        #[cfg(feature = "waveshare")]
        crate::services::camera_device::bump_generation();
        self.decoder.reset();
        self.multiframe.reset();
    }
}

fn ensure_zeroed_len(buffer: &mut Vec<u8>, required: usize) -> bool {
    if buffer.len() == required {
        return true;
    }
    if buffer.len() > required {
        buffer.truncate(required);
        return true;
    }
    if buffer.try_reserve_exact(required - buffer.len()).is_err() {
        return false;
    }
    buffer.resize(required, 0);
    true
}
