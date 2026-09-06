//! Domain-owned QR runtime state.

/// Maximum outgoing QR payload: protocol maximum of 64 frames × 255 bytes.
/// The buffer is inline in internal DRAM because seed/XPrv export paths use it.
mod security;

pub const OUTGOING_QR_BUFFER_SIZE: usize = shared_signer::qr_frame::MAX_FRAMES * u8::MAX as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutgoingQrPurpose {
    None,
    SignedTransaction,
    AntiKlepto,
}


#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CameraScanFault {
    None = 0,
    #[cfg(feature = "m5stack")]
    StartupUnavailable = 1,
    MemoryUnavailable = 2,
    #[cfg(feature = "m5stack")]
    RuntimeResources = 3,
    #[cfg(feature = "m5stack")]
    CaptureTimeout = 4,
    #[cfg(feature = "m5stack")]
    CaptureFailed = 5,
}

impl CameraScanFault {
    pub const fn is_fault(self) -> bool { (self as u8) != 0 }
}

pub struct OutgoingQrState {
    pub purpose: OutgoingQrPurpose,
    pub manual_frames: bool,
    pub buffer: [u8; OUTGOING_QR_BUFFER_SIZE],
    pub length: usize,
    pub frame: u8,
    pub frame_count: u8,
    pub covenant_backup_length: usize,
    pub close_state: Option<crate::runtime::navigation::ContinuationRoute>,
}

impl OutgoingQrState {
    pub fn ensure_len(&mut self, required: usize) -> Result<(), ()> {
        (required <= self.buffer.len()).then_some(()).ok_or(())
    }
}

pub struct QrPresentationState {
    pub large: bool,
    pub mode: u8,
    pub via_density: bool,
}

pub struct QrScanState {
    pub address: [u8; 80],
    pub address_length: usize,
    pub address_valid: bool,
    camera_fault: CameraScanFault,
    camera_reset_requested: bool,
}

impl QrScanState {
    pub fn begin_camera_entry(&mut self) {
        self.camera_fault = CameraScanFault::None;
        self.camera_reset_requested = true;
    }

    pub fn has_camera_fault(&self) -> bool { self.camera_fault.is_fault() }

    pub fn latch_camera_fault(&mut self, fault: CameraScanFault) {
        self.camera_fault = fault;
    }

    pub fn take_camera_reset_request(&mut self) -> bool {
        let requested = self.camera_reset_requested;
        self.camera_reset_requested = false;
        requested
    }


}

pub struct QrState {
    pub outgoing: OutgoingQrState,
    pub presentation: QrPresentationState,
    pub scan: QrScanState,
}

impl QrState {
    /// Initialize the large QR state directly at its final static address.
    ///
    /// `OutgoingQrState::buffer` is intentionally inline internal SRAM because it
    /// can carry seed/XPrv export material. Constructing `QrState` by value would
    /// put that 16,320-byte buffer on the firmware stack before moving it into
    /// `AppData`, so the static AppData initializer uses this placement routine.
    ///
    /// # Safety
    /// `target` must point to valid, properly aligned, uninitialized storage for one
    /// `QrState`, and the caller must not read or drop it until this function returns.
    #[inline(never)]
    pub(super) unsafe fn initialize_in_place(target: *mut Self) {
        let outgoing = core::ptr::addr_of_mut!((*target).outgoing);
        core::ptr::addr_of_mut!((*outgoing).purpose).write(OutgoingQrPurpose::None);
        core::ptr::addr_of_mut!((*outgoing).manual_frames).write(false);
        core::ptr::write_bytes(
            core::ptr::addr_of_mut!((*outgoing).buffer).cast::<u8>(),
            0,
            OUTGOING_QR_BUFFER_SIZE,
        );
        core::ptr::addr_of_mut!((*outgoing).length).write(0);
        core::ptr::addr_of_mut!((*outgoing).frame).write(0);
        core::ptr::addr_of_mut!((*outgoing).frame_count).write(0);
        core::ptr::addr_of_mut!((*outgoing).covenant_backup_length).write(0);
        core::ptr::addr_of_mut!((*outgoing).close_state).write(None);

        let presentation = core::ptr::addr_of_mut!((*target).presentation);
        core::ptr::addr_of_mut!((*presentation).large).write(false);
        core::ptr::addr_of_mut!((*presentation).mode).write(0);
        core::ptr::addr_of_mut!((*presentation).via_density).write(false);

        let scan = core::ptr::addr_of_mut!((*target).scan);
        core::ptr::write_bytes(
            core::ptr::addr_of_mut!((*scan).address).cast::<u8>(),
            0,
            80,
        );
        core::ptr::addr_of_mut!((*scan).address_length).write(0);
        core::ptr::addr_of_mut!((*scan).address_valid).write(false);
        core::ptr::addr_of_mut!((*scan).camera_fault).write(CameraScanFault::None);
        core::ptr::addr_of_mut!((*scan).camera_reset_requested).write(false);
    }
}
