//! Second-core rqrr worker for Waveshare camera scanning.
//!
//! Core 0 owns the job buffer in `IDLE`, publishes a frame with a Release
//! store, and keeps rendering. Core 1 decodes without logging, publishes one
//! outcome, and returns ownership only after core 0 consumes it.

use alloc::vec::Vec;
use signer_firmware_core::camera::dma::plan_decode_submission;
use core::{
    cell::UnsafeCell,
    sync::atomic::{AtomicPtr, AtomicU8, AtomicUsize, Ordering},
};

const IDLE: u8 = 0;
const READY: u8 = 1;
const BUSY: u8 = 2;
const DONE: u8 = 3;

static JOB_STATE: AtomicU8 = AtomicU8::new(IDLE);
static GENERATION: AtomicU8 = AtomicU8::new(0);
static JOB_GENERATION: AtomicU8 = AtomicU8::new(0);
static JOB_WIDTH: AtomicUsize = AtomicUsize::new(0);
static JOB_HEIGHT: AtomicUsize = AtomicUsize::new(0);
static JOB_BUFFER: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static JOB_BUFFER_LEN: AtomicUsize = AtomicUsize::new(0);

struct SharedCell<T>(UnsafeCell<T>);
unsafe impl<T: Send> Sync for SharedCell<T> {}
impl<T> SharedCell<T> {
    const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    fn get(&self) -> *mut T {
        self.0.get()
    }
}

static RESULT: SharedCell<Option<DecodeOutcome>> = SharedCell::new(None);

pub struct DecodeOutcome {
    pub generation: u8,
    pub grids: usize,
    pub results: Vec<(u8, Vec<u8>)>,
    pub prepare_ms: u32,
    pub detect_ms: u32,
    pub width: usize,
}

fn cycle_count() -> u32 {
    esp_hal::xtensa_lx::timer::get_cycle_count()
}

pub fn init(bytes: usize) -> bool {
    if !JOB_BUFFER.load(Ordering::Acquire).is_null() {
        return true;
    }
    let Ok(layout) = core::alloc::Layout::from_size_align(bytes, 4) else {
        return false;
    };
    let pointer = unsafe { alloc::alloc::alloc_zeroed(layout) };
    if pointer.is_null() {
        return false;
    }
    JOB_BUFFER_LEN.store(bytes, Ordering::Relaxed);
    JOB_BUFFER.store(pointer, Ordering::Release);
    true
}

pub fn submit(gray: &[u8], width: usize, height: usize) -> bool {
    let pointer = JOB_BUFFER.load(Ordering::Acquire);
    let Some(length) = plan_decode_submission(
        width,
        height,
        gray.len(),
        JOB_STATE.load(Ordering::Acquire) == IDLE,
        !pointer.is_null(),
        JOB_BUFFER_LEN.load(Ordering::Relaxed),
    ) else {
        return false;
    };
    unsafe { core::ptr::copy_nonoverlapping(gray.as_ptr(), pointer, length); }
    JOB_WIDTH.store(width, Ordering::Relaxed);
    JOB_HEIGHT.store(height, Ordering::Relaxed);
    JOB_GENERATION.store(GENERATION.load(Ordering::Relaxed), Ordering::Relaxed);
    JOB_STATE.store(READY, Ordering::Release);
    true
}

pub fn take_result() -> Option<DecodeOutcome> {
    if JOB_STATE.load(Ordering::Acquire) != DONE {
        return None;
    }
    let result = unsafe { core::ptr::replace(RESULT.get(), None) };
    JOB_STATE.store(IDLE, Ordering::Release);
    result
}

pub fn bump_generation() {
    GENERATION.fetch_add(1, Ordering::Relaxed);
}

pub fn current_generation() -> u8 {
    GENERATION.load(Ordering::Relaxed)
}

pub fn core1_main() -> ! {
    let _ = rqrr::RQRR_HEAP_BACKED;
    loop {
        if JOB_STATE
            .compare_exchange(READY, BUSY, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
            continue;
        }
        publish_outcome(decode_current_job());
    }
}

fn decode_current_job() -> DecodeOutcome {
    let width = JOB_WIDTH.load(Ordering::Relaxed);
    let height = JOB_HEIGHT.load(Ordering::Relaxed);
    let generation = JOB_GENERATION.load(Ordering::Relaxed);
    let length = width.saturating_mul(height);
    let pointer = JOB_BUFFER.load(Ordering::Acquire);
    let gray = unsafe { core::slice::from_raw_parts(pointer, length) };
    let before_prepare = cycle_count();
    let mut image = rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| {
        gray[y * width + x]
    });
    let after_prepare = cycle_count();
    let grids = image.detect_grids();
    let after_detect = cycle_count();
    let grid_count = grids.len();
    let mut results = Vec::new();
    for grid in grids {
        let mut decoded = Vec::new();
        if let Ok(metadata) = grid.decode_to(&mut decoded) {
            results.push((metadata.version.0 as u8, decoded));
        }
    }
    DecodeOutcome {
        generation,
        grids: grid_count,
        results,
        prepare_ms: after_prepare.wrapping_sub(before_prepare) / 240_000,
        detect_ms: after_detect.wrapping_sub(after_prepare) / 240_000,
        width,
    }
}

fn publish_outcome(outcome: DecodeOutcome) {
    unsafe { core::ptr::write(RESULT.get(), Some(outcome)); }
    JOB_STATE.store(DONE, Ordering::Release);
}

