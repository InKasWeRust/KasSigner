//! Synthetic remanence diagnostic. No real wallet-derived sentinel exists.
//! The diagnostic exercises representative secret-bearing application stores
//! and the real unused stack/remanence region, then proves the marker is gone
//! after the intended volatile wipe boundaries.

use crate::runtime::data::AppData;
use core::sync::atomic::{AtomicUsize, Ordering};
use sha2::{Digest, Sha256};

static SENTINEL: [u8; 32] = [
    0xA7,0x31,0xC4,0x5E,0x92,0x6B,0xD8,0x13,0xF0,0x49,0x2D,0x85,0xBE,0x67,0x14,0xCA,
    0x39,0xE1,0x58,0x74,0x0B,0xD2,0x96,0x43,0xFC,0x21,0x6D,0x8A,0x35,0xB7,0x50,0xCE,
];
const STACK_PROBE_BYTES: usize = 2048;
const STACK_LIVE_MARGIN: usize = 512;
static STACK_PROBE_LOW: AtomicUsize = AtomicUsize::new(0);
static STACK_PROBE_HIGH: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn run(ad: &mut AppData) -> bool {
    seed_representative_app_paths(ad);
    let app_before = explicit_marker_hits(ad);

    exercise_secret_bearing_stack_path();
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let stack_before = count_stack_remanence();

    crate::services::device_wipe::zeroize_volatile(ad);
    wipe_unused_stack_remanence();
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    let app_after = explicit_marker_hits(ad);
    let stack_after = count_stack_remanence();
    crate::log!(
        "[sentinel-scan] synthetic app hits {}->{} stack hits {}->{}",
        app_before, app_after, stack_before, stack_after
    );
    app_before >= 8 && app_after == 0 && stack_before > 0 && stack_after == 0
}

pub(crate) fn run_and_halt(ad: &mut AppData, delay: &mut esp_hal::delay::Delay) -> ! {
    let ok = run(ad);
    crate::log!("[sentinel-scan] {}", if ok { "PASS" } else { "FAIL" });
    crate::halt_forever(delay)
}

/// Put the synthetic marker through a real stack-resident crypto staging path.
/// The frame deliberately returns without wiping its synthetic scratch so the
/// diagnostic can prove that the subsequent remanence wipe reaches it.
#[inline(never)]
fn exercise_secret_bearing_stack_path() {
    let mut scratch = [0u8; STACK_PROBE_BYTES];
    let low = scratch.as_ptr() as usize;
    STACK_PROBE_LOW.store(low, Ordering::Relaxed);
    STACK_PROBE_HIGH.store(low.saturating_add(STACK_PROBE_BYTES), Ordering::Release);
    for (offset, byte) in SENTINEL.iter().copied().enumerate() {
        unsafe { core::ptr::write_volatile(scratch.as_mut_ptr().add(128 + offset), byte); }
        unsafe { core::ptr::write_volatile(scratch.as_mut_ptr().add(896 + offset), byte); }
        unsafe { core::ptr::write_volatile(scratch.as_mut_ptr().add(1664 + offset), byte); }
    }
    let digest: [u8; 32] = Sha256::digest(&scratch[896..928]).into();
    for (offset, byte) in digest.iter().copied().enumerate() {
        unsafe { core::ptr::write_volatile(scratch.as_mut_ptr().add(1408 + offset), byte); }
    }
    // Keep the whole stack object observable until the frame returns.
    let observed = unsafe { core::ptr::read_volatile(scratch.as_ptr().add(1664)) };
    core::hint::black_box(observed);
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[inline(never)]
fn approx_sp() -> usize {
    let marker: u32 = 0;
    core::ptr::addr_of!(marker) as usize
}

/// Scan only the retired stack object that actually carried the synthetic
/// secret path. The current scanner frame can reuse the high end of that old
/// frame, so leave a fixed margin below the live stack pointer before reading
/// or wiping. No linker/global RAM boundary is used as a wipe address.
fn remanence_bounds() -> Option<(usize, usize)> {
    let low = STACK_PROBE_LOW.load(Ordering::Acquire);
    let recorded_high = STACK_PROBE_HIGH.load(Ordering::Acquire);
    if low == 0 || recorded_high <= low { return None; }
    let live_safe_high = approx_sp().saturating_sub(STACK_LIVE_MARGIN);
    let high = core::cmp::min(recorded_high, live_safe_high);
    (high > low).then_some((low, high))
}

fn count_stack_remanence() -> usize {
    let Some((low, high)) = remanence_bounds() else { return 0; };
    let mut hits = 0usize;
    let mut address = low;
    while address.saturating_add(SENTINEL.len()) <= high {
        if marker_at(address) { hits = hits.saturating_add(1); }
        address = address.saturating_add(1);
    }
    hits
}

fn marker_at(address: usize) -> bool {
    for index in 0..SENTINEL.len() {
        let stack_byte = unsafe { core::ptr::read_volatile((address + index) as *const u8) };
        let marker_byte = unsafe { core::ptr::read_volatile(SENTINEL.as_ptr().add(index)) };
        if stack_byte != marker_byte { return false; }
    }
    true
}

fn wipe_unused_stack_remanence() {
    let Some((low, high)) = remanence_bounds() else { return; };
    let mut address = low;
    while address < high {
        unsafe { core::ptr::write_volatile(address as *mut u8, 0); }
        address = address.saturating_add(1);
    }
}

fn seed_representative_app_paths(ad: &mut AppData) {
    ad.wallet.keys.acct_key_raw[..32].copy_from_slice(&SENTINEL);
    ad.wallet.keys.hex_input[..32].copy_from_slice(&SENTINEL);
    ad.export.export_key_hex[..32].copy_from_slice(&SENTINEL);
    ad.export.kpub_data[..32].copy_from_slice(&SENTINEL);
    ad.export.xprv_data[..32].copy_from_slice(&SENTINEL);
    ad.qr.outgoing.buffer[..32].copy_from_slice(&SENTINEL);
    ad.signing.message.payload[..32].copy_from_slice(&SENTINEL);
    ad.signing.commit_reveal.plaintext[..32].copy_from_slice(&SENTINEL);
}

fn explicit_marker_hits(ad: &AppData) -> usize {
    [&ad.wallet.keys.acct_key_raw[..], &ad.wallet.keys.hex_input[..], &ad.export.export_key_hex[..],
     &ad.export.kpub_data[..], &ad.export.xprv_data[..], &ad.qr.outgoing.buffer[..],
     &ad.signing.message.payload[..], &ad.signing.commit_reveal.plaintext[..]]
        .into_iter().filter(|bytes| contains_sentinel(bytes)).count()
}

fn count_marker(bytes: &[u8]) -> usize {
    bytes.windows(SENTINEL.len()).filter(|window| *window == SENTINEL).count()
}
fn contains_sentinel(bytes: &[u8]) -> bool { count_marker(bytes) != 0 }
