// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Internal-RAM allocator used only by the QEMU known-answer test image.
//!
//! Real hardware initializes the global allocator from PSRAM. Espressif QEMU
//! does not model external PSRAM, so the test image supplies a bounded internal
//! heap for the allocation-using offline-signer test code.

extern crate alloc;

use alloc::vec::Vec;
use esp_alloc::{HeapRegion, MemoryCapability};
use static_cell::StaticCell;

const QEMU_TEST_HEAP_BYTES: usize = 128 * 1024;
const PROBE_BYTES: usize = 4 * 1024;

static QEMU_TEST_HEAP: StaticCell<[u8; QEMU_TEST_HEAP_BYTES]> = StaticCell::new();

pub(crate) fn initialize() {
    let heap = QEMU_TEST_HEAP.init_with(|| [0; QEMU_TEST_HEAP_BYTES]);
    unsafe {
        esp_alloc::HEAP.add_region(HeapRegion::new(
            heap.as_mut_ptr(),
            heap.len(),
            MemoryCapability::Internal.into(),
        ));
    }
}

pub(crate) fn probe() -> bool {
    let mut buffer = Vec::with_capacity(PROBE_BYTES);
    for index in 0..PROBE_BYTES {
        buffer.push((index as u8).wrapping_mul(17));
    }

    buffer.len() == PROBE_BYTES
        && buffer[0] == 0
        && buffer[1] == 17
        && buffer[PROBE_BYTES - 1] == ((PROBE_BYTES - 1) as u8).wrapping_mul(17)
}
