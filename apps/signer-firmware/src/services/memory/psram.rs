//! Runtime PSRAM provenance and capability-constrained allocation.

use core::{
    alloc::{GlobalAlloc, Layout},
    sync::atomic::{AtomicUsize, Ordering},
};

use esp_alloc::{HeapRegion, MemoryCapability, HEAP};

static PSRAM_BASE: AtomicUsize = AtomicUsize::new(0);
static PSRAM_LEN: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PsramRegion {
    pub start: usize,
    pub len: usize,
}

impl PsramRegion {
    pub const fn end(self) -> Option<usize> {
        self.start.checked_add(self.len)
    }

    pub fn contains(self, start: usize, len: usize) -> bool {
        let Some(region_end) = self.end() else { return false; };
        let Some(allocation_end) = start.checked_add(len) else { return false; };
        start >= self.start && allocation_end <= region_end
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PsramError {
    InvalidRegion,
    AlreadyInitialized,
    NotInitialized,
    InvalidLayout,
    AllocationFailed,
    ProvenanceFailed,
    MisalignedAllocation,
}

/// Initialize the global PSRAM heap region and retain its runtime provenance.
///
/// ESP-HAL owns PSRAM discovery/mapping. KasSigner records exactly the region
/// returned by `psram_raw_parts()` and adds that same region to esp-alloc with
/// the `External` capability used by all Argon2 workspace allocations.
pub(crate) fn initialize(peripheral: &esp_hal::peripherals::PSRAM<'_>) -> Result<PsramRegion, PsramError> {
    let (start, len) = esp_hal::psram::psram_raw_parts(peripheral);
    let start_addr = start as usize;
    if start.is_null() || len == 0 || start_addr.checked_add(len).is_none() {
        return Err(PsramError::InvalidRegion);
    }
    if PSRAM_BASE.compare_exchange(0, start_addr, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return Err(PsramError::AlreadyInitialized);
    }
    PSRAM_LEN.store(len, Ordering::SeqCst);
    unsafe {
        HEAP.add_region(HeapRegion::new(start, len, MemoryCapability::External.into()));
    }
    Ok(PsramRegion { start: start_addr, len })
}


pub(crate) fn initialize_or_halt(peripheral: &esp_hal::peripherals::PSRAM<'_>) -> PsramRegion {
    let region = match initialize(peripheral) {
        Ok(region) => region,
        Err(error) => {
            crate::log!("FATAL: PSRAM provenance initialization failed: {:?}", error);
            loop { core::hint::spin_loop(); }
        }
    };
    let end = region.end().unwrap_or(region.start);
    crate::log!(
        "   PSRAM: runtime region 0x{:08x}..0x{:08x} ({} bytes)",
        region.start, end, region.len,
    );
    region
}

pub(crate) fn region() -> Result<PsramRegion, PsramError> {
    let start = PSRAM_BASE.load(Ordering::SeqCst);
    let len = PSRAM_LEN.load(Ordering::SeqCst);
    if start == 0 || len == 0 {
        Err(PsramError::NotInitialized)
    } else {
        Ok(PsramRegion { start, len })
    }
}

pub(crate) fn free_bytes() -> usize {
    HEAP.free_caps(MemoryCapability::External.into())
}

pub(crate) struct PsramAllocation {
    ptr: *mut u8,
    layout: Layout,
}

impl PsramAllocation {
    pub(crate) fn allocate(size: usize, align: usize) -> Result<Self, PsramError> {
        Self::allocate_with_reserve(size, align, 0)
    }

    pub(crate) fn allocate_with_reserve(size: usize, align: usize, reserve: usize) -> Result<Self, PsramError> {
        let required = size.checked_add(reserve).ok_or(PsramError::InvalidLayout)?;
        if free_bytes() < required { return Err(PsramError::AllocationFailed); }
        let layout = Layout::from_size_align(size, align).map_err(|_| PsramError::InvalidLayout)?;
        if layout.size() == 0 {
            return Err(PsramError::InvalidLayout);
        }
        let ptr = unsafe { HEAP.alloc_caps(MemoryCapability::External.into(), layout) };
        if ptr.is_null() {
            return Err(PsramError::AllocationFailed);
        }
        let allocation = Self { ptr, layout };
        if !allocation.has_valid_provenance() {
            unsafe { HEAP.dealloc(ptr, layout) };
            return Err(PsramError::ProvenanceFailed);
        }
        if allocation.start() % layout.align() != 0 {
            unsafe { HEAP.dealloc(ptr, layout) };
            return Err(PsramError::MisalignedAllocation);
        }

        // `HEAP.alloc_caps` returns raw, uninitialized storage. Initialize it
        // through the raw pointer before exposing any `&[u8]`, `&mut [u8]`,
        // or stronger typed reference. This is a Rust validity boundary, not
        // merely a confidentiality wipe: callers such as Argon2 may only form
        // references to initialized values.
        unsafe { core::ptr::write_bytes(ptr, 0, layout.size()) };
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        Ok(allocation)
    }

    pub(crate) fn start(&self) -> usize { self.ptr as usize }
    pub(crate) fn len(&self) -> usize { self.layout.size() }

    pub(crate) fn has_valid_provenance(&self) -> bool {
        region().is_ok_and(|psram| psram.contains(self.start(), self.len()))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self.ptr, self.layout.size()) }
    }

    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.layout.size()) }
    }
}

impl Drop for PsramAllocation {
    fn drop(&mut self) {
        shared_signer::bytes::zeroize_bytes(self.as_mut_bytes());
        unsafe { HEAP.dealloc(self.ptr, self.layout) };
    }
}

#[cfg(feature = "argon2-bench")]
pub(crate) fn probe_largest_allocatable(cap: usize, granularity: usize) -> usize {
    if granularity == 0 { return 0; }
    let upper = free_bytes().min(cap) / granularity;
    let mut low = 0usize;
    let mut high = upper;
    while low < high {
        let mid = (low + high + 1) / 2;
        if can_allocate(mid * granularity) { low = mid; } else { high = mid - 1; }
    }
    low * granularity
}

#[cfg(feature = "argon2-bench")]
fn can_allocate(size: usize) -> bool {
    if size == 0 { return true; }
    let Ok(layout) = Layout::from_size_align(size, 8) else { return false; };
    let ptr = unsafe { HEAP.alloc_caps(MemoryCapability::External.into(), layout) };
    if ptr.is_null() { return false; }
    let provenance_ok = region().is_ok_and(|psram| psram.contains(ptr as usize, size));
    unsafe { HEAP.dealloc(ptr, layout) };
    provenance_ok
}
