use core::{
    cell::UnsafeCell,
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, Ordering},
};

use super::capture::CameraDma;

pub(super) struct CameraDmaSlot {
    locked: AtomicBool,
    initialized: AtomicBool,
    value: UnsafeCell<MaybeUninit<CameraDma>>,
}

impl CameraDmaSlot {
    pub(super) const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            initialized: AtomicBool::new(false),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    pub(super) fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    pub(super) fn initialize(&self, value: CameraDma) {
        let _guard = self.lock();
        if self.initialized.load(Ordering::Relaxed) {
            return;
        }
        unsafe { (*self.value.get()).write(value) };
        self.initialized.store(true, Ordering::Release);
    }

    pub(super) fn with_mut<R>(
        &self,
        operation: impl FnOnce(&mut CameraDma) -> R,
    ) -> Option<R> {
        let _guard = self.lock();
        if !self.initialized.load(Ordering::Acquire) {
            return None;
        }
        let owner = unsafe { (&mut *self.value.get()).assume_init_mut() };
        Some(operation(owner))
    }

    fn lock(&self) -> CameraDmaGuard<'_> {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        CameraDmaGuard { slot: self }
    }
}

// SAFETY: every access to `value` is serialized by `locked`, and no reference
// escapes the callback-based public API.
unsafe impl Sync for CameraDmaSlot {}

struct CameraDmaGuard<'a> {
    slot: &'a CameraDmaSlot,
}

impl Drop for CameraDmaGuard<'_> {
    fn drop(&mut self) {
        self.slot.locked.store(false, Ordering::Release);
    }
}
