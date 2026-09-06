//! Typed single-slot cross-core mailbox built on [`WorkerLifecycle`].
//!
//! The mailbox centralizes `UnsafeCell`, `MaybeUninit`, slot initialization
//! tracking, volatile storage scrubbing, publication ordering, and cancellation
//! cleanup. Domain workers only provide `Send` job/result types and processing.

use core::{
    cell::UnsafeCell,
    mem::{size_of, MaybeUninit},
    sync::atomic::{AtomicBool, Ordering},
};

use super::{CancelAction, ReserveError, WorkerLifecycle};

struct SharedSlot<T> {
    value: UnsafeCell<MaybeUninit<T>>,
    initialized: AtomicBool,
}

// SAFETY: callers can access a slot only after the mailbox lifecycle transfers
// exclusive ownership between cores. `T: Send` is therefore sufficient.
unsafe impl<T: Send> Sync for SharedSlot<T> {}

impl<T> SharedSlot<T> {
    const fn new() -> Self {
        Self {
            value: UnsafeCell::new(MaybeUninit::uninit()),
            initialized: AtomicBool::new(false),
        }
    }

    fn write(&self, value: T) {
        // Lifecycle ownership guarantees the slot is empty. The initialized
        // guard is defensive and also makes RESERVED cancellation safe before
        // a job has actually been written.
        if self.initialized.load(Ordering::Acquire) {
            self.drop_and_scrub();
        }
        // SAFETY: the lifecycle grants the caller exclusive write ownership.
        unsafe { (*self.value.get()).write(value) };
        // Publish initialization only after the complete value is present.
        self.initialized.store(true, Ordering::Release);
    }

    fn take(&self) -> Option<T> {
        if !self.initialized.swap(false, Ordering::AcqRel) {
            return None;
        }
        // SAFETY: the initialized flag is set only after a complete write and
        // lifecycle acquire/release edges transfer exclusive slot ownership.
        let value = unsafe { (*self.value.get()).assume_init_read() };
        self.scrub_storage();
        Some(value)
    }

    fn drop_and_scrub(&self) {
        if let Some(value) = self.take() {
            drop(value);
        } else {
            self.scrub_storage();
        }
    }

    fn scrub_storage(&self) {
        // SAFETY: callers own the slot and this treats MaybeUninit backing
        // storage as bytes without reading uninitialized contents.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                self.value.get().cast::<u8>(),
                size_of::<MaybeUninit<T>>(),
            )
        };
        shared_signer::bytes::zeroize_bytes(bytes);
    }
}

pub struct CrossCoreMailbox<Job: Send, Output: Send> {
    lifecycle: WorkerLifecycle,
    job: SharedSlot<Job>,
    result: SharedSlot<Output>,
}

impl<Job: Send, Output: Send> CrossCoreMailbox<Job, Output> {
    pub const fn new() -> Self {
        Self {
            lifecycle: WorkerLifecycle::new(),
            job: SharedSlot::new(),
            result: SharedSlot::new(),
        }
    }

    pub fn mark_ready(&self) {
        self.lifecycle.mark_ready();
    }

    pub fn reserve(&self) -> Result<u8, ReserveError> {
        self.lifecycle.reserve()
    }

    /// Write and publish one fully initialized job.
    pub fn publish_job(&self, generation: u8, job: Job, initial_progress: u8) -> bool {
        self.job.write(job);
        if self.lifecycle.publish_ready(generation, initial_progress) {
            return true;
        }
        self.job.drop_and_scrub();
        self.lifecycle.finish_cancelled();
        false
    }

    /// Claim one published job on the worker core.
    pub fn take_job(&self) -> Option<Job> {
        if !self.lifecycle.claim_ready() {
            return None;
        }
        let job = self.job.take();
        if job.is_none() {
            // A missing initialized slot is fail-closed: resolve the lifecycle
            // rather than letting BUSY wedge forever.
            self.lifecycle.abort_missing_job();
        }
        job
    }

    /// Publish a completed result or destroy it if cancellation won the race.
    pub fn publish_result(&self, generation: u8, result: Output) -> bool {
        if !self.lifecycle.begin_publish(generation) {
            drop(result);
            self.lifecycle.finish_cancelled();
            return false;
        }
        self.result.write(result);
        if self.lifecycle.finish_publish() {
            return true;
        }
        self.result.drop_and_scrub();
        self.lifecycle.finish_cancelled();
        false
    }

    pub fn take_result(&self, generation: u8) -> Option<Output> {
        if !self.lifecycle.claim_result(generation) {
            return None;
        }
        let result = self.result.take();
        self.lifecycle.finish_result_take();
        result
    }

    pub fn discard_completed(&self) {
        if !self.lifecycle.claim_any_result() {
            return;
        }
        self.result.drop_and_scrub();
        self.lifecycle.finish_result_take();
    }

    /// Cancel one generation and scrub whichever static slot is owned by the
    /// caller at that lifecycle boundary.
    pub fn cancel(&self, generation: u8) {
        match self.lifecycle.cancel(generation) {
            CancelAction::None | CancelAction::WorkerWillDiscard => {}
            CancelAction::DropQueuedJob => {
                self.job.drop_and_scrub();
                self.lifecycle.finish_cancelled();
            }
            CancelAction::DropCompletedResult => {
                self.result.drop_and_scrub();
                self.lifecycle.finish_cancelled();
            }
        }
    }

    /// Cancel whichever generation currently owns this mailbox, if any.
    pub fn cancel_active(&self) {
        if let Some(generation) = self.lifecycle.active_generation() {
            self.cancel(generation);
        }
    }

    pub fn progress(&self, generation: u8) -> u8 {
        self.lifecycle.progress(generation)
    }

    pub fn set_progress(&self, progress: u8) {
        self.lifecycle.set_progress(progress);
    }

    pub fn is_idle(&self) -> bool {
        self.lifecycle.is_idle()
    }
}

impl<Job: Send, Output: Send> Default for CrossCoreMailbox<Job, Output> {
    fn default() -> Self {
        Self::new()
    }
}
