//! Host-testable lifecycle for single-slot cross-core workers.
//!
//! The worker payload/result storage remains owned by each hardware adapter, but
//! every worker uses this one atomic state protocol. Cancellation is a state
//! transition rather than a generation-only hint, so a cancelled READY/BUSY/
//! PUBLISHING/DONE job cannot strand a stale result and permanently wedge the
//! worker.

mod mailbox;
pub use mailbox::CrossCoreMailbox;

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

const IDLE: u8 = 0;
const RESERVED: u8 = 1;
const READY: u8 = 2;
const BUSY: u8 = 3;
const PUBLISHING: u8 = 4;
const DONE: u8 = 5;
const CANCELLED: u8 = 6;
const TAKING: u8 = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReserveError {
    Unavailable,
    Busy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancelAction {
    None,
    DropQueuedJob,
    WorkerWillDiscard,
    DropCompletedResult,
}

pub struct WorkerLifecycle {
    ready: AtomicBool,
    state: AtomicU8,
    generation: AtomicU8,
    progress: AtomicU8,
}

impl WorkerLifecycle {
    pub const fn new() -> Self {
        Self {
            ready: AtomicBool::new(false),
            state: AtomicU8::new(IDLE),
            generation: AtomicU8::new(0),
            progress: AtomicU8::new(0),
        }
    }

    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::Release);
    }

    pub fn is_idle(&self) -> bool {
        self.state.load(Ordering::Acquire) == IDLE
    }

    pub(crate) fn active_generation(&self) -> Option<u8> {
        (self.state.load(Ordering::Acquire) != IDLE)
            .then(|| self.generation.load(Ordering::Acquire))
    }

    pub fn reserve(&self) -> Result<u8, ReserveError> {
        if !self.ready.load(Ordering::Acquire) {
            return Err(ReserveError::Unavailable);
        }
        self.state
            .compare_exchange(IDLE, RESERVED, Ordering::Acquire, Ordering::Relaxed)
            .map_err(|_| ReserveError::Busy)?;
        let generation = self
            .generation
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_add(1);
        self.progress.store(0, Ordering::Relaxed);
        Ok(generation)
    }

    /// Publish a fully initialized job slot to the worker core.
    pub fn publish_ready(&self, generation: u8, initial_progress: u8) -> bool {
        if self.generation.load(Ordering::Acquire) != generation {
            return false;
        }
        self.progress.store(initial_progress, Ordering::Relaxed);
        self.state
            .compare_exchange(RESERVED, READY, Ordering::Release, Ordering::Relaxed)
            .is_ok()
    }

    /// Claim a published job. The payload slot may be read only after this succeeds.
    pub fn claim_ready(&self) -> bool {
        self.state
            .compare_exchange(READY, BUSY, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    /// Resolve a claimed BUSY state when its guarded payload slot is unexpectedly empty.
    /// This is a defensive recovery path for mailbox corruption, not a normal transition.
    pub(crate) fn abort_missing_job(&self) {
        self.progress.store(0, Ordering::Relaxed);
        let _ = self
            .state
            .compare_exchange(BUSY, IDLE, Ordering::Release, Ordering::Relaxed);
    }

    /// Reserve the result publication boundary after computation completes.
    pub fn begin_publish(&self, generation: u8) -> bool {
        if self.generation.load(Ordering::Acquire) != generation {
            return false;
        }
        self.state
            .compare_exchange(BUSY, PUBLISHING, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Publish an initialized result. Failure means cancellation won the race;
    /// the worker still owns the result slot and must clear it before cleanup.
    pub fn finish_publish(&self) -> bool {
        self.state
            .compare_exchange(PUBLISHING, DONE, Ordering::Release, Ordering::Acquire)
            .is_ok()
    }

    pub fn claim_result(&self, generation: u8) -> bool {
        if self.generation.load(Ordering::Acquire) != generation {
            return false;
        }
        self.state
            .compare_exchange(DONE, TAKING, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    pub fn claim_any_result(&self) -> bool {
        self.state
            .compare_exchange(DONE, TAKING, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    pub fn finish_result_take(&self) {
        self.progress.store(0, Ordering::Relaxed);
        let _ = self
            .state
            .compare_exchange(TAKING, IDLE, Ordering::Release, Ordering::Relaxed);
    }

    /// Cancel one generation and atomically decide who must destroy its slot.
    ///
    /// State ownership moves to CANCELLED *before* generation invalidation. That
    /// ordering is deliberate: an in-flight worker can never observe a stale
    /// generation first, attempt cleanup while the state is still BUSY, and then
    /// lose a race that strands CANCELLED forever. Once the state transition wins,
    /// no new reservation can reuse the slot until either Core0 or Core1 resolves
    /// the cancellation.
    pub fn cancel(&self, generation: u8) -> CancelAction {
        if self.generation.load(Ordering::Acquire) != generation {
            return CancelAction::None;
        }
        loop {
            let state = self.state.load(Ordering::Acquire);
            let action = match state {
                READY | RESERVED => CancelAction::DropQueuedJob,
                BUSY | PUBLISHING => CancelAction::WorkerWillDiscard,
                DONE => CancelAction::DropCompletedResult,
                IDLE | CANCELLED | TAKING => return CancelAction::None,
                _ => return CancelAction::None,
            };
            if self
                .state
                .compare_exchange(state, CANCELLED, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            // Invalidate stale consumers only after cancellation owns the slot. A
            // worker may already have resolved CANCELLED back to IDLE; if a new
            // reservation advanced the generation first, this CAS simply fails
            // rather than clobbering the new job's identity.
            let _ = self.generation.compare_exchange(
                generation,
                generation.wrapping_add(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            );
            return action;
        }
    }

    /// Complete cleanup after CANCELLED ownership has been resolved.
    pub fn finish_cancelled(&self) {
        self.progress.store(0, Ordering::Relaxed);
        let _ = self
            .state
            .compare_exchange(CANCELLED, IDLE, Ordering::Release, Ordering::Relaxed);
    }

    pub fn progress(&self, generation: u8) -> u8 {
        if self.generation.load(Ordering::Acquire) != generation {
            return 0;
        }
        self.progress.load(Ordering::Relaxed)
    }

    pub fn set_progress(&self, progress: u8) {
        self.progress.store(progress, Ordering::Relaxed);
    }
}

impl Default for WorkerLifecycle {
    fn default() -> Self {
        Self::new()
    }
}
