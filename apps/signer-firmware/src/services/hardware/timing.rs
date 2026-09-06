//! Bounded controller timing service.

/// Production/HIL pauses remain real. The ordinary connected workflow image is
/// a controller/state-machine gate, so transient UI hold delays are suppressed
/// there to keep invalid-path coverage bounded and independent of display/audio
/// timing.
pub(crate) fn pause(delay: &mut esp_hal::delay::Delay, milliseconds: u32) {
    #[cfg(all(feature = "workflow-test-auto", not(feature = "workflow-runtime-auto")))]
    {
        core::hint::black_box(delay);
        core::hint::black_box(milliseconds);
    }

    #[cfg(any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto"))]
    delay.delay_millis(milliseconds);
}
