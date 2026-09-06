//! CoreS3 runtime liveness and reset-recovery ownership.
//!
//! The TIMG0 watchdog is armed only after startup policy and the first UI
//! redraw complete. Only the completed outer event-loop iteration owns the feed capability
//! for ordinary runtime work. Seed generation receives narrowly-scoped checkpoints after
//! completed bounded camera-health windows. Credential Argon2 uses the 90-second budget around
//! one foreground-exclusive KDF; the fixed 2 MiB profile is hardware-qualified below that bound.

use core::sync::atomic::{AtomicU32, Ordering};

const DEFAULT_WATCHDOG_MS: u32 = 30_000;
const CREDENTIAL_WATCHDOG_MS: u32 = 90_000;
static REQUESTED_WATCHDOG_MS: AtomicU32 = AtomicU32::new(DEFAULT_WATCHDOG_MS);

pub(crate) fn enter_credential_watchdog_budget() {
    REQUESTED_WATCHDOG_MS.store(CREDENTIAL_WATCHDOG_MS, Ordering::Release);
}

pub(crate) fn leave_credential_watchdog_budget() {
    REQUESTED_WATCHDOG_MS.store(DEFAULT_WATCHDOG_MS, Ordering::Release);
}


#[inline]
pub(crate) fn requested_watchdog_ms() -> u32 {
    REQUESTED_WATCHDOG_MS.load(Ordering::Acquire)
}

#[cfg(all(feature = "m5stack", any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto")))]
macro_rules! watchdog_feed {
    ($timg0:expr) => {{
        use esp_hal::{
            time::Duration,
            timer::timg::{MwdtStage, TimerGroup},
        };
        // Keep TIMG0 inert during persistent-startup policy and the first UI
        // redraw. The returned closure arms the runtime watchdog on its first
        // acknowledgement, after startup has reached a bounded UI state.
        let mut timer_group = Some(TimerGroup::new($timg0));
        let mut runtime_watchdog = None;
        let mut applied_timeout_ms = 0u32;
        move || {
            if let Some(group) = timer_group.take() {
                let mut watchdog = group.wdt;
                let timeout_ms = $crate::runtime::core_s3::requested_watchdog_ms();
                watchdog.set_timeout(MwdtStage::Stage0, Duration::from_millis(u64::from(timeout_ms)));
                applied_timeout_ms = timeout_ms;
                watchdog.enable();
                watchdog.feed();
                $crate::log!("   CoreS3 runtime watchdog: {}ms", timeout_ms);
                runtime_watchdog = Some(watchdog);
                return;
            }
            if let Some(watchdog) = runtime_watchdog.as_mut() {
                let timeout_ms = $crate::runtime::core_s3::requested_watchdog_ms();
                if timeout_ms != applied_timeout_ms {
                    watchdog.set_timeout(MwdtStage::Stage0, Duration::from_millis(u64::from(timeout_ms)));
                    applied_timeout_ms = timeout_ms;
                    $crate::log!("   CoreS3 runtime watchdog budget: {}ms", timeout_ms);
                }
                watchdog.feed();
            }
        }
    }};
}

#[cfg(all(feature = "m5stack", any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto")))]
pub(crate) use watchdog_feed;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RecoveryNotice {
    pub(crate) code: &'static str,
    pub(crate) title: &'static str,
    pub(crate) detail: &'static str,
}

/// Classify the previous CoreS3 reset. Normal power-on/deep-sleep boot does not
/// interrupt startup; watchdog/power/security resets produce a visible notice.
pub(crate) fn recovery_notice() -> Option<RecoveryNotice> {
    use esp_hal::rtc_cntl::SocResetReason;
    let reason = esp_hal::system::reset_reason()?;
    crate::log!("   CoreS3 previous reset reason: {:?}", reason);
    match reason {
        SocResetReason::ChipPowerOn
        | SocResetReason::CoreDeepSleep
        | SocResetReason::CoreSw
        | SocResetReason::CpuSw => None,
        SocResetReason::CoreMwdt0
        | SocResetReason::CoreMwdt1
        | SocResetReason::CoreRtcWdt
        | SocResetReason::CpuMwdt0
        | SocResetReason::CpuMwdt1
        | SocResetReason::CpuRtcWdt
        | SocResetReason::SysRtcWdt
        | SocResetReason::SysSuperWdt => Some(RecoveryNotice {
            code: "SYS-WDT-01",
            title: "SYSTEM RECOVERED",
            detail: "Previous session stopped responding",
        }),
        SocResetReason::SysBrownOut | SocResetReason::CorePwrGlitch => Some(RecoveryNotice {
            code: "SYS-PWR-01",
            title: "POWER RESET",
            detail: "Power became unstable",
        }),
        SocResetReason::CoreEfuseCrc => Some(RecoveryNotice {
            code: "SYS-EFUSE-01",
            title: "SECURITY RESET",
            detail: "eFuse integrity reset detected",
        }),
        _ => Some(RecoveryNotice {
            code: "SYS-RST-01",
            title: "SYSTEM RESTARTED",
            detail: "Unexpected reset detected",
        }),
    }
}

pub(crate) fn show_recovery_notice(
    display: &mut crate::hw::display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
) {
    let Some(notice) = recovery_notice() else { return; };
    display.draw_system_recovery_screen(notice.title, notice.detail, notice.code);
    delay.delay_millis(2_500);
}
