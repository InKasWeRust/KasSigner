//! Dedicated Core1 stack for Connect KasSee account derivation on CoreS3.

#[cfg(not(feature = "hardware-tests"))]
#[cfg(any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto"))]
macro_rules! start {
    ($peripherals:ident) => {{
        use esp_hal::system::{CpuControl, Stack};
        static KPUB_CORE_STACK: static_cell::StaticCell<Stack<49152>> =
            static_cell::StaticCell::new();
        let stack = KPUB_CORE_STACK.init(Stack::new());
        let mut cpu_control = CpuControl::new($peripherals.CPU_CTRL);
        match cpu_control.start_app_core(stack, || {
            $crate::services::wallet_keys::worker::core1_main()
        }) {
            Ok(guard) => {
                core::mem::forget(guard);
                $crate::services::wallet_keys::worker::mark_ready();
                $crate::log!("   Core 1: derivation worker started (48KB stack)");
            }
            Err(_) => {
                $crate::log!("   Core 1: derivation worker unavailable");
            }
        }
    }};
}

#[cfg(not(feature = "hardware-tests"))]
#[cfg(any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto"))]
pub(crate) use start;
