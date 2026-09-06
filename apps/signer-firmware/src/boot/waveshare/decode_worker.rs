//! Waveshare second-core QR decode worker startup.

macro_rules! start {
    ($peripherals:ident) => {{
        let qr_ready = $crate::hw::decode_core::init(320 * 240);
        use esp_hal::system::{CpuControl, Stack};
        static APP_CORE_STACK: static_cell::StaticCell<Stack<49152>> =
            static_cell::StaticCell::new();
        let stack = APP_CORE_STACK.init(Stack::new());
        let mut cpu_control = CpuControl::new($peripherals.CPU_CTRL);
        match cpu_control.start_app_core(stack, || $crate::hw::decode_core::core1_main()) {
            Ok(guard) => {
                core::mem::forget(guard);
                $crate::CORE1_OK.store(true, core::sync::atomic::Ordering::Relaxed);
                if qr_ready {
                    log!("   Core 1: QR worker started");
                } else {
                    log!("   Core 1: started; QR buffer unavailable");
                }
            }
            Err(_) => log!("   Core 1: unavailable; QR worker disabled"),
        }
    }};
}

pub(crate) use start;
