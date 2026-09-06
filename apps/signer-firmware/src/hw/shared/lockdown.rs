// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! ESP32-S3 radio, USB, and JTAG lockdown.
//!
//! The wireless digital power domain and modem clocks are disabled immediately
//! after HAL initialization on every supported board. The hardware RNG clock is
//! retained because it shares the modem clock register.

const SYSTEM_PERIP_CLK_EN0: u32 = 0x600C_0018;
#[cfg(feature = "production")]
const SYSTEM_PERIP_CLK_EN1: u32 = 0x600C_001C;
const SYSTEM_PERIP_RST_EN0: u32 = 0x600C_0020;
#[cfg(feature = "production")]
const SYSTEM_PERIP_RST_EN1: u32 = 0x600C_0024;

// ESP32-S3 APB_CTRL::wifi_clk_en (APB_CTRL base + 0x14).
const APB_CTRL_WIFI_CLK_EN: u32 = 0x6002_6014;
const APB_CTRL_WIFI_CLK_RNG_EN: u32 = 1 << 15;
// ESP32-S3 SYSTEM::bt_lpck_div_frac.
const SYSTEM_BT_LPCK_DIV_FRAC: u32 = 0x600C_002C;

// ESP32-S3 RTC_CNTL_DIG_PWC_REG.
const RTC_CNTL_DIG_PWC: u32 = 0x6000_8090;
const RTC_CNTL_WIFI_FORCE_PD: u32 = 1 << 17;
const RTC_CNTL_WIFI_FORCE_PU: u32 = 1 << 18;

const USB_CLK_EN: u32 = 1 << 23;
#[cfg(feature = "production")]
const USB_DEVICE_CLK_EN: u32 = 1 << 10;
#[cfg(not(any(feature = "hardware-tests", feature = "workflow-test-auto")))]
const USB_SERIAL_JTAG_CONF0: u32 = 0x6003_8044;

use super::mmio::{clear_bits, read, set_bits, write};

/// Disable modem clocks, power down the wireless digital domain, and disable
/// USB OTG. Returns `false` if register read-back does not confirm the policy.
pub fn early_lockdown() -> bool {
    unsafe {
        let wifi_clock = read(APB_CTRL_WIFI_CLK_EN);
        write(
            APB_CTRL_WIFI_CLK_EN,
            wifi_clock & APB_CTRL_WIFI_CLK_RNG_EN,
        );
        write(SYSTEM_BT_LPCK_DIV_FRAC, 0);

        let power = read(RTC_CNTL_DIG_PWC);
        write(
            RTC_CNTL_DIG_PWC,
            (power & !RTC_CNTL_WIFI_FORCE_PU) | RTC_CNTL_WIFI_FORCE_PD,
        );

        clear_bits(SYSTEM_PERIP_CLK_EN0, USB_CLK_EN);
        set_bits(SYSTEM_PERIP_RST_EN0, USB_CLK_EN);
    }

    let verified = radio_power_is_off();
    let power = unsafe { read(RTC_CNTL_DIG_PWC) };
    log!(
        "   [SEC] wireless lockdown: verified={} DIG_PWC=0x{:08X} FORCE_PD={} FORCE_PU={}",
        verified,
        power,
        (power & RTC_CNTL_WIFI_FORCE_PD) != 0,
        (power & RTC_CNTL_WIFI_FORCE_PU) != 0,
    );
    verified
}

/// Verify the exact security properties controlled by `early_lockdown`.
///
/// The hardware RNG clock may remain enabled. Every other modem clock must be
/// gated, the Bluetooth low-power divider must be zero, and the wireless
/// digital power domain must be forced down rather than forced up.
pub fn radio_power_is_off() -> bool {
    unsafe {
        let wifi_clock = read(APB_CTRL_WIFI_CLK_EN);
        let power = read(RTC_CNTL_DIG_PWC);
        let bt_clock = read(SYSTEM_BT_LPCK_DIV_FRAC);
        let usb_clock = read(SYSTEM_PERIP_CLK_EN0);
        let usb_reset = read(SYSTEM_PERIP_RST_EN0);

        (wifi_clock & !APB_CTRL_WIFI_CLK_RNG_EN) == 0
            && bt_clock == 0
            && (power & RTC_CNTL_WIFI_FORCE_PD) != 0
            && (power & RTC_CNTL_WIFI_FORCE_PU) == 0
            && (usb_clock & USB_CLK_EN) == 0
            && (usb_reset & USB_CLK_EN) != 0
    }
}

/// Disable the USB/JTAG bridge after firmware verification.
#[cfg(not(any(feature = "hardware-tests", feature = "workflow-test-auto")))]
pub fn post_boot_lockdown() {
    unsafe {
        let conf0 = read(USB_SERIAL_JTAG_CONF0);
        write(USB_SERIAL_JTAG_CONF0, conf0 & !(0x3 << 3));

        #[cfg(feature = "production")]
        {
            clear_bits(SYSTEM_PERIP_CLK_EN1, USB_DEVICE_CLK_EN);
            set_bits(SYSTEM_PERIP_RST_EN1, USB_DEVICE_CLK_EN);
        }
    }

    #[cfg(feature = "production")]
    log!("   [SEC] USB Serial/JTAG disabled (production)");

    #[cfg(not(feature = "production"))]
    log!("   [SEC] JTAG disabled (USB UART kept for development)");
}
