use super::{
    Delay, SdCardType, route_pins_to_sdhost, sdhost_enable_peripheral,
    sdhost_init_card, sdhost_send_cmd,
};
use super::super::gpio::{func_in_sel_addr, gpio_clear, gpio_set, restore_display_state, save_display_state};
use super::super::registers::{
    CMD_RESP_EXPECT, PIN_MOSI, PIN_SCK, PIN_SD_CS, SDHOST_CDATA_IN_10,
    reg_write, set_boot_card_type, set_card_rca,
};
// ═══════════════════════════════════════════════════════════════
// Boot-time SD init (called from main.rs BEFORE display)
// ═══════════════════════════════════════════════════════════════

/// Pre-SPI power-up sequence. On Waveshare there's no PMU,
/// so this just sets GPIO levels to avoid glitching the card
/// into native mode before we're ready.
pub fn sd_pre_init() {
    // Set all SD pins HIGH (idle) before esp-hal claims GPIO38/39
    gpio_set(PIN_SD_CS);
    gpio_set(PIN_MOSI);
    gpio_clear(PIN_SCK);
}

/// Send 80+ clocks with CS(D3) HIGH, CMD HIGH — SD spec power-up requirement.
/// Uses bitbang since SDHOST isn't set up yet.
pub fn sd_power_up_clocks() {
    gpio_set(PIN_SD_CS);
    gpio_set(PIN_MOSI);
    for _ in 0..200u32 {
        gpio_clear(PIN_SCK);
        for _ in 0..50u32 { unsafe { core::ptr::read_volatile(&0u32 as *const u32); } }
        gpio_set(PIN_SCK);
        for _ in 0..50u32 { unsafe { core::ptr::read_volatile(&0u32 as *const u32); } }
    }
    gpio_clear(PIN_SCK);
}

/// Post-display SD card init via SDHOST controller.
/// Saves display GPIO state, routes to SDHOST, initializes card,
/// then restores display routing.
pub fn init_sdhost(delay: &mut Delay) -> Result<SdCardType, &'static str> {
    log!("[SDHOST] Post-display SD init...");

    let saved = save_display_state();

    sdhost_enable_peripheral();
    route_pins_to_sdhost();

    let result = sdhost_init_card(delay);

    // After CMD7 SELECT_CARD, the card drives D0 (GPIO40) for busy signaling.
    // On the eFuse board, the card holding D0 during restore_display_state
    // corrupts the ST7789T3 MADCTL register.
    // Fix: deselect card so it releases D0, disconnect SDHOST D0 input signal.
    if result.is_ok() {
        let _ = sdhost_send_cmd(7, 0, CMD_RESP_EXPECT); // deselect
        set_card_rca(0);
        // Disconnect SDHOST data input from GPIO40 so card can't drive it
        unsafe {
            reg_write(func_in_sel_addr(SDHOST_CDATA_IN_10), 0xBC); // constant LOW
        }
    }

    restore_display_state(&saved);

    match result {
        Ok(ct) => {
            set_boot_card_type(ct);
            Ok(ct)
        }
        Err(e) => Err(e),
    }
}
