use signer_firmware_core::storage::card::{
    CardState, classify_card_state,
};

use super::{Delay, SdCardType};
use super::gpio::{
    SavedDisplayState, func_in_sel_addr, restore_display_state, save_display_state,
};
use super::registers::{
    CMD_CHECK_RESP_CRC, CMD_RESP_EXPECT, SDHOST_CDATA_IN_10, SDHOST_CLK_EN_BIT,
    SYSTEM_PERIP_CLK_EN1, boot_card_type, card_rca, reg_set_bits, reg_write,
    set_boot_card_type, set_card_rca,
};
use super::sdhost::{
    route_pins_to_sdhost, sdhost_init_card, sdhost_send_cmd, sdhost_set_clock,
    sdhost_wait_not_busy,
};

/// Execute a closure with an active SD card connection.
pub fn with_sd_card<F, T>(delay: &mut Delay, f: F) -> Result<T, &'static str>
where
    F: FnOnce(SdCardType) -> Result<T, &'static str>,
{
    boot_card_type().ok_or("No SD card")?;
    let saved = save_display_state();
    let clock_ready = begin_card_session(delay);
    if let Err(error) = ensure_card_selected(delay, clock_ready) {
        restore_display_state(&saved);
        return Err(error);
    }
    let result = run_active_card_session(f);
    finish_card_session(&saved, &result);
    result
}

fn begin_card_session(delay: &mut Delay) -> bool {
    route_pins_to_sdhost();
    unsafe { reg_set_bits(SYSTEM_PERIP_CLK_EN1, SDHOST_CLK_EN_BIT); }
    let clock_ready = sdhost_set_clock(2).is_ok();
    delay.delay_millis(5);
    clock_ready
}

fn run_active_card_session<F, T>(f: F) -> Result<T, &'static str>
where
    F: FnOnce(SdCardType) -> Result<T, &'static str>,
{
    let card_type = boot_card_type().ok_or("No SD card")?;
    crate::hw::sound::start_ticking();
    let result = f(card_type);
    crate::hw::sound::stop_ticking();
    result
}

fn ensure_card_selected(delay: &mut Delay, clock_ready: bool) -> Result<(), &'static str> {
    if try_reselect(clock_ready) {
        return Ok(());
    }
    let card_type = sdhost_init_card(delay)?;
    set_boot_card_type(card_type);
    Ok(())
}

fn try_reselect(clock_ready: bool) -> bool {
    let rca = card_rca();
    if rca == 0 {
        return false;
    }
    if !clock_ready {
        return false;
    }
    let Ok(status) = sdhost_send_cmd(
        13,
        u32::from(rca) << 16,
        CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC,
    ) else {
        return false;
    };
    execute_reselect_action(rca, classify_card_state(status))
}

fn execute_reselect_action(rca: u16, state: CardState) -> bool {
    match state {
        CardState::Standby => select_standby_card(rca),
        CardState::Transfer => true,
        CardState::Other => false,
    }
}

fn select_standby_card(rca: u16) -> bool {
    if sdhost_send_cmd(
        7,
        u32::from(rca) << 16,
        CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC,
    )
    .is_err()
    {
        return false;
    }
    let _ = sdhost_wait_not_busy();
    true
}

fn finish_card_session<T>(
    saved: &SavedDisplayState,
    result: &Result<T, &'static str>,
) {
    let _ = sdhost_send_cmd(7, 0, CMD_RESP_EXPECT);
    set_card_rca(0);
    unsafe { reg_write(func_in_sel_addr(SDHOST_CDATA_IN_10), 0xBC); }
    restore_display_state(saved);
    if result.is_ok() {
        crate::hw::sound::task_done();
    }
}
