use signer_firmware_core::storage::{
    card::{classify_card_kind, map_card_kind},
    retry::poll_ready_response,
};
use super::capacity::capture_sector_count;

use super::{
    Delay, SdCardType, sdhost_reset, sdhost_send_cmd, sdhost_set_clock,
    sdhost_wait_not_busy,
};
use super::super::registers::{
    CMD_CHECK_RESP_CRC, CMD_RESP_EXPECT, CMD_RESP_LONG, CMD_SEND_INIT,
    CTRL_INT_ENABLE, SDHOST_BLKSIZ, SDHOST_BYTCNT, SDHOST_CTRL, SDHOST_CTYPE,
    SDHOST_DEBNCE, SDHOST_FIFOTH, SDHOST_INTMASK, SDHOST_RINTSTS, SDHOST_RST_N,
    SDHOST_TMOUT, SDHOST_VERID, reg_read, reg_write, set_card_rca,
};

/// Full SD card initialization using SDHOST in native SD mode.
pub(crate) fn sdhost_init_card(delay: &mut Delay) -> Result<SdCardType, &'static str> {
    log!("[SDHOST] Initializing...");
    let (sd_v2, ocr) = begin_initialization(delay)?;
    let card_type = map_card_kind(
        classify_card_kind(sd_v2, ocr),
        SdCardType::SdV1,
        SdCardType::SdV2Sc,
        SdCardType::SdV2Hc,
    );
    identify_and_select_card()?;
    configure_transfer_mode()?;
    log!("[SDHOST] SD card init complete: {:?}", card_type);
    Ok(card_type)
}

fn begin_initialization(delay: &mut Delay) -> Result<(bool, u32), &'static str> {
    configure_controller(delay)?;
    reset_card_to_idle(delay);
    let sd_v2 = detect_sd_v2();
    let ocr = wait_for_operating_condition(delay, sd_v2)?;
    Ok((sd_v2, ocr))
}

fn configure_controller(delay: &mut Delay) -> Result<(), &'static str> {
    let version = unsafe { reg_read(SDHOST_VERID) };
    log!("[SDHOST] VERID=0x{:08x}", version);
    sdhost_reset();
    unsafe {
        reg_write(SDHOST_CTYPE, 0x0000_0000);
        reg_write(SDHOST_BLKSIZ, 512);
        reg_write(SDHOST_BYTCNT, 512);
        reg_write(SDHOST_TMOUT, 0xFFFF_FF40);
        reg_write(SDHOST_INTMASK, 0);
        reg_write(SDHOST_FIFOTH, 1 << 16);
        reg_write(SDHOST_CTRL, CTRL_INT_ENABLE);
        reg_write(SDHOST_RST_N, 0x01);
        reg_write(SDHOST_DEBNCE, 0x00FF_FFFF);
    }
    sdhost_set_clock(100)?;
    delay.delay_millis(50);
    Ok(())
}

fn reset_card_to_idle(delay: &mut Delay) {
    let _ = sdhost_send_cmd(0, 0, CMD_SEND_INIT);
    clear_interrupts();
    delay.delay_millis(10);
    let _ = sdhost_send_cmd(0, 0, 0);
    clear_interrupts();
    delay.delay_millis(10);
}

fn clear_interrupts() {
    unsafe { reg_write(SDHOST_RINTSTS, 0xFFFF_FFFF); }
}

fn detect_sd_v2() -> bool {
    sdhost_send_cmd(8, 0x0000_01AA, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC)
        .map(|response| response & 0x0fff == 0x01aa)
        .unwrap_or(false)
}

fn wait_for_operating_condition(
    delay: &mut Delay,
    sd_v2: bool,
) -> Result<u32, &'static str> {
    let hcs = if sd_v2 { 1u32 << 30 } else { 0 };
    poll_ready_response(
        200,
        || {
            let _ = sdhost_send_cmd(55, 0, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC);
            sdhost_send_cmd(41, 0x00FF_8000 | hcs, CMD_RESP_EXPECT).ok()
        },
        || delay.delay_millis(10),
    )
    .ok_or("ACMD41 timeout")
}

fn identify_and_select_card() -> Result<(), &'static str> {
    let rca = identify_card()?;
    select_card(rca)
}

fn identify_card() -> Result<u16, &'static str> {
    sdhost_send_cmd(2, 0, CMD_RESP_EXPECT | CMD_RESP_LONG | CMD_CHECK_RESP_CRC)?;
    let rca = assign_relative_address()?;
    capture_sector_count(rca)?;
    Ok(rca)
}

fn assign_relative_address() -> Result<u16, &'static str> {
    let response = sdhost_send_cmd(3, 0, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC)?;
    let rca = (response >> 16) as u16;
    set_card_rca(rca);
    Ok(rca)
}

fn select_card(rca: u16) -> Result<(), &'static str> {
    sdhost_send_cmd(
        7,
        u32::from(rca) << 16,
        CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC,
    )?;
    sdhost_wait_not_busy()
}

fn configure_transfer_mode() -> Result<(), &'static str> {
    sdhost_send_cmd(16, 512, CMD_RESP_EXPECT | CMD_CHECK_RESP_CRC)?;
    sdhost_set_clock(2)?;
    log!("[SDHOST] Clock set to 20MHz for data transfers");
    Ok(())
}
