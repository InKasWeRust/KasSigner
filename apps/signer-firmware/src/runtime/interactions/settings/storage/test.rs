use crate::{
    hw::display,
    services::{audio as sound, storage_device as sdcard},
};

const TEST_DATA: &[u8] = b"KasSigner SD test 1234567890ABCDEF";

pub(super) fn run(
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) {
    let _ = &mut *i2c;
    boot_display.draw_sdcard_testing();
    let result = sdcard::with_sd_card!(i2c, delay, verify_card);
    match result {
        Ok((bytes, files)) => show_success(boot_display, bytes, files),
        Err(error) => show_failure(boot_display, error),
    }
    crate::services::timing::pause(delay, 5000);
}

fn verify_card(card_type: sdcard::SdCardType) -> Result<(usize, u32), &'static str> {
    let fat32 = sdcard::mount_fat32(card_type)?;
    let filename = sdcard::to_83_name(b"TEST.TXT");
    let _ = sdcard::delete_file(card_type, &fat32, &filename);
    sdcard::create_file(card_type, &fat32, &filename, TEST_DATA)?;
    let (entry, _, _) = sdcard::find_file_in_root(card_type, &fat32, &filename)?;
    if entry.file_size != TEST_DATA.len() as u32 {
        return Err("Size mismatch");
    }

    let mut readback = [0u8; 512];
    let bytes_read = sdcard::read_file(card_type, &fat32, &entry, &mut readback)?;
    if bytes_read != TEST_DATA.len() {
        return Err("Read size mismatch");
    }
    if &readback[..TEST_DATA.len()] != TEST_DATA {
        return Err("Data mismatch");
    }

    let mut file_count = 0u32;
    sdcard::list_root_dir(card_type, &fat32, |_| {
        file_count += 1;
        true
    })?;
    sdcard::delete_file(card_type, &fat32, &filename)?;
    Ok((bytes_read, file_count))
}

fn show_success(
    boot_display: &mut display::BootDisplay<'_>,
    bytes: usize,
    files: u32,
) {
    log!(
        "[SD-TEST] PASS: {}/{} bytes, {} files",
        bytes,
        TEST_DATA.len(),
        files
    );
    let mut first = [0u8; 40];
    let mut second = [0u8; 40];
    let write_line = format_test_line(&mut first, "Write+Read: ", bytes as u32, " bytes OK");
    let root_line = format_test_line(&mut second, "Root dir: ", files, " files");
    boot_display.draw_sdcard_test_result(&[write_line, root_line, "Data verify: match"], true);
    sound::success();
}

fn show_failure(
    boot_display: &mut display::BootDisplay<'_>,
    error: &'static str,
) {
    log!("[SD-TEST] FAIL: {}", error);
    boot_display.draw_sdcard_test_result(&["SD card test failed:", error], false);
    sound::error();
}

fn format_test_line<'a>(
    buffer: &'a mut [u8; 40],
    prefix: &str,
    value: u32,
    suffix: &str,
) -> &'a str {
    let mut position = 0usize;
    for byte in prefix.bytes() {
        if position < buffer.len() {
            buffer[position] = byte;
            position += 1;
        }
    }
    let mut digits = [0u8; 10];
    let mut remaining = value;
    let mut count = 0usize;
    if remaining == 0 {
        digits[0] = b'0';
        count = 1;
    } else {
        while remaining > 0 {
            digits[count] = b'0' + (remaining % 10) as u8;
            remaining /= 10;
            count += 1;
        }
        digits[..count].reverse();
    }
    for byte in digits[..count].iter().copied().chain(suffix.bytes()) {
        if position < buffer.len() {
            buffer[position] = byte;
            position += 1;
        }
    }
    core::str::from_utf8(&buffer[..position]).unwrap_or("?")
}
