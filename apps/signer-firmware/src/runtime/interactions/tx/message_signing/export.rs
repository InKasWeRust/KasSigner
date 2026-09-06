use crate::runtime::data::AppData;

pub(super) fn begin_sd_export(
    ad: &mut AppData,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
) {
    let next = crate::runtime::interactions::sd::scan_auto_increment(i2c, delay, b"SG", b"TXT");
    let name = crate::runtime::interactions::sd::format_auto_name(b"SG", next, b"TXT");
    ad.storage.export_file.filename = name;
    ad.wallet.seeds.pp_input.reset();
    for byte in name.into_iter().filter(|byte| *byte != b' ') {
        ad.wallet.seeds.pp_input.push_char(byte);
    }
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdSigFilename));
}
