use crate::{hw::display, runtime::data::AppData};

pub(crate) fn process_seed_payload(data: &[u8], compact: bool, ad: &mut AppData) {
    super::dispatch::workflow_process_seed_payload(data, compact, ad);
}

pub(crate) fn process_transaction_payload(
    data: &[u8],
    standard_pskt: bool,
    ad: &mut AppData,
) {
    super::dispatch::workflow_process_transaction_payload(data, standard_pskt, ad);
}

pub(crate) fn process_pending_payload(data: &[u8], ad: &mut AppData) -> bool {
    super::dispatch::workflow_process_pending_payload(data, ad)
}

pub(crate) fn process_anti_klepto_payload(data: &[u8], ad: &mut AppData) {
    super::dispatch::workflow_process_anti_klepto_payload(data, ad);
}

pub(crate) fn process_multiframe(
    session: &mut super::CameraSessionState,
    data: &[u8],
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) {
    let mut no_checkpoint = || {};
    super::multiframe::process_multiframe(
        session, data, data.len(), ad, boot_display, delay, i2c, &mut no_checkpoint,
    );
}


pub(crate) fn validate_stealth_request(
    data: &[u8],
    length: usize,
) -> Result<usize, &'static str> {
    super::dispatch::workflow_validate_stealth_request(data, length)
}
