use super::{commit_recovery, AppData, BackupDevice, display, stego, zeroize_bytes};

pub(crate) fn workflow_open_payload(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    backup_device: &mut dyn BackupDevice,
    carrier: stego::StegoCarrier,
    payload: &[u8],
    descriptor: &[u8],
    portable_password: Option<&[u8]>,
) -> bool {
    if !stage(ad, carrier, payload, descriptor) {
        return false;
    }
    let mut indices = [0u16; 24];
    let mut hint = [0u8; 64];
    let result = match portable_password {
        Some(password) => stego::unpack_portable_payload(
            carrier,
            payload,
            descriptor,
            password,
            &mut indices,
            &mut hint,
        ),
        None => stego::unpack_device_bound_payload(
            carrier,
            payload,
            descriptor,
            backup_device,
            &mut indices,
            &mut hint,
        ),
    };
    commit_recovery(ad, boot_display, delay, carrier, result, &mut indices, &mut hint)
}

pub(crate) fn workflow_stage_portable_payload(
    ad: &mut AppData,
    carrier: stego::StegoCarrier,
    payload: &[u8],
    descriptor: &[u8],
) -> bool {
    if !stage(ad, carrier, payload, descriptor) {
        return false;
    }
    ad.stego.session.portable.clear();
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StegoImportPortablePassword));
    true
}

fn stage(
    ad: &mut AppData,
    carrier: stego::StegoCarrier,
    payload: &[u8],
    descriptor: &[u8],
) -> bool {
    if descriptor.is_empty()
        || descriptor.len() > ad.stego.import.descriptor_buf.len()
        || payload.len() != stego::STEGO_PAYLOAD_SIZE
    {
        return false;
    }
    ad.stego.import.clear_descriptor();
    ad.stego.import.descriptor_buf[..descriptor.len()].copy_from_slice(descriptor);
    ad.stego.import.descriptor_len = descriptor.len();
    zeroize_bytes(&mut ad.stego.import.embedded_payload);
    ad.stego.import.embedded_payload[..payload.len()].copy_from_slice(payload);
    ad.stego.import.embedded_payload_len = payload.len();
    ad.stego.import.carrier = Some(carrier);
    true
}
