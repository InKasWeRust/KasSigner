use super::super::super::{AppData, display, parse_descriptor};
use crate::runtime::interactions::feedback::{show_rejection, show_success, ErrorSound};
use crate::runtime::{data::{EncryptedPayloadKind, TextFileKind}, navigation::ContinuationRoute};

pub(super) fn route(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    kind: EncryptedPayloadKind,
    failure_state: ContinuationRoute,
    plaintext: &[u8],
) {
    match kind {
        EncryptedPayloadKind::Text(TextFileKind::MultisigDescriptor) => {
            load_descriptor_only(ad, boot_display, delay, liveness, plaintext, failure_state)
        }
        EncryptedPayloadKind::Text(TextFileKind::Kpub) => {
            load_kpub_only(ad, boot_display, delay, plaintext, failure_state)
        }
        EncryptedPayloadKind::Text(TextFileKind::MultisigAddress) => {
            load_address_only(ad, boot_display, delay, plaintext, failure_state)
        }
        EncryptedPayloadKind::Transaction => {
            route_transaction_import(ad, boot_display, delay, liveness, plaintext)
        }
    }
}

fn route_transaction_import(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    plaintext: &[u8],
) {
    if is_descriptor(plaintext) {
        load_descriptor_only(ad, boot_display, delay, liveness, plaintext, crate::runtime::navigation::continuation!(SdKsptFileList));
    } else if is_address(plaintext) {
        store_address(ad, plaintext);
        complete_success(ad, boot_display, delay, "Address loaded!", crate::runtime::navigation::continuation!(MultisigShowAddress));
    } else if plaintext.starts_with(kassigner_protocol::wire::pskt_envelope::PSKT_MAGIC) {
        crate::runtime::interactions::tx::load_standard_transaction_with_checkpoint(plaintext, ad, liveness);
    } else {
        crate::runtime::interactions::tx::load_compact_transaction_with_checkpoint(plaintext, ad, liveness);
    }
}

fn load_descriptor_only(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    liveness: &mut dyn FnMut(),
    plaintext: &[u8],
    failure_state: ContinuationRoute,
) {
    if !is_descriptor(plaintext) {
        failure(ad, boot_display, delay, "Not a descriptor", failure_state);
        return;
    }
    let Some(descriptor) = parse_descriptor(plaintext) else {
        failure(ad, boot_display, delay, "Bad descriptor", failure_state);
        return;
    };

    crate::runtime::interactions::multisig_config::install_descriptor_and_resolve(ad, &descriptor, false, liveness);
    complete_success(
        ad,
        boot_display,
        delay,
        "Descriptor loaded!",
        crate::runtime::navigation::continuation!(MultisigDescriptor),
    );
}

fn load_kpub_only(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    plaintext: &[u8],
    failure_state: ContinuationRoute,
) {
    let mut canonical = [0u8; offline_signer::derivation::xpub::KPUB_MAX_LEN];
    let Ok(length) =
        offline_signer::derivation::xpub::normalize_kpub_text(plaintext, &mut canonical)
    else {
        failure(
            ad,
            boot_display,
            delay,
            "Not a valid kpub",
            failure_state,
        );
        return;
    };

    ad.export.kpub_data[..length].copy_from_slice(&canonical[..length]);
    ad.export.kpub_len = length;
    complete_success(
        ad,
        boot_display,
        delay,
        "Kpub loaded!",
        crate::runtime::navigation::continuation!(ExportKpub),
    );
}

fn load_address_only(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    plaintext: &[u8],
    failure_state: ContinuationRoute,
) {
    if !is_address(plaintext) || plaintext.len() > offline_signer::derivation::xpub::KPUB_MAX_LEN {
        failure(
            ad,
            boot_display,
            delay,
            "Not a valid address",
            failure_state,
        );
        return;
    }
    store_address(ad, plaintext);
    complete_success(
        ad,
        boot_display,
        delay,
        "Address loaded!",
        crate::runtime::navigation::continuation!(MultisigShowAddress),
    );
}

fn store_address(ad: &mut AppData, plaintext: &[u8]) {
    ad.export.kpub_data[..plaintext.len()].copy_from_slice(plaintext);
    ad.export.kpub_len = plaintext.len();
    ad.signing.multisig.creating.active = false;
}

fn is_descriptor(plaintext: &[u8]) -> bool {
    plaintext.starts_with(b"multi_hd45(") || plaintext.starts_with(b"multi_hd(")
}

fn is_address(plaintext: &[u8]) -> bool {
    plaintext.starts_with(b"kaspa:") || plaintext.starts_with(b"kaspatest:")
}

fn complete_success(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    message: &str,
    next_state: ContinuationRoute,
) {
    show_success(boot_display, delay, message, 1_000);
    crate::runtime::effects::continue_to(ad, next_state);
}

fn failure(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    message: &str,
    next_state: ContinuationRoute,
) {
    show_rejection(boot_display, delay, message, 2_000, ErrorSound::Silent);
    crate::runtime::effects::continue_to(ad, next_state);
}
