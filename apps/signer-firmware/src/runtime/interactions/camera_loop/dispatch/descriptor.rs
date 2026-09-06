//! Multisig descriptor QR import (`multi_hd45` and legacy `multi_hd`).

use super::super::{sound, AppData};

pub(super) fn matches(data: &[u8], len: usize) -> bool {
    let payload = &data[..len.min(data.len())];
    payload.starts_with(b"multi_hd45(") || payload.starts_with(b"multi_hd(")
}

pub(super) fn process(
    data: &[u8],
    len: usize,
    ad: &mut AppData,
    checkpoint: &mut (impl FnMut() + ?Sized),
) {
    let payload = &data[..len.min(data.len())];
    let Ok(parsed) = kassigner_protocol::wire::multisig_descriptor::parse_multisig_descriptor(payload) else {
        sound::error();
        return;
    };
    crate::runtime::interactions::multisig_config::install_descriptor_and_resolve(ad, &parsed, true, checkpoint);
    if let Some(slot) = ad.signing.multisig.store.find_free() {
        ad.signing.multisig.store.configs[slot] = ad.signing.multisig.creating.clone();
    }
    log!("   → multisig descriptor QR imported ({}-of-{}, v45={})",
        parsed.threshold, parsed.participant_count, parsed.v45);
    sound::qr_decoded();
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigDescriptor));
    crate::runtime::effects::redraw(ad);
}
