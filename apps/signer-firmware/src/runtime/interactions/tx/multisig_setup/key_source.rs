use crate::runtime::interactions::feedback::{show_rejection, ErrorSound};
use crate::{
    runtime::data::AppData,
    hw::display,
};

pub(super) fn handle(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    key_idx: u8,
    x: u16,
    y: u16,
    is_back: bool,
) -> bool {
    if is_back {
        return go_back(ad, key_idx);
    }

    if (30..=290).contains(&x) && (90..=135).contains(&y) {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ScanQR));
        return true;
    }

    if !(30..=290).contains(&x) || !(145..=190).contains(&y) {
        return false;
    }

    if super::seed_picker::has_wallet_choice(ad) {
        ad.signing.multisig.scroll = 0;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigPickSeed { key_idx }));
    } else {
        show_rejection(boot_display, delay, "No wallet slots available", 1500, ErrorSound::Silent);
    }
    true
}

fn go_back(ad: &mut AppData, key_idx: u8) -> bool {
    if key_idx == 0 {
        ad.wallet.seeds.clear_multisig_wallet_return();
        ad.signing.multisig.creating.n = 0;
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigChooseMN));
    } else {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigAddKey {
            key_idx: key_idx - 1,
        }));
    }
    true
}
