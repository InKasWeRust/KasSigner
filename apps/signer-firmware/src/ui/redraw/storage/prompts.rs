use super::{AppData, BootDisplay};
use crate::runtime::input::AppState;

pub(super) fn redraw(ad: &AppData, display: &mut BootDisplay<'_>) -> bool {
    match ad.navigation.app.state {
        AppState::SdSeedExportPassphrase
        | AppState::SdXprvExportPassphrase
        | AppState::SdWalletBackupImportPassphrase
        | AppState::SdKsptEncryptPass => {
            display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "PASSWORD");
        }
        AppState::SdDeleteConfirm => display.draw_sd_delete_confirm(&ad.storage.browser.selected_file),
        AppState::CovBackupName => display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "COV NAME"),
        AppState::SdKsptFilename => display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "FILENAME"),
        AppState::SdKpubFilename => display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "KPUB FILENAME"),
        AppState::SdSigFilename => display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "SIG FILENAME"),
        AppState::SdSeedFilename => display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "SEED FILENAME"),
        AppState::SdXprvFilename => display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "XPRV FILENAME"),
        AppState::SdMsAddrFilename => display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "ADDRESS FILENAME"),
        AppState::SdMsDescFilename => display.draw_keyboard_screen_full(&ad.wallet.seeds.pp_input, "DESC FILENAME"),
        AppState::SdMsAddrEncryptAsk
        | AppState::SdMsDescEncryptAsk
        | AppState::SdKsptEncryptAsk
        | AppState::SdKpubEncryptAsk => display.draw_kspt_encrypt_ask(),
        AppState::SdBackupWarning => display.draw_yes_no_ask(
            "DEVICE-BOUND BACKUP",
            "Encrypted with password + this",
            "KasSigner's eFuse key. Continue?",
        ),
        AppState::SdOverwriteWarning => draw_overwrite_warning(ad, display),
        _ => return false,
    }
    true
}

fn draw_overwrite_warning(ad: &AppData, display: &mut BootDisplay<'_>) {
    let length = ad.storage.export_file.overwrite_prompt_len as usize;
    let prompt = core::str::from_utf8(&ad.storage.export_file.overwrite_prompt[..length])
        .unwrap_or("Overwrite?");
    display.draw_yes_no_ask("FILE EXISTS", prompt, "");
}
