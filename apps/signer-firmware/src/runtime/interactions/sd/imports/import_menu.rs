use super::super::common::context::SdImportMenuContext;
// SD controller workflow: import menu.
use super::super::{AppData, ImportScanRule, display, scan_by_rule};
use crate::runtime::interactions::menu_selection::{handle_paged_menu_touch, PagedMenuAction};
use crate::runtime::data::TextFileKind;
use signer_firmware_core::storage::routing::{import_scan_plan, ImportScanPlan};
const WALLET_BACKUP_RULE: ImportScanRule = ImportScanRule {
    extensions: &[*b"KAS"],
    max_size: crate::services::backup::MAX_XPRV_BACKUP_SIZE as u32,
    exclude_hidden: true,
    next_state: crate::runtime::navigation::continuation!(SdWalletBackupFileList),
    empty_message: "No current .KAS backups found",
    text_import_kind: None,
};
const TRANSACTION_RULE: ImportScanRule = ImportScanRule {
    extensions: &[*b"KSP"],
    max_size: 1024,
    exclude_hidden: true,
    next_state: crate::runtime::navigation::continuation!(SdKsptFileList),
    empty_message: "No .KSP files found",
    text_import_kind: None,
};
const KPUB_RULE: ImportScanRule = ImportScanRule {
    extensions: &[*b"TXT"],
    max_size: 1024,
    exclude_hidden: true,
    next_state: crate::runtime::navigation::continuation!(SdKpubFileList),
    empty_message: "No .TXT files found",
    text_import_kind: Some(TextFileKind::Kpub),
};
const MULTISIG_ADDRESS_RULE: ImportScanRule = ImportScanRule {
    text_import_kind: Some(TextFileKind::MultisigAddress),
    ..KPUB_RULE
};
const MULTISIG_DESCRIPTOR_RULE: ImportScanRule = ImportScanRule {
    extensions: &[*b"TXT", *b"KSP"],
    max_size: 512,
    exclude_hidden: true,
    next_state: crate::runtime::navigation::continuation!(SdKpubFileList),
    empty_message: "No descriptor files found",
    text_import_kind: Some(TextFileKind::MultisigDescriptor),
};
const COVENANT_BACKUP_RULE: ImportScanRule = ImportScanRule {
    extensions: &[*b"COV"],
    max_size: 1024,
    exclude_hidden: true,
    next_state: crate::runtime::navigation::continuation!(SdFileList),
    empty_message: "No .COV files on SD",
    text_import_kind: None,
};

const IMPORT_RULES: [ImportScanRule; 6] = [
    WALLET_BACKUP_RULE,
    TRANSACTION_RULE,
    KPUB_RULE,
    MULTISIG_ADDRESS_RULE,
    MULTISIG_DESCRIPTOR_RULE,
    COVENANT_BACKUP_RULE,
];

fn scan_rule_plan(
    rule_index: usize,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    card_present: bool,
) {
    scan_by_rule(
        ad,
        boot_display,
        delay,
        i2c,
        card_present,
        IMPORT_RULES[rule_index],
    );
}

fn dispatch_import_scan(
    item: u8,
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    card_present: bool,
) {
    let Some(plan): Option<ImportScanPlan> = import_scan_plan(item) else { return; };
    scan_rule_plan(plan.rule_index(), ad, boot_display, delay, i2c, card_present);
}

pub(crate) fn handle_sd_import_menu(ctx: SdImportMenuContext<'_, '_, '_>) -> bool {
    let SdImportMenuContext {
        ad,
        boot_display,
        delay,
        i2c,
        sd_card_type,
        list_zones,
        page_up_zone,
        page_down_zone,
        x,
        y,
        is_back,
        ..
    } = ctx;

    if is_back {
        ad.navigation.sd_import_menu.reset();
        crate::runtime::effects::back(ad);
        return true;
    }
    match handle_paged_menu_touch(
        &mut ad.navigation.sd_import_menu,
        list_zones,
        page_up_zone,
        page_down_zone,
        x,
        y,
    ) {
        PagedMenuAction::PageChanged => true,
        PagedMenuAction::Selected(6) => {
            ad.wallet.keys.hex_input_len = 0;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ImportPrivKey));
            true
        }
        PagedMenuAction::Selected(item) => {
            dispatch_import_scan(item, ad, boot_display, delay, i2c, sd_card_type.is_some());
            true
        }
        PagedMenuAction::None => false,
    }
}
