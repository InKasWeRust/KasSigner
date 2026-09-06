//! Advanced-settings redraw helpers.

use super::super::display;
use crate::runtime::{data::AppData, input::AppState};

pub(super) fn redraw(
    ad: &AppData,
    boot_display: &mut display::BootDisplay<'_>,
) -> bool {
    match ad.navigation.app.state {
        AppState::AdvancedDuressWarning => {
            let (title, guidance) = duress_copy(ad);
            boot_display.draw_advanced_warning(
                title,
                "Entering it wipes all internal user data.",
                "It can never be disabled or changed.",
                guidance,
            );
            boot_display.draw_back_button();
        }
        AppState::AdvancedDuressEntry => draw_duress_entry(ad, boot_display, false),
        AppState::AdvancedDuressConfirm => draw_duress_entry(ad, boot_display, true),
        AppState::AdvancedSdStorageWarning => boot_display.draw_advanced_warning(
            "DEVICE-BOUND SD STORAGE",
            "Works only with this KasSigner Device.",
            "Recovery words remain your portable backup.",
            "Boot requires your PIN/password + SD.",
        ),
        AppState::FactoryResetWarning => boot_display.draw_advanced_warning(
            "FACTORY RESET",
            "Erases all saved wallets and settings.",
            "Unbacked wallets cannot be recovered.",
            "Verify recovery backups before continuing.",
        ),
        AppState::FactoryResetConfirm => boot_display.draw_factory_reset_confirmation(),
        #[cfg(feature = "m5stack")]
        AppState::AdvancedRtcEntry => boot_display.draw_numeric_format_entry(
            &ad.wallet.seeds.pp_input,
            "SET RTC (UTC)",
            "YYYYMMDDHHMM",
        ),
        #[cfg(feature = "m5stack")]
        AppState::AdvancedTimeLockWarning => boot_display.draw_advanced_warning(
            "NO-SIGN-BEFORE",
            "No transaction can be signed early.",
            "The lock cannot be disabled or changed.",
            "Hardware RTC is enforced in UTC.",
        ),
        #[cfg(feature = "m5stack")]
        AppState::AdvancedTimeLockEntry => boot_display.draw_numeric_format_entry(
            &ad.wallet.seeds.pp_input,
            "LOCK UNTIL (UTC)",
            "YYYYMMDDHHMM",
        ),
        #[cfg(feature = "m5stack")]
        AppState::AdvancedTimeLockConfirm => boot_display.draw_time_lock_confirmation(
            ad.storage.persistence.advanced.pending_not_before_unix,
        ),
        #[cfg(feature = "m5stack")]
        AppState::AdvancedWeeklyWarning => boot_display.draw_advanced_warning(
            "WEEKLY SIGNING WINDOWS",
            "Only configured UTC windows can sign.",
            "Windows cannot be changed or disabled.",
            "Up to four non-overlapping windows.",
        ),
        #[cfg(feature = "m5stack")]
        AppState::AdvancedWeeklyEntry => boot_display.draw_advanced_text_entry(
            &ad.wallet.seeds.pp_input,
            "WEEKLY WINDOWS (UTC)",
            "MON 08:10-08:25;MON 21:33-21:43",
        ),
        #[cfg(feature = "m5stack")]
        AppState::AdvancedWeeklyConfirm => boot_display.draw_weekly_confirmation(
            ad.storage.persistence.advanced.pending_weekly_count,
        ),
        _ => return false,
    }
    true
}

fn draw_duress_entry(
    ad: &AppData,
    boot_display: &mut display::BootDisplay<'_>,
    confirming: bool,
) {
    use crate::services::credential_policy::CredentialKind;
    let kind = ad.storage.persistence.advanced.credential_kind;
    let numeric = kind == Some(CredentialKind::Pin);
    let title = match (kind, confirming) {
        (Some(CredentialKind::Pin), false) => "CREATE DURESS PIN",
        (Some(CredentialKind::Pin), true) => "CONFIRM DURESS PIN",
        (Some(CredentialKind::Password), false) => "CREATE DURESS PASS",
        (Some(CredentialKind::Password), true) => "CONFIRM DURESS PASS",
        (None, false) => "CREATE DURESS",
        (None, true) => "CONFIRM DURESS",
    };
    // PIN setup is deliberately visible so the owner can verify the exact
    // digits being entered. Password-mode duress remains masked.
    boot_display.draw_storage_secret_entry(&ad.wallet.seeds.pp_input, title, numeric, numeric);
    boot_display.draw_back_button();
}

fn duress_copy(ad: &AppData) -> (&'static str, &'static str) {
    use crate::services::credential_policy::CredentialKind;
    match ad.storage.persistence.advanced.credential_kind {
        Some(CredentialKind::Pin) => ("DURESS PIN", "Use a strong, distinct PIN."),
        Some(CredentialKind::Password) => ("DURESS PASSWORD", "Use a strong, distinct password."),
        None => ("DURESS", "Use a strong, distinct secret."),
    }
}
