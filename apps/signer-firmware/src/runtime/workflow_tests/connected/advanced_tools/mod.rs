use crate::{
    runtime::interactions::{TouchInput, tx::TxTouchContext},
    hw::{display::BootDisplay, sdcard::SdCardType, touch::TouchZone},
    runtime::{data::AppData, input::AppState},
};
use esp_hal::{delay::Delay, i2c::master::I2c, Blocking};

mod exports;
mod messages;
mod secrets;
mod seed_tools;

pub(super) struct AdvancedToolsContext<'ctx, 'display, 'hal> {
    pub(super) ad: &'ctx mut AppData,
    pub(super) display: &'ctx mut BootDisplay<'display>,
    pub(super) i2c: &'ctx mut I2c<'hal, Blocking>,
    pub(super) sd: &'ctx Option<SdCardType>,
    pub(super) delay: &'ctx mut Delay,
    pub(super) grid: [TouchZone; 4],
    pub(super) list: [TouchZone; 4],
    pub(super) up: TouchZone,
    pub(super) down: TouchZone,
}

impl AdvancedToolsContext<'_, '_, '_> {
    pub(super) fn redraw_step(&mut self) {
        super::redraw_step(self.ad, self.display, self.i2c, self.sd);
        super::show_step(self.delay);
    }

    pub(super) fn menu_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        crate::runtime::interactions::menu::handle_navigation_touch(
            self.ad,
            &self.grid,
            &self.list,
            &self.up,
            &self.down,
            TouchInput::new(x, y, is_back),
        )
    }

    pub(super) fn seed_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        crate::runtime::interactions::seed::handle_seed_touch(
            self.ad,
            self.display,
            self.delay,
            &mut || {},
            TouchInput::new(x, y, is_back),
        )
    }

    pub(super) fn tx_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        let input = TouchInput::new(x, y, is_back);
        let context = TxTouchContext {
            ad: self.ad,
            boot_display: self.display,
            delay: self.delay,
            liveness: &mut || {}, i2c: self.i2c,
            sd_card_type: self.sd,
            list_zones: &self.list,
            input,
        };
        crate::runtime::interactions::tx::handle_tx_touch(context)
    }

    pub(super) fn tx_touch_without_sd(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        let no_sd = None;
        crate::runtime::interactions::tx::handle_tx_touch(TxTouchContext {
            ad: self.ad,
            boot_display: self.display,
            delay: self.delay,
            liveness: &mut || {}, i2c: self.i2c,
            sd_card_type: &no_sd,
            list_zones: &self.list,
            input: TouchInput::new(x, y, is_back),
        })
    }

    pub(super) fn export_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        let input = TouchInput::new(x, y, is_back);
        if let Some(result) = crate::runtime::interactions::export::menus::handle_navigation_touch(
            self.ad,
            &self.list,
            &self.up,
            &self.down,
            input,
        ) {
            return Some(result);
        }
        crate::runtime::interactions::export::handle_export_touch(
            crate::runtime::interactions::export::ExportTouchContext {
                ad: self.ad,
                boot_display: self.display,
                delay: self.delay,
                liveness: &mut || {}, i2c: self.i2c,
                sd_card_type: self.sd,
                list_zones: &self.list,
                page_up_zone: &self.up,
                page_down_zone: &self.down,
                input,
            },
        )
    }

    pub(super) fn export_touch_without_sd(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        let input = TouchInput::new(x, y, is_back);
        if let Some(result) = crate::runtime::interactions::export::menus::handle_navigation_touch(
            self.ad,
            &self.list,
            &self.up,
            &self.down,
            input,
        ) {
            return Some(result);
        }
        let no_sd = None;
        crate::runtime::interactions::export::handle_export_touch(
            crate::runtime::interactions::export::ExportTouchContext {
                ad: self.ad,
                boot_display: self.display,
                delay: self.delay,
                liveness: &mut || {}, i2c: self.i2c,
                sd_card_type: &no_sd,
                list_zones: &self.list,
                page_up_zone: &self.up,
                page_down_zone: &self.down,
                input,
            },
        )
    }

    pub(super) fn set_text(&mut self, value: &[u8]) {
        self.ad.wallet.seeds.pp_input.reset();
        let length = value.len().min(self.ad.wallet.seeds.pp_input.buf.len());
        self.ad.wallet.seeds.pp_input.buf[..length].copy_from_slice(&value[..length]);
        self.ad.wallet.seeds.pp_input.len = length;
        self.ad.wallet.seeds.pp_input.cursor = length;
    }

    pub(super) fn open_wallet_advanced(&mut self) -> bool {
        crate::runtime::effects::home(self.ad);
        if !crate::runtime::interactions::menu::handle_root_touch(self.ad, 82, 188)
            || self.ad.navigation.app.state != AppState::SeedsMenu
        {
            return false;
        }
        self.ad.navigation.production.wallet_menu.reset();
        if self.menu_touch(self.down.x + 20, self.down.y + 20, false) != Some(true) {
            return false;
        }
        // Wallet -> Advanced is absolute item 6. After paging the seven-item
        // Wallet menu to scroll=4, item 6 occupies visible row 2.
        let zone = self.list[2];
        self.menu_touch(zone.x + zone.w / 2, zone.y + zone.h / 2, false) == Some(true)
            && self.ad.navigation.app.state == AppState::WalletAdvancedMenu
    }

    pub(super) fn open_backup_advanced_item(&mut self, item: usize, expected: AppState) -> bool {
        crate::runtime::effects::home(self.ad);
        if !crate::runtime::interactions::menu::handle_root_touch(self.ad, 82, 188)
            || self.ad.navigation.app.state != AppState::SeedsMenu
        {
            return false;
        }
        self.ad.navigation.production.wallet_menu.reset();
        if !crate::runtime::interactions::menu::primary::workflow_wallet_select(self.ad, 1)
            || self.ad.navigation.app.state != AppState::WalletBackupMethodsMenu
            || !crate::runtime::interactions::menu::primary::workflow_wallet_backup_methods_select(self.ad, 3)
            || self.ad.navigation.app.state != AppState::BackupRecoveryMenu
        {
            return false;
        }
        self.ad.navigation.production.backup_recovery_menu.reset();
        if item >= 4 && self.menu_touch(self.down.x + 20, self.down.y + 20, false) != Some(true) {
            return false;
        }
        let zone = self.list[item % 4];
        self.menu_touch(zone.x + zone.w / 2, zone.y + zone.h / 2, false) == Some(true)
            && self.ad.navigation.app.state == expected
    }

    pub(super) fn open_advanced_item(&mut self, item: usize, expected: AppState) -> bool {
        if !self.open_wallet_advanced() {
            return false;
        }
        self.ad.navigation.production.wallet_advanced_menu.reset();
        if item >= 4 && self.menu_touch(self.down.x + 20, self.down.y + 20, false) != Some(true) {
            return false;
        }
        let zone = self.list[item % 4];
        self.menu_touch(zone.x + zone.w / 2, zone.y + zone.h / 2, false) == Some(true)
            && self.ad.navigation.app.state == expected
    }
}

pub(super) fn exercise(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
) -> bool {
    let (grid, list, up, down) = crate::runtime::touch_dispatch::touch_zones();
    let mut ctx = AdvancedToolsContext { ad, display, i2c, sd, delay, grid, list, up, down };
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED WALLET TOOLS TRANCHE BEGIN");
    let mut summary = super::probe_status::ProbeSummary::new("ADVANCED-TOOLS");

    summary.begin("SEED-TOOLS");
    let seed_tools_ok = seed_tools::exercise(&mut ctx);
    summary.record("SEED-TOOLS", seed_tools_ok);
    recover(&mut ctx, seed_tools_ok);

    summary.begin("EXPORTS");
    let exports_ok = exports::exercise(&mut ctx);
    summary.record("EXPORTS", exports_ok);
    recover(&mut ctx, exports_ok);

    summary.begin("MESSAGES");
    let messages_ok = messages::exercise(&mut ctx);
    summary.record("MESSAGES", messages_ok);
    recover(&mut ctx, messages_ok);

    summary.begin("SECRETS");
    let secrets_ok = secrets::exercise(&mut ctx);
    summary.record("SECRETS", secrets_ok);
    recover(&mut ctx, secrets_ok);

    summary.begin("FINISH-HOME");
    let finish_ok = finish(&mut ctx);
    summary.record("FINISH-HOME", finish_ok);
    summary.finish(5)
}

fn recover(ctx: &mut AdvancedToolsContext<'_, '_, '_>, probe_ok: bool) {
    if probe_ok {
        return;
    }
    crate::runtime::effects::home(ctx.ad);
    if !crate::services::wallet_session::install_workflow_backup_mnemonic_fixture(ctx.ad) {
        log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED-TOOLS PROBE RECOVERY FIXTURE FAILED");
    }
}

fn finish(ctx: &mut AdvancedToolsContext<'_, '_, '_>) -> bool {
    crate::runtime::effects::home(ctx.ad);
    if !super::root::home_ok(ctx.ad) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED TOOLS PHYSICAL SD/RNG HIL DEFERRED TO PERIPHERAL TRANCHE");
    log!("KASSIGNER_WORKFLOW_TESTS: ADVANCED WALLET TOOLS TRANCHE PASS");
    true
}
