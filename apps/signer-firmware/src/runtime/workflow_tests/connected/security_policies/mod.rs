use crate::{
    hw::{display::BootDisplay, sdcard::SdCardType, touch::TouchZone},
    runtime::{data::AppData, input::AppState},
};
use esp_hal::{delay::Delay, i2c::master::I2c, Blocking};

mod duress;
mod pop_it;
mod signing;
#[cfg(feature = "m5stack")]
mod time;

pub(super) struct SecurityContext<'ctx, 'display, 'hal> {
    pub(super) ad: &'ctx mut AppData,
    pub(super) display: &'ctx mut BootDisplay<'display>,
    pub(super) i2c: &'ctx mut I2c<'hal, Blocking>,
    pub(super) sd: &'ctx Option<SdCardType>,
    pub(super) delay: &'ctx mut Delay,
    pub(super) list: [TouchZone; 4],
    pub(super) up: TouchZone,
    pub(super) down: TouchZone,
}

impl SecurityContext<'_, '_, '_> {
    pub(super) fn redraw_step(&mut self) {
        super::redraw_step(self.ad, self.display, self.i2c, self.sd);
        super::show_step(self.delay);
    }

    pub(super) fn set_text(&mut self, value: &[u8]) {
        self.ad.wallet.seeds.pp_input.reset();
        let length = value.len().min(self.ad.wallet.seeds.pp_input.buf.len());
        self.ad.wallet.seeds.pp_input.buf[..length].copy_from_slice(&value[..length]);
        self.ad.wallet.seeds.pp_input.len = length;
        self.ad.wallet.seeds.pp_input.cursor = length;
    }

    pub(super) fn advanced_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        let input = crate::runtime::touch_dispatch::workflow_touch_input(x, y, is_back)?;
        crate::runtime::interactions::settings::handle_advanced_navigation(self.ad, input)
    }

    pub(super) fn open_card(&mut self, y: u16) -> Option<bool> {
        crate::runtime::interactions::settings::advanced::workflow::open_card(
            crate::runtime::touch_dispatch::workflow_touch_input(160, y, false)?,
            self.ad, self.display, self.delay,
        )
    }

    pub(super) fn home(&mut self) -> bool {
        crate::runtime::effects::home(self.ad);
        super::root::home_ok(self.ad)
    }
}

pub(super) fn exercise(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
) -> bool {
    if !super::signing::fixture::install_wallet(ad) || !enter_security(ad) { return false; }
    let (_, list, up, down) = crate::runtime::touch_dispatch::touch_zones();
    let mut ctx = SecurityContext { ad, display, i2c, sd, delay, list, up, down };
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY POLICIES TRANCHE BEGIN");
    let mut summary = super::probe_status::ProbeSummary::new("SECURITY-POLICIES");

    summary.begin("AVAILABILITY-INTEGRITY");
    let availability_ok = unavailable_and_integrity(&mut ctx);
    summary.record("AVAILABILITY-INTEGRITY", availability_ok);
    recover(&mut ctx);

    summary.begin("DURESS");
    let duress_ok = duress::exercise(&mut ctx);
    summary.record("DURESS", duress_ok);
    recover(&mut ctx);

    summary.begin("TIME-POLICY");
    let time_ok = time_policy_exercise(&mut ctx);
    summary.record("TIME-POLICY", time_ok);
    recover(&mut ctx);

    summary.begin("SIGNING-POLICY");
    let signing_ok = signing::exercise(&mut ctx);
    summary.record("SIGNING-POLICY", signing_ok);
    recover(&mut ctx);

    summary.begin("POP-IT");
    let pop_it_ok = pop_it::exercise(&mut ctx);
    summary.record("POP-IT", pop_it_ok);

    summary.begin("FINISH-HOME");
    let finish_ok = finish(&mut ctx);
    summary.record("FINISH-HOME", finish_ok);
    summary.finish(6)
}

fn recover(ctx: &mut SecurityContext<'_, '_, '_>) {
    crate::runtime::effects::home(ctx.ad);
    if !super::signing::fixture::install_wallet(ctx.ad) || !enter_security(ctx.ad) {
        log!("KASSIGNER_WORKFLOW_TESTS: SECURITY-POLICIES PROBE RECOVERY FAILED");
    }
}


#[cfg(feature = "m5stack")]
fn time_policy_exercise(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    time::exercise(ctx)
}

#[cfg(feature = "waveshare")]
fn time_policy_exercise(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    // Waveshare has no trusted hardware RTC. Production must keep each
    // RTC-backed policy on the Advanced screen and fail closed instead of
    // exposing the CoreS3-only entry/confirmation states.
    for y in [93u16, 131u16, 207u16] {
        if ctx.open_card(y) != Some(true)
            || ctx.ad.navigation.app.state != AppState::AdvancedFeatures
        {
            return false;
        }
    }
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY RTC-BACKED POLICIES UNAVAILABLE FAIL-CLOSED PASS");
    true
}

fn enter_security(ad: &mut AppData) -> bool {
    if !super::root::home_ok(ad) { return false; }
    let settings = crate::ui::layout::HOME_GRID_ZONES[3];
    if !crate::runtime::interactions::menu::handle_connected_root_probe(
        ad, settings.x + settings.w / 2, settings.y + settings.h / 2,
    ) || ad.navigation.app.state != AppState::SettingsMenu { return false; }
    let (_, list, up, down) = crate::runtime::touch_dispatch::touch_zones();
    let security = list[2];
    crate::runtime::interactions::settings::handle_settings_menu_navigation(
        ad, &list, &up, &down,
        crate::runtime::touch_dispatch::physical_touch_input(
            security.x + security.w / 2, security.y + security.h / 2,
        ),
    ) == Some(true) && ad.navigation.app.state == AppState::AdvancedFeatures
}

fn unavailable_and_integrity(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    ctx.ad.storage.persistence.advanced.availability =
        crate::runtime::data::AdvancedAvailability::Unavailable;
    ctx.ad.storage.persistence.advanced.policy_integrity =
        crate::runtime::data::PolicyIntegrity::Valid;
    if ctx.open_card(55) != Some(true) || ctx.ad.navigation.app.state != AppState::AdvancedFeatures {
        return false;
    }
    crate::runtime::interactions::settings::advanced::workflow::install_saved_wallet_fixture(
        ctx.ad,
        crate::services::credential_policy::CredentialKind::Pin,
    );
    ctx.ad.storage.persistence.advanced.policy_integrity = crate::runtime::data::PolicyIntegrity::Invalid;
    if ctx.open_card(55) != Some(true) || ctx.ad.navigation.app.state != AppState::AdvancedFeatures {
        return false;
    }
    ctx.ad.storage.persistence.advanced.policy_integrity = crate::runtime::data::PolicyIntegrity::Valid;
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY SAVED-WALLET/INTEGRITY FAIL-CLOSED PASS");
    true
}

fn finish(ctx: &mut SecurityContext<'_, '_, '_>) -> bool {
    if !ctx.home() { return false; }
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY PERSISTENT FLASH/HMAC + PHYSICAL RTC/EFUSE HIL DEFERRED");
    log!("KASSIGNER_WORKFLOW_TESTS: SECURITY POLICIES TRANCHE PASS");
    true
}
