use crate::{
    runtime::interactions::TouchInput,
    hw::{display::BootDisplay, sdcard::SdCardType, touch::TouchZone},
    runtime::{data::AppData, input::AppState},
};
use esp_hal::{delay::Delay, i2c::master::I2c, Blocking};
use core::sync::atomic::{AtomicU8, Ordering};

static FAILURE_STAGE: AtomicU8 = AtomicU8::new(0);

mod delete;

struct WalletContext<'ctx, 'display, 'hal> {
    ad: &'ctx mut AppData,
    display: &'ctx mut BootDisplay<'display>,
    i2c: &'ctx mut I2c<'hal, Blocking>,
    sd: &'ctx Option<SdCardType>,
    delay: &'ctx mut Delay,
    grid: [TouchZone; 4],
    list: [TouchZone; 4],
    up: TouchZone,
    down: TouchZone,
}

impl WalletContext<'_, '_, '_> {
    fn redraw(&mut self) {
        super::redraw_step(self.ad, self.display, self.i2c, self.sd);
    }

    fn show_step(&mut self) {
        super::show_step(self.delay);
    }

    fn seed_list_touch(&mut self, x: u16, y: u16, is_back: bool) -> Option<bool> {
        let mut feed = || {};
        crate::runtime::interactions::seed::handle_inventory_touch(
            self.ad,
            self.display,
            self.delay,
            &mut feed,
            TouchInput::new(x, y, is_back),
        )
    }

    fn open_wallet_item(&mut self, item: usize, expected: AppState) -> bool {
        self.ad.navigation.production.wallet_menu.reset();
        if item >= 4 && !self.ad.navigation.production.wallet_menu.page_down() {
            return false;
        }
        let visible = item % usize::from(signer_firmware_core::input::navigation::Menu::MAX_VISIBLE);
        let zone = self.list[visible];
        let selected = crate::runtime::interactions::menu_selection::selected_visible_item(
            &self.ad.navigation.production.wallet_menu,
            &self.list,
            zone.x + zone.w / 2,
            zone.y + zone.h / 2,
        );
        if selected != u8::try_from(item).ok()
            || !crate::runtime::interactions::menu::primary::workflow_wallet_select(self.ad, item)
        {
            return false;
        }
        self.ad.navigation.app.state == expected && crate::runtime::navigation::reconcile(self.ad)
    }

    fn return_wallet_menu(&mut self) -> bool {
        self.ad.navigation.app.state == AppState::SeedsMenu && crate::runtime::navigation::reconcile(self.ad)
    }
}

pub(super) fn exercise(
    ad: &mut AppData,
    display: &mut BootDisplay<'_>,
    i2c: &mut I2c<'_, Blocking>,
    sd: &Option<SdCardType>,
    delay: &mut Delay,
) -> bool {
    if !crate::services::wallet_session::install_workflow_wallet_inventory_fixture(ad) {
        log!("KASSIGNER_WORKFLOW_TESTS: WALLET FIXTURE FAIL");
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET INVENTORY FIXTURE READY 5");
    if !super::reset_tranche_to_home(ad) {
        log!("KASSIGNER_WORKFLOW_TESTS: WALLET SCENARIO RESET FAIL");
        return false;
    }
    let wallet_zone = crate::ui::layout::HOME_GRID_ZONES[2];
    if !crate::runtime::interactions::menu::handle_connected_root_probe(
        ad,
        wallet_zone.x + wallet_zone.w / 2,
        wallet_zone.y + wallet_zone.h / 2,
    ) || ad.navigation.app.state != AppState::SeedsMenu
        || !crate::runtime::navigation::reconcile(ad)
    {
        log!("KASSIGNER_WORKFLOW_TESTS: WALLET PRODUCTION ENTRY ROUTE FAIL");
        return false;
    }

    let (grid, list, up, down) = crate::runtime::touch_dispatch::touch_zones();
    let mut ctx = WalletContext { ad, display, i2c, sd, delay, grid, list, up, down };
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET MANAGEMENT BEGIN");

    mark_failure_stage(1);
    if !wallet_menu_integrity(&mut ctx) { return false; }
    mark_failure_stage(2);
    if !wallet_root_routes(&mut ctx) { return false; }
    mark_failure_stage(3);
    if !wallet_details(&mut ctx) { return false; }
    mark_failure_stage(4);
    if !wallet_inventory(&mut ctx) { return false; }
    mark_failure_stage(5);
    if !add_wallet_routes(&mut ctx) { return false; }
    mark_failure_stage(6);
    if !delete::exercise(&mut ctx) { return false; }
    mark_failure_stage(9);
    if !finish_home(&mut ctx) { return false; }
    FAILURE_STAGE.store(0, Ordering::Relaxed);
    true
}

pub(super) fn mark_failure_stage(stage: u8) {
    FAILURE_STAGE.store(stage, Ordering::Relaxed);
}

pub(super) fn replay_failure_detail() {
    let message = match FAILURE_STAGE.load(Ordering::Relaxed) {
        1 => Some("MENU-PAGING: wallet menu no-op/page-up/page-down contract failed"),
        2 => Some("ROOT-ROUTES: Receive/Backup/Recovery/Multisig/Advanced route or Back owner failed"),
        3 => Some("DETAILS: wallet details name-edit or delete-cancel contract failed"),
        4 => Some("INVENTORY: wallet list contract failed before a more specific stage was recorded"),
        40 => Some("INVENTORY-PAGE-DOWN: wallet list did not advance from scroll 0 to 3"),
        41 => Some("INVENTORY-PAGE-UP: wallet list did not return from scroll 3 to 0"),
        42 => Some("INVENTORY-ACTIVATE: wallet slot 1 did not activate from the third visible row"),
        43 => Some("INVENTORY-RETURN: wallet activation did not return to the Wallet menu owner"),
        5 => Some("ADD-WALLET: add-wallet menu/create/restore/back contract failed"),
        6 => Some("DELETE-RELEASE-CANCEL: destructive hold release/cancel contract failed"),
        7 => Some("DELETE-COMMIT: destructive hold completion or no-active-wallet invariant failed"),
        8 => Some("DELETE-REACTIVATE: required-selection Back guard or surviving wallet activation failed"),
        9 => Some("FINISH-HOME: wallet flow could not return through authoritative Home route"),
        _ => None,
    };
    if let Some(message) = message {
        log!("KASSIGNER_WORKFLOW_TESTS: CONNECTED FAILURE REASON WALLET: {}", message);
    }
}

fn wallet_menu_integrity(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    use crate::runtime::interactions::menu_selection::{handle_paged_menu_touch, PagedMenuAction};

    log!("KASSIGNER_WORKFLOW_TESTS: WALLET MENU NOOP BEGIN");
    let no_op = handle_paged_menu_touch(
        &mut ctx.ad.navigation.production.wallet_menu,
        &ctx.list,
        &ctx.up,
        &ctx.down,
        319,
        239,
    );
    if no_op != PagedMenuAction::None || ctx.ad.navigation.app.state != AppState::SeedsMenu {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET MENU NOOP OK");

    log!("KASSIGNER_WORKFLOW_TESTS: WALLET MENU PAGE DOWN BEGIN");
    if handle_paged_menu_touch(
        &mut ctx.ad.navigation.production.wallet_menu,
        &ctx.list,
        &ctx.up,
        &ctx.down,
        ctx.down.x + 20,
        ctx.down.y + 20,
    ) != PagedMenuAction::PageChanged
        || ctx.ad.navigation.production.wallet_menu.scroll != 4
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET MENU PAGE DOWN OK");

    log!("KASSIGNER_WORKFLOW_TESTS: WALLET MENU PAGE UP BEGIN");
    if handle_paged_menu_touch(
        &mut ctx.ad.navigation.production.wallet_menu,
        &ctx.list,
        &ctx.up,
        &ctx.down,
        ctx.up.x + 20,
        ctx.up.y + 20,
    ) != PagedMenuAction::PageChanged
        || ctx.ad.navigation.production.wallet_menu.scroll != 0
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET MENU NOOP/PAGING OK");
    true
}

fn wallet_root_routes(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    if !wallet_receive_route(ctx)
        || !simple_route(ctx, 1, AppState::WalletBackupMethodsMenu)
        || !simple_route(ctx, 2, AppState::SdImportMenu)
    {
        return false;
    }
    if !simple_route(ctx, 5, AppState::MultisigMenu) || !simple_route(ctx, 6, AppState::WalletAdvancedMenu) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET ROOT ROUTES OK");
    true
}

fn wallet_receive_route(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    if !ctx.open_wallet_item(0, AppState::ShowAddress) {
        return false;
    }
    ctx.redraw();
    ctx.show_step();
    let (_, list, up, down) = crate::runtime::touch_dispatch::touch_zones();
    let result = crate::runtime::interactions::export::handle_export_touch(
        crate::runtime::interactions::export::ExportTouchContext {
            ad: &mut *ctx.ad,
            boot_display: &mut *ctx.display,
            delay: &mut *ctx.delay,
            liveness: &mut || {}, i2c: &mut *ctx.i2c,
            sd_card_type: ctx.sd,
            list_zones: &list,
            page_up_zone: &up,
            page_down_zone: &down,
            input: TouchInput::new(20, 20, true),
        },
    );
    result == Some(true) && ctx.return_wallet_menu()
}

fn simple_route(ctx: &mut WalletContext<'_, '_, '_>, item: usize, expected: AppState) -> bool {
    if !ctx.open_wallet_item(item, expected) {
        return false;
    }
    ctx.redraw();
    ctx.show_step();
    let returned = crate::runtime::navigation::handle_back(ctx.ad);
    returned && ctx.return_wallet_menu()
}

fn wallet_details(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DETAILS ROUTE BEGIN");
    if !ctx.open_wallet_item(3, AppState::WalletDetails) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DETAILS ROUTE OK");
    ctx.redraw();
    ctx.show_step();
    wallet_details_edit_name(ctx) && wallet_details_delete_cancel(ctx)
}

fn wallet_details_edit_name(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    if ctx.ad.wallet.seeds.seed_mgr.active != 0 {
        return false;
    }
    if !crate::runtime::interactions::menu::primary::workflow_wallet_details_edit(ctx.ad)
        || ctx.ad.navigation.app.state != (AppState::WalletNameEntry { purpose: 2 })
    {
        return false;
    }
    ctx.ad.wallet.seeds.pp_input.reset();
    for byte in b"Edited Wallet" { ctx.ad.wallet.seeds.pp_input.push_char(*byte); }
    if crate::runtime::interactions::seed::handle_seed_touch(
        ctx.ad, ctx.display, ctx.delay, &mut || {}, TouchInput::new(300, 210, false),
    ) != Some(true)
        || ctx.ad.navigation.app.state != AppState::WalletDetails
        || ctx.ad.wallet.seeds.seed_mgr.active_slot().map(|slot| slot.name_str()) != Some("Edited Wallet")
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DETAILS NAME EDIT OK");
    true
}

fn wallet_details_delete_cancel(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    if !crate::runtime::interactions::menu::primary::workflow_wallet_details_delete(ctx.ad)
        || ctx.ad.navigation.app.state != AppState::ConfirmDeleteSeed
        || ctx.ad.wallet.seeds.pending_delete_slot != 0
    {
        return false;
    }
    ctx.redraw();
    ctx.show_step();
    if crate::runtime::interactions::seed::handle_seed_touch(
        ctx.ad, ctx.display, ctx.delay, &mut || {}, TouchInput::new(90, 205, false),
    ) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SeedList
        || ctx.ad.wallet.seeds.pending_delete_slot != u8::MAX
        || ctx.ad.wallet.seeds.seed_mgr.slots[0].is_empty()
    {
        return false;
    }
    if ctx.seed_list_touch(20, 20, true) != Some(true) || !ctx.return_wallet_menu() {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET DETAILS DELETE CANCEL OK");
    true
}

fn wallet_inventory(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    if !ctx.open_wallet_item(4, AppState::SeedList) {
        return false;
    }
    ctx.redraw();
    ctx.show_step();
    mark_failure_stage(40);
    if ctx.seed_list_touch(300, 112, false) != Some(true) || ctx.ad.wallet.seeds.seed_list_scroll != 3 {
        return false;
    }
    mark_failure_stage(41);
    if ctx.seed_list_touch(20, 112, false) != Some(true) || ctx.ad.wallet.seeds.seed_list_scroll != 0 {
        return false;
    }
    // WALLETS renders Add Wallet first, then loaded wallets. With scroll=0,
    // slot 0 is row 1 and slot 1 is row 2. Select the third visible row so
    // this probe actually exercises a wallet switch instead of re-selecting 0.
    mark_failure_stage(42);
    if ctx.seed_list_touch(160, 158, false) != Some(true)
        || ctx.ad.wallet.seeds.seed_mgr.active != 1
    {
        return false;
    }
    mark_failure_stage(43);
    if !ctx.return_wallet_menu() {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET SWITCH/PAGING OK active=1");
    true
}

fn add_wallet_routes(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    open_add_wallet_menu(ctx)
        && exercise_add_wallet_create(ctx)
        && exercise_add_wallet_restore(ctx)
        && exercise_add_wallet_back(ctx)
}

fn open_add_wallet_menu(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    if !ctx.open_wallet_item(4, AppState::SeedList)
        // Add Wallet is the first canonical WALLETS row whenever capacity is
        // available; do not page away from item 0 before selecting it.
        || ctx.seed_list_touch(160, 66, false) != Some(true)
        || ctx.ad.navigation.app.state != AppState::AddWalletChoice
    {
        return false;
    }
    ctx.redraw();
    ctx.show_step();
    log!("KASSIGNER_WORKFLOW_TESTS: ADD WALLET NOOP BEGIN");
    if crate::runtime::interactions::seed::handle_navigation_touch(ctx.ad, TouchInput::new(310, 100, false)) != Some(false) {
        return false;
    }
    true
}

fn exercise_add_wallet_create(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    log!("KASSIGNER_WORKFLOW_TESTS: ADD WALLET CREATE BEGIN");
    if crate::runtime::interactions::seed::handle_navigation_touch(ctx.ad, TouchInput::new(160, 58, false)) != Some(true)
        || ctx.ad.navigation.app.state != (AppState::WalletNameEntry { purpose: 1 })
    {
        return false;
    }
    ctx.ad.wallet.seeds.pp_input.reset();
    for byte in b"Added Wallet" { ctx.ad.wallet.seeds.pp_input.push_char(*byte); }
    if crate::runtime::interactions::seed::handle_seed_touch(
        ctx.ad, ctx.display, ctx.delay, &mut || {}, TouchInput::new(300, 210, false),
    ) != Some(true) || ctx.ad.navigation.app.state != (AppState::ChooseWordCount { action: 0 })
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADD WALLET CREATE NAME/ROUTE OK");
    crate::runtime::effects::return_to(ctx.ad, crate::runtime::navigation::ReturnScope::SeedTool)
        && ctx.ad.navigation.app.state == AppState::AddWalletChoice
        && crate::runtime::navigation::reconcile(ctx.ad)
}

fn exercise_add_wallet_restore(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    log!("KASSIGNER_WORKFLOW_TESTS: ADD WALLET RESTORE BEGIN");
    if crate::runtime::interactions::seed::handle_navigation_touch(
        ctx.ad,
        TouchInput::new(160, 142, false),
    ) != Some(true)
        || ctx.ad.navigation.app.state != AppState::StorageSeedSourceChoice
    {
        return false;
    }
    if crate::runtime::interactions::persistence::workflow_handle_seed_source_choice(
        TouchInput::new(20, 20, true),
        ctx.ad,
    ) != Some(true)
        || ctx.ad.navigation.app.state != AppState::AddWalletChoice
    {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADD WALLET RESTORE MENU/BACK OK");
    crate::runtime::navigation::reconcile(ctx.ad)
}

fn exercise_add_wallet_back(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    log!("KASSIGNER_WORKFLOW_TESTS: ADD WALLET BACK BEGIN");
    if crate::runtime::interactions::seed::handle_navigation_touch(ctx.ad, TouchInput::new(20, 20, true)) != Some(true)
        || ctx.ad.navigation.app.state != AppState::SeedList
    {
        return false;
    }
    if ctx.seed_list_touch(20, 20, true) != Some(true) || !ctx.return_wallet_menu() {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: ADD WALLET CREATE/RESTORE/BACK OK");
    true
}

fn finish_home(ctx: &mut WalletContext<'_, '_, '_>) -> bool {
    if !crate::runtime::navigation::handle_back(ctx.ad) || !super::root::home_ok(ctx.ad) {
        return false;
    }
    log!("KASSIGNER_WORKFLOW_TESTS: WALLET MANAGEMENT PASS");
    true
}
