from pathlib import Path
import json
import re
import unittest

ROOT = Path(__file__).resolve().parents[3]


def read(relative: str) -> str:
    return (ROOT / relative).read_text()


class NavigationStateMachineTests(unittest.TestCase):
    def test_navigation_is_authoritative_before_input_and_render(self) -> None:
        runtime = read("apps/signer-firmware/src/runtime/mod.rs")
        data = read("apps/signer-firmware/src/runtime/data/navigation.rs")
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        redraw = read("apps/signer-firmware/src/ui/redraw.rs")
        facade = read("apps/signer-firmware/src/runtime/navigation/mod.rs")

        self.assertIn("pub(crate) mod navigation;", runtime)
        self.assertIn("committed_state", data)
        self.assertIn("NavigationOwner", data)
        tap_at = dispatch.index("TouchAction::Tap")
        reconcile_at = dispatch.index("runtime::navigation::reconcile($ad)", tap_at)
        route_at = dispatch.index("touch_routes::route_touch!", reconcile_at)
        self.assertLess(reconcile_at, route_at)
        self.assertIn("let _ = $crate::runtime::navigation::reconcile($ad);", dispatch[route_at:])
        self.assertEqual(redraw.count("let _ = crate::runtime::navigation::reconcile(ad);"), 1)
        self.assertIn("qr_presentation::prepare_navigation(ad)", redraw)
        self.assertIn("transition_allowed", facade)
        reconcile = facade[facade.index("pub(crate) fn reconcile"):facade.index("/// Central handling", facade.index("pub(crate) fn reconcile"))]
        self.assertIn("actual != ad.navigation.committed_state", reconcile)
        self.assertIn("kernel::force_recover(ad, actual)", reconcile)
        self.assertIn("result_screen_is_valid(ad, actual)", reconcile)
        self.assertNotIn("owner_for(ad, actual", reconcile)
        self.assertNotIn("committed_state = actual", reconcile)
        self.assertNotIn("state_belongs_to", facade)

    def test_runtime_authorities_have_no_legacy_bypasses(self) -> None:
        firmware = ROOT / "apps/signer-firmware/src"
        navigation = firmware / "runtime/navigation/mod.rs"
        touch_service = firmware / "runtime/touch_service.rs"
        effects = firmware / "runtime/effects.rs"

        nav_offenders = []
        touch_offenders = []
        redraw_offenders = []
        assignment = re.compile(r"(?:\$?ad)\.navigation\.app\.state\s*=(?!=)")
        touch_call = re.compile(r"(?:hw::touch::|touch::)(?:read_touch|read_touch_checked|read_touch_full|read_touch_with_gesture)\s*\(")
        redraw_write = re.compile(r"ad\.runtime\.needs_redraw\s*=")
        for path in firmware.rglob("*.rs"):
            source = path.read_text()
            navigation_root = firmware / "runtime/navigation"
            if path != navigation and navigation_root not in path.parents and assignment.search(source):
                nav_offenders.append(path.relative_to(ROOT).as_posix())
            if path != touch_service and "/hw/" not in path.as_posix() and touch_call.search(source):
                touch_offenders.append(path.relative_to(ROOT).as_posix())
            if ("/controllers/" in path.as_posix() or "/services/" in path.as_posix()) and redraw_write.search(source):
                redraw_offenders.append(path.relative_to(ROOT).as_posix())

        self.assertEqual(nav_offenders, [], "only the runtime/navigation package may commit AppState")
        self.assertEqual(touch_offenders, [], "only runtime/touch_service may read production touch transport")
        self.assertEqual(redraw_offenders, [], "controllers/services must request redraw through runtime/effects")
        self.assertIn("UiEffect", effects.read_text())

    def test_cores3_watchdog_is_outer_loop_owned(self) -> None:
        core = read("apps/signer-firmware/src/runtime/core_s3.rs")
        loop = read("apps/signer-firmware/src/runtime/event_loop/mod.rs")
        main = read("apps/signer-firmware/src/main.rs")
        self.assertIn("TimerGroup::new($timg0)", core)
        self.assertIn("MwdtStage::Stage0", core)
        self.assertIn("watchdog.feed()", core)
        self.assertIn("$crate::runtime::core_s3::requested_watchdog_ms()", core)
        self.assertNotIn("REQUESTED_WATCHDOG_MS.load(Ordering::Acquire)", core.split("macro_rules! watchdog_feed", 1)[1])
        self.assertIn("runtime_watchdog", main)
        liveness = read("apps/signer-firmware/src/runtime/event_loop/runner/liveness.rs")
        runtime_feed = "event_loop::runner::acknowledge_runtime"
        wave_feed = "event_loop::runner::acknowledge(&mut $watchdog_feed)"
        runtime_feed_positions = [m.start() for m in re.finditer(runtime_feed, loop)]
        wave_feed_positions = [m.start() for m in re.finditer(re.escape(wave_feed), loop)]
        persistence_at = loop.index("event_loop::persistence::sync!")
        camera_at = loop.index("event_loop::camera::run_step!")
        # The ordinary frame still acknowledges only after camera/persistence.
        # A second, earlier acknowledgement belongs exclusively to the
        # credential-KDF quarantine lane, which intentionally skips those services.
        self.assertEqual(len(runtime_feed_positions), 2)
        self.assertEqual(len(wave_feed_positions), 2)
        self.assertGreater(runtime_feed_positions[-1], persistence_at)
        self.assertGreater(runtime_feed_positions[-1], camera_at)
        self.assertEqual(liveness.count("watchdog_feed();"), 2)


    def test_renderers_cannot_mutate_navigation_state(self) -> None:
        redraw_root = ROOT / "apps/signer-firmware/src/ui/redraw"
        screen_root = ROOT / "apps/signer-firmware/src/ui/screens"
        paths = [ROOT / "apps/signer-firmware/src/ui/redraw.rs"]
        paths.extend(redraw_root.rglob("*.rs"))
        paths.extend(screen_root.rglob("*.rs"))
        forbidden = ("navigation.app.state =", ".navigate(", ".go_home(", "go_main_menu(")
        offenders = []
        for path in paths:
            source = path.read_text()
            if any(token in source for token in forbidden):
                offenders.append(path.relative_to(ROOT).as_posix())
        self.assertEqual(offenders, [], "renderers/screens must not own AppState transitions")

    def test_multiframe_qr_navigation_is_prepared_before_render(self) -> None:
        prep = read("apps/signer-firmware/src/runtime/qr_presentation.rs")
        redraw = read("apps/signer-firmware/src/ui/redraw.rs")
        qr = read("apps/signer-firmware/src/ui/redraw/signing/qr.rs")
        self.assertIn("prepare_navigation(ad)", redraw)
        self.assertIn("effects::route(ad, crate::runtime::navigation::route!(ShowQrModeChoice))", prep)
        self.assertIn("qr.outgoing.frame_count = frame_count as u8", prep)
        self.assertNotIn("navigation.app.state =", qr)
        self.assertNotIn("draw_qr_mode_choice", qr)

    def test_main_menu_bypasses_hardware_rich_generic_router(self) -> None:
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        menu = read("apps/signer-firmware/src/runtime/interactions/menu.rs")
        routes = read("apps/signer-firmware/src/runtime/event_loop/touch_routes.rs")

        root_branch = dispatch[dispatch.index("if $ad.navigation.app.state == $crate::runtime::input::AppState::MainMenu"):dispatch.index("if !$crate::runtime::navigation::reconcile($ad)")]
        self.assertIn("handle_root_touch($ad, x, y)", root_branch)
        self.assertNotIn("route_touch!", root_branch)
        self.assertNotIn("&mut $i2c", root_branch)
        self.assertNotIn("&mut $boot_display", root_branch)
        self.assertNotIn("dvp_camera_opt", root_branch)
        self.assertNotIn("cam_dma_buf_opt", root_branch)

        root = menu[menu.index("pub fn handle_root_touch"):menu.index("/// Handle hardware-owning", menu.index("pub fn handle_root_touch"))]
        self.assertIn("primary::handle_root_touch", root)
        primary = read("apps/signer-firmware/src/runtime/interactions/menu/primary.rs")
        primary_root = primary[primary.index("pub(super) fn handle_root_touch"):primary.index("pub(super) fn handle_main_menu")]
        self.assertIn("handle_main_menu(ad, &crate::ui::layout::HOME_GRID_ZONES, x, y)", primary_root)
        self.assertNotIn("I2c", root)
        self.assertNotIn("BootDisplay", root)
        self.assertNotIn("DvpCamera", root)
        self.assertNotIn("DmaRxBuf", root)

        nav = menu[menu.index("pub fn handle_navigation_touch"):menu.index("/// Dedicated hardware-free Home dispatcher")]
        self.assertIn("primary::handle_navigation_touch", nav)
        self.assertNotIn("boot_display", nav)
        self.assertNotIn("i2c", nav)
        self.assertNotIn("dvp_camera_opt", nav)
        self.assertIn("handle_navigation_touch", routes)


    def test_settings_root_menu_is_pure_and_uses_same_release_safe_event_loop(self) -> None:
        settings = read("apps/signer-firmware/src/runtime/interactions/settings/mod.rs")
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        pure_dispatch = read("apps/signer-firmware/src/runtime/event_loop/settings_dispatch.rs")
        routes = read("apps/signer-firmware/src/runtime/event_loop/touch_routes.rs")
        self.assertIn("pub fn handle_settings_menu_navigation", settings)
        pure = settings[settings.index("pub fn handle_settings_menu_navigation"):settings.index("pub fn handle_settings_touch")]
        self.assertNotIn("BootDisplay", pure)
        self.assertNotIn("I2c", pure)
        self.assertNotIn("DvpCamera", pure)
        self.assertIn("settings_dispatch::handle", dispatch)
        self.assertIn("SettingsMenu pure dispatch BEGIN", pure_dispatch)
        self.assertIn("handle_settings_menu_navigation", pure_dispatch)
        context = settings[settings.index("pub struct SettingsTouchContext"):settings.index("/// Route the Settings root menu")]
        self.assertNotIn("list_zones", context)
        self.assertNotIn("page_up_zone", context)
        self.assertNotIn("page_down_zone", context)
        settings_branch = routes[routes.index("InteractionDomain::Settings"):routes.index("InteractionDomain::WorkflowTests") if "InteractionDomain::WorkflowTests" in routes else routes.index("InteractionDomain::Signing")]
        self.assertNotIn("list_zones", settings_branch)

    def test_m5stack_display_settings_bypasses_generic_hardware_router(self) -> None:
        settings = read("apps/signer-firmware/src/runtime/interactions/settings/mod.rs")
        display = read("apps/signer-firmware/src/runtime/interactions/settings/display.rs")
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        pure_dispatch = read("apps/signer-firmware/src/runtime/event_loop/settings_dispatch.rs")
        power = read("apps/signer-firmware/src/runtime/power_state.rs")
        loop = read("apps/signer-firmware/src/runtime/event_loop/mod.rs")

        self.assertIn("pub fn handle_display_settings_navigation", settings)
        pure = settings[settings.index("pub fn handle_display_settings_navigation"):settings.index("/// Route Audio Settings")]
        self.assertNotIn("BootDisplay", pure)
        self.assertNotIn("I2c", pure)
        self.assertNotIn("sd_card", pure)
        self.assertNotIn("Dma", pure)

        m5 = display[display.index('#[cfg(feature = "m5stack")]'):display.index('#[cfg(feature = "waveshare")]')]
        self.assertIn("ad.settings.brightness = value", m5)
        self.assertNotIn("BootDisplay", m5)
        self.assertNotIn("I2c", m5)
        self.assertNotIn("set_brightness", m5)
        self.assertNotIn("update_brightness_bar", m5)

        branch = pure_dispatch[pure_dispatch.index("AppState::DisplaySettings"):pure_dispatch.index("AppState::AudioSettings")]
        self.assertIn("handle_display_settings_navigation", branch)
        self.assertNotIn("route_touch!", branch)
        self.assertNotIn("boot_display", branch)
        self.assertNotIn("i2c", branch)
        self.assertNotIn("dvp_camera_opt", branch)
        self.assertNotIn("cam_dma_buf_opt", branch)
        self.assertIn("settings_dispatch::handle", dispatch)

        self.assertIn("pub(crate) fn apply_requested_brightness", power)
        self.assertIn("set_brightness!(i2c, requested)", power)
        self.assertIn("apply_requested_brightness($ad, &mut $i2c, &mut applied_brightness)", loop)

    def test_multisig_descriptor_qr_dismisses_back_to_descriptor(self) -> None:
        output = read("apps/signer-firmware/src/runtime/interactions/tx/multisig_output.rs")
        presentation = read("apps/signer-firmware/src/runtime/interactions/menu/qr/presentation.rs")
        workflow = read("apps/signer-firmware/src/runtime/workflow_tests/connected/multisig/output.rs")

        descriptor_branch = output[output.index("fn handle_descriptor"):output.index("fn prepare_filename")]
        self.assertIn(
            "ad.qr.outgoing.close_state = Some(crate::runtime::navigation::continuation!(MultisigDescriptor));",
            descriptor_branch,
        )
        self.assertIn("if let Some(target) = ad.qr.outgoing.close_state", presentation)
        self.assertIn("crate::runtime::effects::continue_to(ad, target)", presentation)
        self.assertIn("ctx.menu_touch(160, 120, false)", workflow)
        self.assertIn("ctx.ad.navigation.app.state != AppState::MultisigDescriptor", workflow)

    def test_multisig_descriptor_global_back_is_stable_and_sd_title_fits(self) -> None:
        back = read("apps/signer-firmware/src/runtime/navigation/back.rs")
        workflow = read("apps/signer-firmware/src/runtime/workflow_tests/connected/multisig/output.rs")
        prompts = read("apps/signer-firmware/src/ui/redraw/storage/prompts.rs")
        self.assertIn(
            "MultisigDescriptor if ad.signing.multisig.creating.active => MultisigShowAddress",
            back,
        )
        self.assertIn("MultisigDescriptor => SdImportMenu", back)
        self.assertIn("crate::runtime::navigation::handle_back(ctx.ad)", workflow)
        self.assertIn('"DESC FILENAME"', prompts)
        self.assertNotIn('"DESCRIPTOR FILENAME"', prompts)

    def test_about_navigation_does_not_enter_hardware_settings_facade(self) -> None:
        settings = read("apps/signer-firmware/src/runtime/interactions/settings/mod.rs")
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        pure_dispatch = read("apps/signer-firmware/src/runtime/event_loop/settings_dispatch.rs")
        self.assertIn("pub fn handle_about_navigation", settings)
        hardware = settings[settings.index("pub fn handle_settings_touch"): ]
        self.assertNotIn("AppState::About", hardware)
        self.assertIn("handle_about_navigation", pure_dispatch)
        self.assertIn("settings_dispatch::handle", dispatch)

    def test_m5stack_audio_settings_bypasses_generic_hardware_router(self) -> None:
        settings = read("apps/signer-firmware/src/runtime/interactions/settings/mod.rs")
        audio = read("apps/signer-firmware/src/runtime/interactions/settings/audio.rs")
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        pure_dispatch = read("apps/signer-firmware/src/runtime/event_loop/settings_dispatch.rs")

        self.assertIn("pub fn handle_audio_settings_navigation", settings)
        pure = settings[settings.index("pub fn handle_audio_settings_navigation"):settings.index("pub fn handle_settings_touch")]
        self.assertNotIn("BootDisplay", pure)
        self.assertNotIn("I2c", pure)
        self.assertNotIn("sd_card", pure)
        self.assertNotIn("Dma", pure)
        self.assertNotIn("update_volume_bar", audio)
        self.assertNotIn("BootDisplay", audio)
        self.assertIn("ad.settings.set_volume(value)", audio)
        self.assertIn("sound::set_volume(ad.settings.volume)", audio)

        start = pure_dispatch.index("AppState::AudioSettings")
        end = pure_dispatch.index("AppState::About", start)
        branch = pure_dispatch[start:end]
        self.assertIn("handle_audio_settings_navigation", branch)
        self.assertNotIn("route_touch!", branch)
        self.assertNotIn("boot_display", branch)
        self.assertNotIn("i2c", branch)
        self.assertNotIn("dvp_camera_opt", branch)
        self.assertNotIn("cam_dma_buf_opt", branch)
        self.assertIn("settings_dispatch::handle", dispatch)

        hardware = settings[settings.index("pub fn handle_settings_touch"):]
        self.assertNotIn("AppState::AudioSettings", hardware)

    def test_m5stack_settings_and_common_menus_bypass_generic_capability_router(self) -> None:
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        routes = read("apps/signer-firmware/src/runtime/event_loop/touch_routes.rs")
        primary = read("apps/signer-firmware/src/runtime/interactions/menu/primary.rs")
        settings_dispatch = read("apps/signer-firmware/src/runtime/event_loop/settings_dispatch.rs")
        nav_dispatch = read("apps/signer-firmware/src/runtime/event_loop/navigation_dispatch.rs")

        route_at = dispatch.index("touch_routes::route_touch!")
        pure_dispatch_at = dispatch.index("navigation_dispatch::handle_pure")
        self.assertLess(pure_dispatch_at, route_at)
        self.assertIn("runtime::interactions::menu::handle_navigation_touch", nav_dispatch)
        self.assertIn("runtime::interactions::export::menus::handle_navigation_touch", nav_dispatch)
        for state in ("SeedToolsMenu", "ImportExportChoice", "ImportMenu",
                      "SingleSigMenu", "MultisigMenu", "Rejected"):
            self.assertIn(f"AppState::{state}", primary)

        settings_branch = routes[routes.index('cfg(feature = "waveshare")'):routes.index("InteractionDomain::WorkflowTests") if "InteractionDomain::WorkflowTests" in routes else routes.index("InteractionDomain::Signing")]
        self.assertIn("InteractionDomain::Settings", settings_branch)
        self.assertIn("AppState::SdCardSettings", settings_dispatch)
        self.assertIn("handle_advanced_navigation", settings_dispatch)
        self.assertIn("AppState::SdCardSettings", dispatch)
        sd_direct = dispatch[dispatch.index('AppState::SdCardSettings'):dispatch.index("touch_routes::route_touch!", dispatch.index('AppState::SdCardSettings'))]
        self.assertNotIn("dvp_camera_opt", sd_direct)
        self.assertNotIn("cam_dma_buf_opt", sd_direct)

    def test_pure_export_navigation_precedes_hardware_export_context(self) -> None:
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        nav = read("apps/signer-firmware/src/runtime/interactions/export/menus/mod.rs")
        seed = read("apps/signer-firmware/src/runtime/interactions/export/menus/seed.rs")
        nav_dispatch = read("apps/signer-firmware/src/runtime/event_loop/navigation_dispatch.rs")
        route_at = dispatch.index("touch_routes::route_touch!")
        nav_at = dispatch.index("navigation_dispatch::handle_pure")
        self.assertLess(nav_at, route_at)
        self.assertIn("runtime::interactions::export::menus::handle_navigation_touch", nav_dispatch)
        for forbidden in ("BootDisplay", "I2c", "DmaRxBuf", "DvpCamera", "sd_card_type"):
            self.assertNotIn(forbidden, nav)
        self.assertIn("root::handle_pure", nav)
        self.assertIn("seed::handle_pure", nav)
        self.assertIn("signing_keys::handle", nav)
        self.assertIn("handle_seed_backup_pure", seed)
        self.assertIn("handle_qr_export_pure", seed)

    def test_pure_menu_dispatch_stays_behind_parent_facades_and_xprv_exists(self) -> None:
        primary = read("apps/signer-firmware/src/runtime/interactions/menu/primary.rs")
        import_export = read("apps/signer-firmware/src/runtime/interactions/menu/import_export/mod.rs")
        signing = read("apps/signer-firmware/src/runtime/interactions/menu/signing.rs")
        export_nav = read("apps/signer-firmware/src/runtime/interactions/export/menus/mod.rs")
        xprv = read("apps/signer-firmware/src/runtime/interactions/export/xprv.rs")

        # Sibling controller code must call the parent facade instead of reaching
        # into private child modules whose pub(super) visibility stops there.
        self.assertIn("super::import_export::handle_pure", primary)
        self.assertNotIn("import_export::menu::handle_", primary)
        self.assertIn("super::signing::handle_pure", primary)
        self.assertNotIn("signing::single_sig::handle_pure", primary)
        self.assertNotIn("signing::multisig::handle", primary)
        import_menu = read("apps/signer-firmware/src/runtime/interactions/menu/import_export/menu.rs")
        multisig = read("apps/signer-firmware/src/runtime/interactions/menu/signing/multisig.rs")
        self.assertIn("pub(super) fn handle_pure", import_export)
        self.assertIn("menu::handle_pure", import_export)
        self.assertNotIn("match ad.navigation.app.state", import_export[:import_export.index("pub(super) fn handle(")])
        self.assertIn("pub(super) fn handle_pure", import_menu)
        self.assertIn("AppState::ImportExportChoice", import_menu)
        self.assertIn("AppState::ImportMenu", import_menu)
        self.assertIn("pub(super) fn handle_pure", signing)
        self.assertIn("single_sig::handle_pure", signing)
        self.assertIn("multisig::handle_pure", signing)
        self.assertNotIn("match ad.navigation.app.state", signing[:signing.index("pub(super) fn handle(")])
        self.assertIn("pub(super) fn handle_pure", multisig)

        # Every pure-export call emitted by the export-navigation facade must
        # resolve to a real handler. XPRV was the missing definition.
        self.assertIn("super::xprv::handle_pure", export_nav)
        self.assertIn("pub(super) fn handle_pure", xprv)
        pure = xprv[xprv.index("pub(super) fn handle_pure"):xprv.index("pub(super) fn handle(context")]
        self.assertIn("AppState::ExportXprv", pure)
        self.assertIn("AppState::XprvExportMenu", pure)
        for forbidden in ("BootDisplay", "I2c", "sd_card_type", "show_xprv", "scan_auto_increment"):
            self.assertNotIn(forbidden, pure)

    def test_advanced_edit_cancel_paths_are_hardware_free_before_commit(self) -> None:
        advanced = read("apps/signer-firmware/src/runtime/interactions/settings/advanced/mod.rs")
        pure = advanced[advanced.index("pub(crate) fn handle_pure"):advanced.index("pub(crate) fn handle(", advanced.index("pub(crate) fn handle_pure") + 1)]
        for forbidden in ("BootDisplay", "PersistentWallet", "I2c", "DmaRxBuf", "DvpCamera"):
            self.assertNotIn(forbidden, pure)
        self.assertIn("handle_pure_warning", pure)
        self.assertIn("handle_pure_entry", pure)
        self.assertIn("handle_pure_confirm", pure)
        self.assertIn("EditAction::Submitted => None", pure)

    def test_partial_brightness_bar_is_waveshare_only(self) -> None:
        screen = read("apps/signer-firmware/src/ui/screens/device/settings.rs")
        marker = '#[cfg(feature = "waveshare")]\n    pub fn update_brightness_bar'
        self.assertIn(marker, screen)

    def test_m5stack_does_not_compile_unreachable_display_drag_handler(self) -> None:
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        settings_dispatch = read("apps/signer-firmware/src/runtime/event_loop/settings_dispatch.rs")
        m5_touch = read("apps/signer-firmware/src/hw/m5stack/touch/mod.rs")

        # CoreS3 uses the FT6336U ContactGate edge model and does not dispatch
        # Drag actions. Keeping a CoreS3 drag reducer only creates dead code.
        self.assertIn("contact_gate::ContactGate", m5_touch)
        self.assertNotIn('#[cfg(feature = "m5stack")]\npub(crate) fn handle_display_drag', settings_dispatch)
        self.assertEqual(settings_dispatch.count("pub(crate) fn handle_display_drag"), 1)
        self.assertIn('#[cfg(feature = "waveshare")]\npub(crate) fn handle_display_drag', settings_dispatch)
        drag_area = dispatch[dispatch.index("// ─── Waveshare: swipe gestures + drag"):dispatch.index("pub(crate) use handle_action")]
        self.assertIn('#[cfg(feature = "waveshare")]', drag_area)
        self.assertNotIn('#[cfg(feature = "m5stack")]', drag_area)

    def test_seeds_root_render_is_state_pure_and_seed_controller_owned(self) -> None:
        inventory = read("apps/signer-firmware/src/ui/redraw/wallet/inventory.rs")
        routing = read("apps/signer-firmware/src/runtime/input/routing.rs")
        seed_facade = read("apps/signer-firmware/src/runtime/interactions/seed/seed_list.rs")
        primary = read("apps/signer-firmware/src/runtime/interactions/menu/primary.rs")

        production = read("apps/signer-firmware/src/ui/redraw/navigation/production.rs")
        production_controller = read("apps/signer-firmware/src/runtime/interactions/menu/primary/production.rs")
        self.assertIn('AppState::SeedsMenu => boot_display.update_menu_content("WALLET"', production)
        self.assertIn("AppState::SeedList => draw_seed_list", inventory)
        self.assertNotIn("ad.navigation.app.state =", inventory)
        self.assertIn("AppState::SeedsMenu =>", production_controller)
        self.assertNotIn("I2c", production_controller)
        self.assertNotIn("DvpCamera", production_controller)
        self.assertNotIn("DmaRxBuf", production_controller)
        self.assertNotIn("AppState::SeedsMenu =>", primary)

    def test_global_escape_and_multisig_setup_are_hardware_free(self) -> None:
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        back = read("apps/signer-firmware/src/runtime/navigation/back.rs")
        reconcile = dispatch.index("runtime::navigation::reconcile($ad)")
        back_at = dispatch.index("runtime::navigation::handle_back($ad)", reconcile)
        settings_at = dispatch.index("settings_dispatch::handle", back_at)
        route_at = dispatch.index("touch_routes::route_touch!", settings_at)
        pure_at = dispatch.index("navigation_dispatch::handle_pure", settings_at)
        nav_dispatch = read("apps/signer-firmware/src/runtime/event_loop/navigation_dispatch.rs")
        self.assertLess(back_at, settings_at)
        self.assertLess(pure_at, route_at)
        self.assertNotIn("let is_home = (52..=82).contains(&x)", dispatch)

        for state in ("SeedList", "ConfirmDeleteSeed", "MultisigChooseMN",
                      "MultisigAddKey", "MultisigPickSeed"):
            self.assertIn(state, back)
        nav_dispatch = read("apps/signer-firmware/src/runtime/event_loop/navigation_dispatch.rs")
        seed = read("apps/signer-firmware/src/runtime/interactions/seed.rs")
        menu = read("apps/signer-firmware/src/runtime/interactions/menu.rs")
        self.assertIn("handle_inventory_touch", nav_dispatch)
        self.assertIn("handle_signing_feedback_touch", nav_dispatch)
        inventory = seed[seed.index("pub fn handle_inventory_touch"):seed.index("/// Handle touch events", seed.index("pub fn handle_inventory_touch"))]
        self.assertNotIn("I2c", inventory)
        self.assertNotIn("sd_card", inventory)
        production = read("apps/signer-firmware/src/runtime/interactions/menu/primary/production.rs")
        self.assertIn("AppState::SeedsMenu =>", production)
        self.assertNotIn("I2c", production)
        narrow = menu[menu.index("pub fn handle_signing_feedback_touch"):menu.index('#[cfg(feature = "workflow-test-auto")]', menu.index("pub fn handle_signing_feedback_touch"))]
        self.assertNotIn("I2c", narrow)
        self.assertNotIn("DvpCamera", narrow)
        self.assertNotIn("DmaRxBuf", narrow)

    def test_export_touch_context_router_initializer_supplies_all_zone_capabilities(self) -> None:
        context = read("apps/signer-firmware/src/runtime/interactions/export/context.rs")
        routes = read("apps/signer-firmware/src/runtime/event_loop/touch_routes.rs")

        definition = context[context.index("pub struct ExportTouchContext"):context.index("/// Capabilities for export menus")]
        export_branch = routes[routes.index("InteractionDomain::Export"):routes.index("InteractionDomain::Persistence")]
        initializer = export_branch[export_branch.index("ExportTouchContext {"):export_branch.index("},", export_branch.index("ExportTouchContext {"))]

        for field in ("ad", "boot_display", "delay", "i2c", "sd_card_type",
                      "list_zones", "page_up_zone", "page_down_zone", "input"):
            self.assertIn(f"pub {field}:", definition)
            if field in {"list_zones", "page_up_zone", "page_down_zone"}:
                self.assertIn(f"{field}: &$" + field, initializer)
            else:
                self.assertIn(f"{field}:", initializer) if field != "input" else self.assertIn("input", initializer)

    def test_consumed_taps_cannot_skip_shared_frame_tail(self) -> None:
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        loop = read("apps/signer-firmware/src/runtime/event_loop/mod.rs")

        tap_start = dispatch.index("'tap_dispatch: {")
        tap_end = dispatch.index("// ─── Waveshare: swipe gestures + drag", tap_start)
        tap_block = dispatch[tap_start:tap_end]
        self.assertNotIn("continue;", tap_block)
        self.assertIn("break 'tap_dispatch;", tap_block)
        self.assertIn("handle_root_touch($ad, x, y)", tap_block)
        self.assertIn("$ad.runtime.needs_redraw = true;", tap_block)
        dispatch_at = loop.index("event_loop::dispatch::handle_action!")
        frame_at = loop.index("event_loop::frame::finish_frame!", dispatch_at)
        self.assertLess(dispatch_at, frame_at)
        frame = read("apps/signer-firmware/src/runtime/event_loop/frame.rs")
        self.assertIn('NAV redraw BEGIN: {:?}', frame)
        self.assertIn('NAV redraw DONE: {:?}', frame)

    def test_main_to_settings_is_an_explicit_committed_root_transition(self) -> None:
        root = read("apps/signer-firmware/src/runtime/navigation/root.rs")
        policy = read("apps/signer-firmware/src/runtime/navigation/policy.rs")
        facade = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
        primary = read("apps/signer-firmware/src/runtime/interactions/menu/primary.rs")

        self.assertIn("3 => Some((AppState::SettingsMenu, Settings))", root)
        self.assertIn("AppState::ShowAddress | AppState::ScanQR | AppState::SeedsMenu | AppState::SettingsMenu", root)
        self.assertIn("pub(crate) fn transition_root", facade)
        self.assertIn("root::root_route(index).map(|route| route.0)?", facade)
        self.assertIn("kernel::dispatch(ad, UiEvent::RootSelect(event_index))", facade)
        self.assertIn("super::root::transition_allowed(to_state)", policy)
        self.assertIn("Main => matches!(to, Seeds | Settings | Signing | Export)", policy)
        self.assertIn("prepare_owner_entry(ad, transition.owner)", read("apps/signer-firmware/src/runtime/navigation/kernel.rs"))
        self.assertIn("NavigationOwner::Settings => ad.navigation.settings_menu.reset()", read("apps/signer-firmware/src/runtime/navigation/kernel.rs"))
        self.assertIn("main_menu_target_at(x, y)", primary)
        self.assertIn("crate::runtime::effects::root(ad, index)", primary)
        self.assertNotIn("handle_boot", primary)
        self.assertNotIn("ad.navigation.app.state =", primary)

    def test_cores3_physical_touch_gate_and_home_geometry_cannot_drop_settings_tap(self) -> None:
        touch = read("apps/signer-firmware/src/hw/m5stack/touch/mod.rs")
        gate = read("crates/signer-firmware-core/src/input/touch/contact_gate.rs")
        touch_tests = read("apps/signer-firmware/src/hw/m5stack/touch/unit_tests/mod.rs")
        layout = read("apps/signer-firmware/src/ui/layout.rs")
        touch_dispatch = read("apps/signer-firmware/src/runtime/touch_dispatch.rs")
        home = read("apps/signer-firmware/src/ui/screens/navigation/home.rs")

        self.assertIn("touch::contact_gate::ContactGate", touch)
        self.assertIn("TouchEventType::PressDown => self.observe_press_down", gate)
        self.assertIn("TouchEventType::Contact => self.observe_contact", gate)
        self.assertIn("TouchAction::Tap { x, y }", gate)
        self.assertNotIn("navigation_changed", gate)
        self.assertNotIn("MISSED_RELEASE_REARM_SAMPLES", gate)
        self.assertIn("if !self.is_down", gate)
        self.assertIn("pub fn require_release", gate)
        self.assertIn("release_required", gate)
        self.assertIn("screen_transition_requires_release_before_next_screen_contact",
                      read("crates/signer-firmware-core/src/unit_tests/firmware_decisions/contact_gate.rs"))
        self.assertIn("read_touch_checked", touch)
        touch_owner = read("crates/signer-firmware-core/src/input/touch.rs")
        self.assertTrue(touch_owner.startswith("//! Board-neutral touch contracts"))
        self.assertIn("pub mod contact_gate;", touch_owner)
        self.assertIn("clearly new PressDown recovers after a missed release", touch_tests)
        self.assertIn("held-contact samples never synthesize duplicate taps", touch_tests)
        loop = read("apps/signer-firmware/src/runtime/event_loop/mod.rs")
        self.assertNotIn("on_navigation_commit", loop)
        frame = read("apps/signer-firmware/src/runtime/event_loop/frame.rs")
        presentation_frame = read("apps/signer-firmware/src/runtime/event_loop/navigation_dispatch.rs")
        self.assertIn("arm_release_for_state", frame)
        self.assertIn("tracker.require_release()", presentation_frame)
        self.assertIn("tracker.require_strict_release()", presentation_frame)
        self.assertIn("NAV frame input release barrier armed", frame)
        self.assertNotIn("TouchTracker::new()", frame)
        touch_poll = read("apps/signer-firmware/src/runtime/event_loop/touch.rs")
        self.assertIn("touch_service::read_checked", touch_poll)
        self.assertIn("release barrier cleared", touch_poll)
        self.assertIn("I2C read failed — gate preserved", touch_poll)
        self.assertIn("sample {:?} -> {:?}", touch_poll)
        self.assertIn("x: 238, y: 188", touch_tests)
        self.assertIn("HOME_GRID_ZONES", layout)
        self.assertIn("TouchZone::new(164, 143", layout)
        self.assertIn("crate::ui::layout::HOME_GRID_ZONES", touch_dispatch)
        self.assertIn("crate::ui::layout::HOME_GRID_ZONES[i]", home)
        self.assertNotIn("TouchZone::new(162, 145", touch_dispatch)
        # A decoded CoreS3 tap must not perform an unrelated PMU write before dispatch.
        touch_poll = read("apps/signer-firmware/src/runtime/event_loop/touch.rs")
        ordinary_touch = touch_poll.split("// Dim-first-touch suppression", 1)[1].split("// Idle dimming / sleep", 1)[0]
        self.assertEqual(ordinary_touch.count("set_brightness!"), 1)
        self.assertIn("Brightness restoration belongs only", ordinary_touch)
        loop = read("apps/signer-firmware/src/runtime/event_loop/mod.rs")
        self.assertIn('navigation_dispatch::log_main_tap_boundary($ad, action, "dispatch boundary reached")', loop)
        self.assertIn('navigation_dispatch::log_main_tap_boundary($ad, action, "dispatch BEGIN")', loop)
        self.assertIn("TOUCH CoreS3 MainMenu {}", read("apps/signer-firmware/src/runtime/event_loop/navigation_dispatch.rs"))

    def test_cores3_wake_has_one_touch_poll_owner_and_no_post_wake_tap_debounce(self) -> None:
        touch_poll = read("apps/signer-firmware/src/runtime/event_loop/touch.rs")
        power = read("apps/signer-firmware/src/runtime/power_state.rs")

        self.assertIn("let raw_touch = !matches!($touch_state", touch_poll)
        self.assertIn("if raw_touch || is_touch {", touch_poll)
        self.assertIn("$tracker.require_release();", touch_poll)
        self.assertIn("$wake_debounce = 0;", touch_poll)
        self.assertIn("dim wake DONE — release gate armed", touch_poll)

        wake = power[power.index("pub(crate) fn handle_wake"):power.index("pub(crate) fn handle_idle")]
        self.assertIn("physical_touch: bool", wake)
        self.assertIn("tracker.require_release();", wake)
        self.assertIn("*wake_debounce = 0;", wake)
        self.assertIn("sleep wake DONE — release gate armed", wake)
        self.assertNotIn("read_touch(", wake)
        self.assertNotIn("TouchTracker::new()", wake)
        self.assertNotIn("for _ in 0..80", wake)
        self.assertNotIn("delay.delay_millis(500)", wake)

    def test_renderers_cannot_own_settings_navigation(self) -> None:
        redraw = read("apps/signer-firmware/src/ui/redraw/navigation.rs")
        about_at = redraw.index("AppState::About")
        about = redraw[about_at:redraw.index("_ => return false", about_at)]

        self.assertIn("draw_about_screen()", about)
        self.assertNotIn("Delay::new", about)
        self.assertNotIn("delay_millis", about)
        self.assertNotIn("app.state =", about)
        self.assertNotIn("navigate(", about)

    def test_m5_navigation_click_queues_to_owned_runtime_audio_after_state_commit(self) -> None:
        sound = read("apps/signer-firmware/src/hw/m5stack/sound.rs")
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        click_at = sound.index("pub fn click()")
        click = sound[click_at:sound.index("pub fn qr_found", click_at)]

        self.assertIn("request(CUE_CLICK)", click)
        self.assertIn("pub(crate) struct RuntimeAudio", sound)
        self.assertIn("self.tx.write_dma_circular(&words)", sound)
        self.assertIn("SOUND_DMA_TIMEOUT", sound)
        self.assertIn("service_pending", sound)
        self.assertNotIn("AtomicPtr", sound)
        self.assertNotIn("StaticCell<SoundTx>", sound)
        self.assertNotIn("unsafe {", sound)
        route_at = dispatch.index("touch_routes::route_touch!")
        reconcile_at = dispatch.index("runtime::navigation::reconcile($ad)", route_at)
        click_after = dispatch.index("if click_after_route && handled {", reconcile_at)
        audio_after = dispatch.index("event_loop::audio::click($ad, &mut $runtime_audio)", click_after)
        self.assertLess(route_at, reconcile_at)
        self.assertLess(reconcile_at, click_after)
        self.assertLess(click_after, audio_after)

    def test_settings_cannot_cross_into_signing_or_qr_results(self) -> None:
        policy = read("apps/signer-firmware/src/runtime/navigation/policy.rs")
        facade = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
        qr = read("apps/signer-firmware/src/runtime/data/qr.rs")
        signing = read("apps/signer-firmware/src/runtime/signing/workflow.rs")

        self.assertIn("Settings => matches!(to, Main | Seeds | Signing | Export | Storage | Stego | Multisig)", policy)
        production = read("apps/signer-firmware/src/runtime/navigation/production.rs")
        self.assertNotIn("Covenant Sign", production)
        self.assertNotIn("Private Swap", production)
        self.assertNotIn("Anti-Klepto", production)
        self.assertNotIn("Stealth", production)
        self.assertIn("Settings => AppState::SettingsMenu", policy)
        self.assertIn("ShowQrPopup", facade)
        self.assertIn("OutgoingQrPurpose::SignedTransaction", facade)
        self.assertIn("clear_abandoned_workflow", read("apps/signer-firmware/src/runtime/navigation/kernel.rs"))
        self.assertIn("ad.qr.outgoing.clear()", read("apps/signer-firmware/src/runtime/navigation/kernel.rs"))
        self.assertNotIn("Generic", qr)
        self.assertIn("OutgoingQrPurpose::SignedTransaction", signing)




    def test_settings_and_persistence_use_navigation_facade(self) -> None:
        paths = [ROOT / path for path in ("apps/signer-firmware/src/runtime/interactions/persistence.rs", "apps/signer-firmware/src/runtime/interactions/persistence/onboarding.rs", "apps/signer-firmware/src/runtime/interactions/persistence/credential.rs")]
        paths += list((ROOT / "apps/signer-firmware/src/runtime/interactions/settings").rglob("*.rs"))
        for path in paths:
            source = path.read_text()
            self.assertNotRegex(source, r"ad\.navigation\.app\.state\s*=(?!=)", path.as_posix())
            self.assertNotIn("ad.navigation.app.go_main_menu()", source, path.as_posix())

    def test_passphrase_back_returns_to_choice_without_abandoning_seed(self) -> None:
        back = read("apps/signer-firmware/src/runtime/navigation/back.rs")
        entry = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")
        app = read("apps/signer-firmware/src/runtime/input/wallet_app.rs")

        self.assertIn("PassphraseEntry => PassphraseChoice", back)
        self.assertIn("PassphraseEntry => ad.wallet.seeds.pp_input.reset()", back)
        self.assertNotIn("cancel_unstored_seed", back)
        self.assertIn("crate::runtime::effects::route(ad, crate::runtime::navigation::route!(PassphraseChoice))", entry)
        returns = app[app.index("fn returns_to_main_on_press"): ]
        self.assertNotIn("PassphraseEntry", returns)
        self.assertNotIn("PassphraseChoice", returns)

    def test_seed_failure_navigation_does_not_nest_mutable_appdata_borrows(self) -> None:
        entry = read("apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs")

        self.assertNotIn("route_dynamic!", entry)
        self.assertEqual(entry.count("recover_seed_setup_failure(ad);"), 2)
        helper = entry[entry.index("fn recover_seed_setup_failure"):entry.index("fn first_empty_multisig_key")]
        self.assertIn("ReturnScope::SeedTool", helper)
        self.assertIn("route!(StorageSeedSourceChoice)", helper)
        self.assertIn("route!(StorageSeedWordCountChoice { action: 0 })", helper)

    def test_onboarding_requires_guarded_terminal_transition(self) -> None:
        policy = read("apps/signer-firmware/src/runtime/navigation/policy.rs")
        facade = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
        persistent_nav = read("apps/signer-firmware/src/runtime/interactions/persistence.rs")
        persistence = "\n".join(read(path) for path in ("apps/signer-firmware/src/runtime/interactions/persistence.rs", "apps/signer-firmware/src/runtime/interactions/persistence/onboarding.rs", "apps/signer-firmware/src/runtime/interactions/persistence/credential.rs", "apps/signer-firmware/src/runtime/event_loop/operation_engine/credential/result.rs"))

        self.assertIn("if to_state == AppState::MainMenu { return from != NavigationOwner::Onboarding; }", policy)
        terminal = facade[facade.index("pub(crate) fn complete_onboarding"):facade.index("fn result_screen_is_valid", facade.index("pub(crate) fn complete_onboarding"))]
        self.assertIn("NavigationOwner::Onboarding", terminal)
        self.assertIn("intent.is_seed_onboarding()", terminal)
        self.assertIn("recovery_words_acknowledged", terminal)
        self.assertIn("seed_loaded", terminal)
        self.assertIn("ad.storage.persistence.reset()", terminal)
        self.assertIn("kernel::force_commit(ad, AppState::MainMenu, NavigationOwner::Main, true)", terminal)
        self.assertIn("complete_onboarding(ad)", persistent_nav)
        self.assertIn("complete_onboarding(ad)", persistence)

    def test_sd_recovery_ack_is_owned_by_settings_only_for_sd_enable_intent(self) -> None:
        policy = read("apps/signer-firmware/src/runtime/navigation/policy.rs")
        onboarding = read("apps/signer-firmware/src/runtime/navigation/onboarding.rs")
        self.assertIn("DeviceStorageIntent::EnableSd", policy)
        self.assertIn("is_sd_enable_state(state)", policy)
        self.assertIn("return NavigationOwner::Settings", policy)
        self.assertIn("super::onboarding::owns_state(intent, state)", policy)
        self.assertIn("intent.is_seed_onboarding()", onboarding)
        self.assertIn("StorageRecoveryAcknowledgement", onboarding)

    def test_onboarding_uses_explicit_screen_to_screen_transition_matrix(self) -> None:
        policy = read("apps/signer-firmware/src/runtime/navigation/policy.rs")
        matrix = read("apps/signer-firmware/src/runtime/navigation/onboarding.rs")

        self.assertIn("super::onboarding::transition_allowed(from_state, to_state)", policy)
        self.assertIn("source_transition_allowed(from, to)", matrix)
        self.assertIn("entropy_transition_allowed(from, to)", matrix)
        self.assertIn("seed_entry_transition_allowed(from, to)", matrix)
        self.assertIn("recovery_transition_allowed(from, to)", matrix)
        self.assertIn("credential_transition_allowed(from, to)", matrix)
        self.assertIn("StorageModeChoice => matches!(to, StorageSeedSourceChoice | WalletNameEntry { purpose: 0 })", matrix)
        self.assertIn("WalletNameEntry { purpose: 0 } => matches!(to, StorageModeChoice | StorageSeedWordCountChoice { action: 0 })", matrix)
        self.assertIn("RestoreWord { word_idx: 0 }", matrix)
        self.assertIn("RestoreWord12Detected", matrix)
        self.assertIn("StorageSeedDiceCountChoice", matrix)
        self.assertIn("StorageSeedTouchChoice", matrix)
        self.assertIn("PassphraseChoice", matrix)
        self.assertIn("StorageRecoveryAcknowledgement", matrix)
        self.assertIn("StorageFinalizeChoice", matrix)
        self.assertIn("StorageCredentialType", matrix)
        self.assertIn("_ => false", matrix)

    def test_optional_touch_entropy_follows_optional_dice_and_is_additive(self) -> None:
        state = read("apps/signer-firmware/src/runtime/input/state.rs")
        additive = read("apps/signer-firmware/src/runtime/interactions/menu/seed_generation/additive.rs")
        mixer = read("apps/signer-firmware/src/services/entropy/mixer.rs")
        touch = read("apps/signer-firmware/src/runtime/event_loop/touch_entropy.rs")
        ui = read("apps/signer-firmware/src/ui/screens/device/persistence.rs")

        self.assertIn("StorageSeedTouchChoice", state)
        branch_at = additive.index("if NO_DICE_BUTTON_Y.contains")
        no_dice = additive[branch_at:additive.index("} else if ADD_DICE_BUTTON_Y.contains", branch_at)]
        self.assertIn("StorageSeedTouchChoice", no_dice)
        self.assertIn("crate::runtime::effects::route(ad, crate::runtime::navigation::route!(StorageSeedTouchChoice))", additive)
        self.assertIn("NO_TOUCH_BUTTON_Y", additive)
        self.assertIn("ADD_TOUCH_BUTTON_Y", additive)
        self.assertIn('b"KasSigner/additive-touch/v1"', mixer)
        self.assertIn("mix_additive_touch", touch)
        self.assertIn("finalize_staged_entropy", touch)
        self.assertIn('"ADD TOUCH"', ui)
        self.assertIn('"No Touch Entropy"', ui)
        self.assertIn('"Add Touch Entropy"', ui)

    def test_all_touch_routes_reconcile_after_workflow_dispatch(self) -> None:
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        routes = read("apps/signer-firmware/src/runtime/event_loop/touch_routes.rs")
        self.assertGreaterEqual(dispatch.count("runtime::navigation::reconcile($ad)"), 5)
        self.assertNotIn("runtime::interactions::persistence::handle", dispatch)
        self.assertIn("InteractionDomain::Persistence", routes)
        self.assertIn("runtime::interactions::persistence::handle", routes)
        self.assertIn("runtime::interactions::settings::advanced::handle", dispatch)
        self.assertIn("TouchAction::SwipeLeft", dispatch)
        self.assertIn("TouchAction::SwipeRight", dispatch)

    def test_onboarding_owner_routes_before_generic_screen_family(self) -> None:
        routes = read("apps/signer-firmware/src/runtime/event_loop/touch_routes.rs")
        onboarding = read("apps/signer-firmware/src/runtime/interactions/onboarding.rs")
        state_machine = read("apps/signer-firmware/src/runtime/navigation/onboarding.rs")
        navigation = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
        routing = read("apps/signer-firmware/src/runtime/input/routing.rs")

        owner_at = routes.index("runtime::navigation::is_onboarding($ad)")
        generic_at = routes.index("controllers::classify(", owner_at)
        self.assertLess(owner_at, generic_at)
        self.assertIn("handle_onboarding_touch", routes[owner_at:generic_at])
        self.assertIn("HandlerGroup::Persistence", routing)
        self.assertIn("pub(crate) enum OnboardingRoute", state_machine)
        self.assertIn("StorageSeedWordCountChoice { .. }", state_machine)
        self.assertIn("Some(Generation)", state_machine)
        self.assertIn("route_for(intent, state).is_some()", state_machine)
        self.assertIn("onboarding_route(ad)", onboarding)
        self.assertIn("OnboardingRoute::Generation", onboarding)
        self.assertIn("runtime::interactions::menu::seed_generation::handle", onboarding)
        self.assertIn("OnboardingRoute::Dice", onboarding)
        self.assertIn("handle_onboarding_dice", onboarding)
        self.assertIn("OnboardingRoute::RecoveryWords", onboarding)
        self.assertIn("export::seed_backup::handle", onboarding)
        self.assertIn("onboarding::route_for", navigation)

    def test_create_mnemonic_word_count_taps_are_live_and_share_render_geometry(self) -> None:
        generation = read("apps/signer-firmware/src/runtime/interactions/menu/seed_generation.rs")
        state_machine = read("apps/signer-firmware/src/runtime/navigation/onboarding.rs")
        wallet = read("apps/signer-firmware/src/ui/screens/wallet/mod.rs")
        keyboard = read("apps/signer-firmware/src/ui/screens/wallet/keyboard.rs")
        screens = read("apps/signer-firmware/src/ui/screens.rs")

        self.assertIn("StorageSeedWordCountChoice { .. }", state_machine)
        self.assertIn("Some(Generation)", state_machine)
        self.assertIn("crate::ui::screens::word_count_choice_at(x, y)", generation)
        self.assertIn('Onboarding mnemonic length selected: {} words', generation)
        word_count_at = generation.index('let Some(word_count)')
        selected_at = generation.index('Onboarding mnemonic length selected: {} words', word_count_at)
        entropy_at = generation.index('start_word_count_action(', selected_at)
        self.assertLess(selected_at, entropy_at)
        self.assertNotIn('crate::hw::sound::click();', generation[word_count_at:entropy_at])
        dispatch = read("apps/signer-firmware/src/runtime/event_loop/dispatch.rs")
        ack_at = dispatch.index("let word_count_ack = matches!(")
        click_at = dispatch.index("event_loop::audio::click($ad, &mut $runtime_audio)", ack_at)
        route_at = dispatch.index("touch_routes::route_touch!", click_at)
        self.assertIn("word_count_choice_at(x, y)", dispatch[ack_at:route_at])
        self.assertLess(ack_at, click_at)
        self.assertLess(click_at, route_at)
        navigation = read("apps/signer-firmware/src/runtime/navigation/mod.rs")
        router = navigation.split("pub(crate) fn tap_uses_router_click", 1)[1].split("/// Fail closed", 1)[0]
        self.assertIn("StorageSeedWordCountChoice { .. }", router)
        self.assertIn("ChooseWordCount { .. }", router)
        self.assertIn("pub(crate) fn word_count_choice_at", wallet)
        self.assertIn("WORD_COUNT_BUTTON_X", wallet)
        self.assertIn("WORD_COUNT_12_Y", wallet)
        self.assertIn("WORD_COUNT_24_Y", wallet)
        self.assertIn("WORD_COUNT_BUTTON_X", keyboard)
        self.assertIn("WORD_COUNT_12_Y", keyboard)
        self.assertIn("WORD_COUNT_24_Y", keyboard)
        self.assertIn("pub(crate) use wallet::word_count_choice_at", screens)
        self.assertNotIn("fn selected_word_count", generation)

    def test_onboarding_transition_surfaces_do_not_write_raw_screen_state(self) -> None:
        paths = [
            "apps/signer-firmware/src/runtime/interactions/onboarding.rs",
            "apps/signer-firmware/src/runtime/interactions/persistence.rs",
            "apps/signer-firmware/src/runtime/interactions/persistence/onboarding.rs",
            "apps/signer-firmware/src/runtime/interactions/persistence/credential.rs",
            "apps/signer-firmware/src/runtime/interactions/menu/seed_generation.rs",
            "apps/signer-firmware/src/runtime/interactions/menu/seed_generation/additive.rs",
            "apps/signer-firmware/src/runtime/interactions/menu/seed_tools/dice.rs",
            "apps/signer-firmware/src/runtime/interactions/seed/passphrase.rs",
            "apps/signer-firmware/src/runtime/interactions/seed/passphrase_choice.rs",
            "apps/signer-firmware/src/runtime/interactions/seed/import/word_entry.rs",
            "apps/signer-firmware/src/runtime/interactions/seed/import/word_flow.rs",
            "apps/signer-firmware/src/runtime/interactions/export/seed_backup.rs",
        ]
        for relative in paths:
            source = read(relative)
            self.assertNotIn("ad.navigation.app.state =", source, relative)
            self.assertNotIn("ad.navigation.app.go_main_menu()", source, relative)















    def test_menu_guard_denial_is_fail_closed_without_navigation_recovery(self) -> None:
        reducer = read("apps/signer-firmware/src/runtime/navigation/menu_reducer.rs")
        kernel = read("apps/signer-firmware/src/runtime/navigation/kernel.rs")
        backup = read("apps/signer-firmware/src/runtime/workflow_tests/connected/backup.rs")

        self.assertIn("pub(super) enum ResolveError", reducer)
        self.assertIn("GuardDenied", reducer)
        self.assertIn("return Err(ResolveError::GuardDenied)", reducer)
        self.assertIn("MissingItem", reducer)
        self.assertIn("MissingDestination", reducer)
        self.assertIn("Err(Rejection::MenuGuardDenied)", kernel)
        guard_branch = kernel.split("Err(Rejection::MenuGuardDenied)", 1)[1].split("Err(rejection)", 1)[0]
        self.assertNotIn("recover(ad", guard_branch)
        self.assertIn("return false", guard_branch)
        self.assertIn("BACKUP RAW-KEY MNEMONIC ROUTES REJECTED", backup)













if __name__ == "__main__":
    unittest.main()
