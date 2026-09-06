from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
BOOT = ROOT / "apps/signer-firmware/src/boot/m5stack"


class M5StackBootPhaseTests(unittest.TestCase):
    def test_initialize_macro_is_a_thin_ownership_facade(self) -> None:
        expected = {"mod.rs", "power.rs", "display.rs", "audio.rs", "entropy.rs", "sd.rs", "camera.rs", "kpub_worker.rs"}
        self.assertEqual({path.name for path in BOOT.glob("*.rs")}, expected)
        limits = {
            "mod.rs": 125,
            "power.rs": 80,
            "display.rs": 80,
            "audio.rs": 80,
            "entropy.rs": 60,
            "sd.rs": 80,
            "camera.rs": 80,
            "kpub_worker.rs": 60,
        }
        for name, maximum in limits.items():
            lines = (BOOT / name).read_text().count("\n") + 1
            self.assertLessEqual(lines, maximum, f"{name} exceeded SRP line cap")

        facade = (BOOT / "mod.rs").read_text()
        for phase in ("power", "display", "audio", "entropy", "sd", "camera"):
            self.assertIn(f"m5stack::{phase}::", facade)
        for leaked_policy in ("init_axp2101", "init_aw9523b", "init_aw88298", "init_gc0308", "bitbang_init"):
            self.assertNotIn(leaked_policy, facade)

    def test_cores3_shared_hardware_has_one_boot_constructor_per_peripheral(self) -> None:
        sources = "\n".join(
            path.read_text()
            for root in (BOOT, ROOT / "apps/signer-firmware/src/hw/m5stack")
            for path in root.rglob("*.rs")
        )
        for constructor in ("I2c::new(", "Spi::new(", "I2s::new(", "LcdCam::new("):
            self.assertEqual(
                sources.count(constructor),
                1,
                f"CoreS3 hardware ownership changed for {constructor}",
            )
        volatile_paths = sorted(
            path.relative_to(ROOT).as_posix()
            for path in (ROOT / "apps/signer-firmware/src/hw/m5stack").rglob("*.rs")
            if "ptr::write_volatile" in path.read_text()
        )
        self.assertEqual(
            volatile_paths,
            [
                "apps/signer-firmware/src/hw/m5stack/spi_bus/gpio35.rs",
                "apps/signer-firmware/src/hw/m5stack/spi_bus/sd_power_lines.rs",
            ],
        )

    def test_shared_spi_owner_precedes_sd_and_display_clients(self) -> None:
        facade = (BOOT / "mod.rs").read_text()
        display = (BOOT / "display.rs").read_text()
        hw_selector = (ROOT / "apps/signer-firmware/src/hw/mod.rs").read_text()
        self.assertIn(
            "pub(crate) use active_board::spi_bus::initialize as initialize_cores3_spi;",
            hw_selector,
        )
        self.assertNotIn("$crate::hw::m5stack::", facade)
        spi_at = facade.index("let spi = Spi::new")
        owner_at = facade.index("initialize_cores3_spi(spi, sd_cs)")
        sd_at = facade.index("m5stack::sd::initialize")
        display_at = facade.index("m5stack::display::initialize")
        self.assertLess(spi_at, owner_at)
        self.assertLess(owner_at, sd_at)
        self.assertLess(sd_at, display_at)
        self.assertLess(display_at, facade.index("m5stack::audio::initialize"))
        self.assertLess(display_at, facade.index("m5stack::entropy::initialize"))
        self.assertLess(display_at, facade.index("m5stack::camera::initialize_sensor"))
        self.assertIn("display.show_logo_screen()", display)

    def test_cores3_camera_uses_hal_exclusive_lcd_cam_and_gpio_ownership(self) -> None:
        facade = (BOOT / "mod.rs").read_text()
        camera_phase = (BOOT / "camera.rs").read_text()
        driver_root = ROOT / "apps/signer-firmware/src/hw/m5stack/cameras/gc0308"
        driver = "\n".join(path.read_text() for path in driver_root.glob("*.rs"))
        controller = "\n".join(
            path.read_text()
            for path in (ROOT / "apps/signer-firmware/src/runtime/interactions/camera_loop").glob("*.rs")
        )

        master_clock = facade.index(".with_master_clock($peripherals.GPIO2)")
        sensor_init = facade.index("m5stack::camera::initialize_sensor")
        self.assertLess(master_clock, sensor_init)
        self.assertIn("HAL owns XCLK/DVP routing", camera_phase)
        self.assertIn("no raw GPIO/IO_MUX override", camera_phase)
        self.assertEqual(
            {path.name for path in driver_root.glob("*.rs")},
            {"mod.rs", "bus.rs", "initialization.rs", "power.rs", "registers.rs", "types.rs"},
        )
        for forbidden in (
            "IO_MUX::PTR", "GPIO::PTR", "SYSTEM_PERIP_CLK_EN1",
            "SYSTEM_PERIP_RST_EN1", "start_sensor_xclk",
            "setup_cam_gpio_routing", "configure_cam_vsync_eof",
            "enable_lcd_cam_clocks", "ensure_lcd_clk_enabled",
        ):
            self.assertNotIn(forbidden, driver)
        self.assertNotIn("0x6004_1000", controller)

    def test_workflow_auto_gate_runs_before_optional_board_initialization(self) -> None:
        manifest = (ROOT / "apps/signer-firmware/Cargo.toml").read_text()
        main = (ROOT / "apps/signer-firmware/src/main.rs").read_text()
        self.assertIn('developer-ui = []', manifest)
        self.assertIn('workflow-tests = ["developer-ui", "provisioning-ui"]', manifest)
        self.assertNotIn('workflow-tests = ["verbose-boot"]', manifest)
        gate = main.index("runtime::workflow_tests::run_boot_gate();")
        self.assertLess(gate, main.index("run_startup_tests"))
        self.assertLess(gate, main.index("boot::m5stack::initialize!"))
        self.assertLess(gate, main.index("boot::waveshare::initialize!"))
        self.assertLess(gate, main.index("run_firmware_verify"))
        self.assertLess(gate, main.index("enforce_boot_known_answer_tests"))
        self.assertNotIn("report_boot_gate", main)

    def test_workflow_auto_skips_optional_peripherals_only_in_controller_profile(self) -> None:
        facade = (BOOT / "mod.rs").read_text()
        controller = facade.split('#[cfg(all(feature = "workflow-test-auto", not(feature = "workflow-runtime-auto")))]\n        {', 1)[1].split('#[cfg(any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto"))]', 1)[0]
        production_runtime = facade.split('#[cfg(any(not(feature = "workflow-test-auto"), feature = "workflow-runtime-auto"))]\n        {', 1)[1]
        self.assertIn("OPTIONAL AUDIO/ENTROPY/CAMERA SKIPPED; SD PROBED", controller)
        self.assertIn("BOARD PHASES COMPLETE", controller)
        self.assertIn("None::<DvpCamera<'_>>", controller)
        self.assertIn("None::<esp_hal::dma::DmaRxBuf>", controller)
        self.assertIn("None::<$crate::hw::sound::RuntimeAudio>", controller)
        self.assertNotIn("I2s::new", controller)
        self.assertNotIn("entropy::initialize", controller)
        self.assertNotIn("LcdCam::new", controller)
        self.assertIn("I2s::new", production_runtime)
        self.assertIn("entropy::initialize", production_runtime)
        self.assertIn("LcdCam::new", production_runtime)
        self.assertIn('let sd_card_type = $crate::boot::m5stack::sd::initialize(&mut i2c, &mut $delay);', facade)
        self.assertLess(facade.index('sd::initialize(&mut i2c, &mut $delay)'), facade.index('display::initialize('))
        self.assertIn('KASSIGNER_WORKFLOW_RUNTIME: REAL PMU/TOUCH/ENTROPY/CAMERA INIT PATH EXECUTED', production_runtime)
        self.assertIn('KASSIGNER_WORKFLOW_HIL: DESTRUCTIVE MEDIA PROFILE ENABLED', production_runtime)

    def test_make_flash_is_interactive_and_observable_by_default(self) -> None:
        helper = (ROOT / "scripts/common/lib/make_tasks.py").read_text()
        flash = helper.split("def flash_firmware", 1)[1].split("def workflow_e2e", 1)[0]
        self.assertIn('command = ["espflash", "flash", "--monitor"', flash)
        self.assertIn("press CTRL+C to exit", flash)
        self.assertNotIn('reset_command = ["espflash", "reset"', flash)

    def test_m5stack_runner_delay_binding_matches_runtime_profile(self) -> None:
        runner = (ROOT / "apps/signer-firmware/src/runtime/event_loop/runner.rs").read_text()
        self.assertIn(
            '#[cfg(all(feature = "m5stack", not(feature = "workflow-test-auto")))] let mut delay = delay;',
            runner,
        )
        self.assertNotIn(
            '#[cfg(all(feature = "m5stack", feature = "workflow-test-auto"))] let delay = delay;',
            runner,
        )
        self.assertIn(
            'workflow_auto::run(\n        ad, boot_display, i2c, sd_card_type, delay,',
            runner,
        )
        self.assertNotIn('#[cfg(feature = "m5stack")] let delay = delay;', runner)
        self.assertNotIn('#[cfg(feature = "m5stack")] let mut delay = delay;', runner)

    def test_startup_screen_is_rendered_before_touch_loop(self) -> None:
        runner = (ROOT / "apps/signer-firmware/src/runtime/event_loop/runner.rs").read_text()
        prepare = runner.index("persistent_wallet.prepare_startup(ad);")
        render = runner.index("startup_ui::render(ad")
        event_loop = runner.index("super::run!(")
        self.assertLess(prepare, render)
        self.assertLess(render, event_loop)
        startup_ui = (ROOT / "apps/signer-firmware/src/runtime/event_loop/runner/startup_ui.rs").read_text()
        self.assertIn("ui::redraw::redraw_screen", startup_ui)

    def test_runtime_sd_never_reclaims_live_display_spi2(self) -> None:
        sd_phase = (BOOT / "sd.rs").read_text()
        m5_root = ROOT / "apps/signer-firmware/src/hw/m5stack"
        transport_root = m5_root / "storage/transport"
        transport = (transport_root / "mod.rs").read_text()
        protocol = (transport_root / "protocol/wire.rs").read_text()
        spi_state = (m5_root / "spi_bus/state.rs").read_text()
        spi_config = (m5_root / "spi_bus/config.rs").read_text()
        lcd = (m5_root / "spi_bus/lcd.rs").read_text()
        gpio35 = (m5_root / "spi_bus/gpio35.rs").read_text()

        self.assertIn("probe_boot_card(delay)", sd_phase)
        self.assertIn("Shared-SPI SD probe", sd_phase)
        self.assertIn("probe_boot_card", transport)
        self.assertIn("m5stack::spi_bus::with_sd_selected", protocol)
        self.assertIn("StaticCell<SharedBus>", spi_state)
        self.assertIn("AtomicPtr<SharedBus>", spi_state)
        self.assertIn("CoreS3 SPI2 bus re-entry", spi_state)
        self.assertIn("frequency_hz: Cell<u32>", spi_state)
        self.assertIn("ensure_frequency", spi_config)
        self.assertIn("current_hz.get() == frequency_hz", spi_config)
        self.assertNotIn("critical_section::with", spi_state)
        self.assertIn("select_lcd_dc", gpio35)
        self.assertIn("select_sd_miso", gpio35)
        self.assertIn("LcdDevice", lcd)

        all_transport = "\n".join(path.read_text() for path in transport_root.rglob("*.rs"))
        for retired in (
            "save_and_reclaim", "restore_spi_state", "SPI2_CLOCK_REG",
            "SPI2_USER_REG", "bb_transfer", "fast_bb_read_512",
        ):
            self.assertNotIn(retired, all_transport)
        self.assertFalse((transport_root / "bitbang").exists())
        self.assertFalse((transport_root / "registers.rs").exists())
        self.assertFalse((transport_root / "gpio.rs").exists())

    def test_audio_dma_is_owned_bounded_and_fail_closed(self) -> None:
        sound = (ROOT / "apps/signer-firmware/src/hw/m5stack/sound.rs").read_text()
        audio = (ROOT / "apps/signer-firmware/src/boot/m5stack/audio.rs").read_text()
        self.assertIn("tx.write_dma_circular(&*buffer)", audio)
        self.assertEqual(audio.count("write_dma_circular"), 1)
        self.assertIn("pub(crate) struct RuntimeAudio", sound)
        self.assertIn("tx: SoundTx", sound)
        self.assertIn("buffer: &'static mut SoundBuffer", sound)
        self.assertIn("self.tx.write_dma_circular(&words)", sound)
        self.assertIn("SOUND_DMA_TIMEOUT", sound)
        self.assertIn("play_bounded_dma(transfer, used)", sound)
        self.assertIn("runtime audio disabled after bounded I2S write failure", sound)
        self.assertNotIn("AtomicPtr", sound)
        self.assertNotIn("unsafe {", sound)
        self.assertNotIn("write_words(&buffer[..used])", sound)


    def test_home_battery_indicator_uses_boot_cache_not_runtime_i2c(self) -> None:
        battery = (ROOT / "apps/signer-firmware/src/hw/m5stack/power/battery.rs").read_text()
        power = (ROOT / "apps/signer-firmware/src/boot/m5stack/power.rs").read_text()
        redraw = (ROOT / "apps/signer-firmware/src/ui/redraw/navigation.rs").read_text()
        touch = (ROOT / "apps/signer-firmware/src/hw/m5stack/touch/mod.rs").read_text()
        self.assertIn("refresh_boot_cache(i2c)", power)
        self.assertIn('#[cfg(not(feature = "workflow-test-auto"))]\n            match crate::hw::battery::refresh_boot_cache(i2c)', power)
        self.assertIn('#[cfg(feature = "workflow-test-auto")]', power)
        self.assertIn("Battery boot snapshot: skipped for workflow E2E liveness", power)
        self.assertIn("KASSIGNER_WORKFLOW_TESTS: OPTIONAL BATTERY SNAPSHOT SKIPPED", power)
        self.assertIn("cached_battery_value()", battery)
        macro = battery.split("macro_rules! read_battery", 1)[1]
        self.assertIn("cached_battery_value()", macro)
        self.assertNotIn("read_battery_value($i2c)", macro)
        self.assertIn("battery::read_battery!(i2c)", redraw)
        self.assertIn('#[cfg(feature = "workflow-test-auto")]\npub(crate) fn probe', touch)



if __name__ == "__main__":
    unittest.main()
