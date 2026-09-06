import hashlib
import importlib.util
import pathlib
import subprocess
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[3]


class PopItSecureBootTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")


    def test_pop_it_is_settings_only_and_never_injected_at_startup(self):
        runner = self.read("apps/signer-firmware/src/runtime/event_loop/runner.rs")
        graph_menus = self.read("apps/signer-firmware/src/runtime/navigation/ui_graph/menus.rs")
        preferences = self.read("apps/signer-firmware/src/services/persistent_wallet/device/preferences.rs")
        journal = self.read("apps/signer-firmware/src/services/persistent_wallet/journal.rs")
        self.assertNotIn("startup_security", runner)
        self.assertFalse((ROOT / "apps/signer-firmware/src/runtime/event_loop/runner/startup_security.rs").exists())
        self.assertIn('ui_menu!(AdvancedMenu, 3, "Pop It!"', graph_menus)
        self.assertNotIn("pop_it_prompt_consumed", preferences)
        self.assertNotIn("dev_pop_it_prompt", preferences)
        self.assertNotIn("LEGACY_POP_IT_PROMPT_CONSUMED", journal)
        self.assertNotIn("LEGACY_POP_IT_REQUESTED", journal)
        self.assertIn("LEGACY_RESERVED_BIT_0", journal)
        self.assertIn("Current firmware does not interpret them as active features", journal)

    def test_prompt_warns_before_permanently_abandoning_owner_authority(self):
        screen = self.read("apps/signer-firmware/src/ui/screens/device/pop_it.rs")
        controller = self.read("apps/signer-firmware/src/runtime/interactions/settings/advanced/pop_it.rs")
        route = self.read("apps/signer-firmware/src/runtime/interactions/menu/primary/production.rs")
        boot_security = self.read("apps/signer-firmware/src/services/verify/boot_security.rs")
        states = self.read("apps/signer-firmware/src/runtime/input/state.rs")
        for label in ('"SET UP OWNER FIRMWARE"', '"CONTINUE WITHOUT IT"', '"YES"', '"NO"', '"EXPLAIN"'):
            self.assertIn(label, screen)
        self.assertIn('"No owner firmware key is enrolled."', screen)
        self.assertIn('"firmware enrollment on this device."', screen)
        self.assertIn("OWNER_SETUP_BUTTON_Y", controller)
        self.assertIn("CONTINUE_WITHOUT_BUTTON_Y", controller)
        self.assertIn("route!(OwnerFirmwareMenu)", controller)
        self.assertIn("route!(PopItConfirm)", controller)
        self.assertIn("owner_authority_enrolled()", route)
        self.assertIn("pub fn owner_authority_enrolled() -> bool", boot_security)
        self.assertIn("SECURE_BOOT_DIGEST1_PURPOSE", boot_security)
        self.assertIn("SECURE_BOOT_KEY_REVOKE1", boot_security)
        self.assertIn("WR_DIS", boot_security)
        self.assertIn("OWNER_REVOKE_WR_DIS_MASK: u32 = 1 << 6", boot_security)
        self.assertNotIn("WR_DIS_SECURE_BOOT_KEY_REVOKE1", boot_security)
        self.assertIn("SECURE_BOOT_KEY_REVOKE2", boot_security)
        for state in ("PopItPrompt", "PopItExplain", "PopItConfirm"):
            self.assertIn(state, states)
        self.assertIn("display.draw_pop_it_applying()", controller)
        self.assertIn("esp_hal::system::software_reset()", controller)
        self.assertIn('"FINAL: TYPE POP IT"', screen)
        self.assertIn("confirmation_phrase_valid", controller)

    def test_pop_it_remains_in_advanced_until_hardware_enabled(self):
        navigation = self.read("apps/signer-firmware/src/runtime/navigation/production.rs")
        graph_menus = self.read("apps/signer-firmware/src/runtime/navigation/ui_graph/menus.rs")
        controller = self.read("apps/signer-firmware/src/runtime/interactions/menu/primary/production.rs")
        self.assertIn('ui_menu!(AdvancedMenu, 3, "Pop It!"', graph_menus)
        self.assertIn('ui_menu!(AdvancedMenu, 2, "Owner Firmware"', graph_menus)
        self.assertIn("secure_boot_enabled()", navigation)
        self.assertIn("ui_graph::advanced_labels", navigation)
        self.assertIn("pop_it_available()", controller)
        self.assertIn("effects::menu_select(ad, index)", controller)

    def test_preflight_is_fail_closed_before_request_and_reset(self):
        preflight = self.read("apps/signer-firmware/src/services/verify/boot_security.rs")
        controller = self.read("apps/signer-firmware/src/runtime/interactions/settings/advanced/pop_it.rs")
        for fragment in (
            "secure_boot_enabled()",
            "APP_SECURITY_VERSION == 0",
            "build_commit()",
        ):
            self.assertIn(fragment, preflight)
        # Flash-encryption and anti-rollback eFuses are intentionally absent
        # before consent; the Pop It-gated bootloader provisions them afterward.
        self.assertNotIn("flash_encryption_enabled()", preflight)
        self.assertNotIn("device_security_version()", preflight)
        preflight_pos = controller.index("boot_security::pop_it_preflight()")
        request_pos = controller.index("persistence.request_pop_it()")
        reset_pos = controller.index("esp_hal::system::software_reset()")
        self.assertLess(preflight_pos, request_pos)
        self.assertLess(request_pos, reset_pos)
        self.assertNotRegex(controller, r"Efuse::|write_field|burn_efuse|REG_WRITE")

    def test_bootloader_gate_delegates_irreversible_work_to_esp_idf(self):
        patcher = self.read("tools/build/firmware/secure_bootloader/m5stack/patch_pop_it_bootloader.py")
        owner_patch = self.read("tools/build/firmware/secure_bootloader/m5stack/owner_bootloader_patch.py")
        secure_patch = self.read("tools/build/firmware/secure_bootloader/m5stack/owner_secure_boot_patch.py")
        build = self.read("tools/build/firmware/secure_bootloader/m5stack/build.sh")
        config = self.read("tools/build/firmware/secure_bootloader/m5stack/sdkconfig.defaults")
        boot_control = self.read("apps/signer-firmware/src/services/persistent_wallet/device/boot_control.rs")
        self.assertIn("KASSIGNER_BOOTCTL_BASE 0x00610000U", owner_patch)
        self.assertIn("KASSIGNER_OWNER_STAGE_BASE 0x00410000U", owner_patch)
        self.assertIn("KASSIGNER_BOOTCTL_OP_POP_IT 1U", owner_patch)
        self.assertIn("KASSIGNER_BOOTCTL_OP_ENROLL_OWNER 2U", owner_patch)
        self.assertIn("KASSIGNER_BOOTCTL_OP_INSTALL_OWNER 3U", owner_patch)
        self.assertIn("esp_secure_boot_v2_permanently_enable(image_data)", secure_patch)
        self.assertIn("esp_rom_get_reset_reason(0) != RESET_REASON_CORE_SW", owner_patch)
        self.assertIn("esp_efuse_write_key", owner_patch)
        self.assertIn("ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0", owner_patch)
        self.assertIn("ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST1", owner_patch)
        self.assertIn("esp_efuse_set_digest_revoke(2)", owner_patch)
        self.assertIn("esp_efuse_set_write_protect_of_digest_revoke(0)", owner_patch)
        self.assertIn("esp_efuse_set_write_protect_of_digest_revoke(1)", owner_patch)
        self.assertIn("kassigner_secure_boot_v2_verify_key_digest", owner_patch)
        self.assertIn("check_anti_rollback(target)", owner_patch)
        self.assertIn("esp_efuse_is_flash_encryption_enabled()", owner_patch)
        self.assertIn("bootloader_components", build)
        self.assertIn("patch_pop_it_bootloader.py", build)
        self.assertIn("espsecure digest-sbv2-public-key", build)
        self.assertIn("--expected-key-digest", build)
        self.assertIn("CONFIG_SECURE_BOOT_V2_ENABLED=y", config)
        self.assertIn("CONFIG_SECURE_BOOT_BUILD_SIGNED_BINARIES=y", config)
        self.assertIn("# CONFIG_SECURE_BOOT_FLASH_ENC_KEYS_BURN_TOGETHER is not set", config)
        self.assertIn("const BOOTCTL_BASE:u32=0x0061_0000", boot_control)
        self.assertNotIn("KSPREF01", owner_patch)
        self.assertNotIn("KASSIGNER_CONFIG_A", owner_patch)
        self.assertIn("owner_bootloader_patch.py", patcher)

    def test_patcher_refuses_unknown_idf_source_and_gates_expected_blocks(self):
        path = ROOT / "tools/build/firmware/secure_bootloader/m5stack/patch_pop_it_bootloader.py"
        spec = importlib.util.spec_from_file_location("pop_it_patcher", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        fixture = (
            "#include <string.h>\n"
            "static bool ota_has_initial_contents;\n"
            + module.ANTI_ROLLBACK_FUNCTION_ANCHOR
            + "}\n"
            + module.LOAD_BOOT_ANCHOR
            + "}\n"
            "static void load_image(const esp_image_metadata_t *image_data) {\n"
            + module.SECURE_BOOT_BLOCK
            + "#ifdef CONFIG_SECURE_FLASH_ENC_ENABLED\n"
            + "    bool flash_encryption_enabled = esp_flash_encrypt_state();\n"
            + module.FLASH_ENCRYPTION_MUTATION_ANCHOR + " }\n"
            + module.FLASH_ENCRYPTION_MUTATION_ANCHOR + " }\n"
            + module.FLASH_ENCRYPTION_COMMIT_ANCHOR + "\n"
            + "#endif\n"
            + "}\n"
        )
        digest = bytes(range(32))
        with tempfile.TemporaryDirectory() as td:
            source = pathlib.Path(td) / "bootloader_utility.c"
            source.write_text(fixture)
            module.patch_utility(source, digest)
            patched = source.read_text()
            self.assertEqual(patched.count("KasSigner owner-authority boot-control and OTA handoff"), 1)
            self.assertIn("kassigner_process_owner_boot_control(bs, start_index)", patched)
            self.assertIn("kassigner_pop_it_transition_armed", patched)
            self.assertEqual(patched.count("!flash_encryption_enabled && kassigner_pop_it_transition_armed"), 2)
            take = patched.index("kassigner_bootctl_take(KASSIGNER_BOOTCTL_OP_POP_IT")
            burn = patched.index("esp_secure_boot_v2_permanently_enable(image_data)")
            self.assertLess(take, burn)
            self.assertIn("anti-rollback eFuse update deferred until Pop It", patched)
            self.assertIn("0x00, 0x01, 0x02, 0x03", patched)
            with self.assertRaises(SystemExit):
                module.patch_utility(source, digest)
        with tempfile.TemporaryDirectory() as td:
            source = pathlib.Path(td) / "bootloader_utility.c"
            source.write_text("static bool ota_has_initial_contents;\n")
            with self.assertRaises(SystemExit):
                module.patch_utility(source, digest)

    def test_bootloader_preflight_and_owner_install_bind_exact_authority_keys(self):
        path = ROOT / "tools/build/firmware/secure_bootloader/m5stack/patch_pop_it_bootloader.py"
        spec = importlib.util.spec_from_file_location("pop_it_patcher_preflight", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        fixture = (
            "static esp_err_t s_calculate_image_public_key_digests(void);\n"
            + module.SECURE_BOOT_PREFLIGHT_ANCHOR
            + "{ return ESP_OK; }\n"
        )
        digest = bytes(range(32))
        with tempfile.TemporaryDirectory() as td:
            source = pathlib.Path(td) / "secure_boot.c"
            source.write_text(fixture)
            module.patch_secure_boot(source, digest)
            patched = source.read_text()
            self.assertIn("kassigner_expected_provisioning_sbv2_digest", patched)
            self.assertIn("kassigner_secure_boot_v2_verify_key_digest", patched)
            self.assertIn("s_calculate_image_public_key_digests", patched)
            self.assertIn("bootloader is not signed by the expected official key", patched)
            self.assertIn("application is not signed by the expected official key", patched)
            self.assertIn("image_len - SIG_BLOCK_PADDING", patched)
            with self.assertRaises(SystemExit):
                module.patch_secure_boot(source, digest)
        with tempfile.TemporaryDirectory() as td:
            source = pathlib.Path(td) / "secure_boot.c"
            source.write_text(fixture)
            with self.assertRaises(SystemExit):
                module.patch_secure_boot(source, b"too short")

    def test_bootloader_owner_only_render_closes_vendor_authority_slots(self):
        path = ROOT / "tools/build/firmware/secure_bootloader/m5stack/patch_pop_it_bootloader.py"
        spec = importlib.util.spec_from_file_location("pop_it_patcher_owner_only", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        digest = bytes(range(32))
        utility_fixture = (
            "static bool ota_has_initial_contents;\n"
            + module.ANTI_ROLLBACK_FUNCTION_ANCHOR + "}\n"
            + module.LOAD_BOOT_ANCHOR + "}\n"
            "static void load_image(const esp_image_metadata_t *image_data) {\n"
            + module.SECURE_BOOT_BLOCK
            + "#ifdef CONFIG_SECURE_FLASH_ENC_ENABLED\n"
            + "    bool flash_encryption_enabled = esp_flash_encrypt_state();\n"
            + module.FLASH_ENCRYPTION_MUTATION_ANCHOR + " }\n"
            + module.FLASH_ENCRYPTION_MUTATION_ANCHOR + " }\n"
            + module.FLASH_ENCRYPTION_COMMIT_ANCHOR + "\n#endif\n}\n"
        )
        secure_fixture = (
            "static esp_err_t s_calculate_image_public_key_digests(void);\n"
            + module.SECURE_BOOT_PREFLIGHT_ANCHOR + "{ return ESP_OK; }\n"
        )
        with tempfile.TemporaryDirectory() as td:
            utility = pathlib.Path(td) / "bootloader_utility.c"
            secure = pathlib.Path(td) / "secure_boot.c"
            utility.write_text(utility_fixture)
            secure.write_text(secure_fixture)
            module.patch_utility(utility, digest, True)
            module.patch_secure_boot(secure, digest, True)
            utility_text = utility.read_text()
            secure_text = secure.read_text()
            self.assertIn("#define KASSIGNER_OWNER_ONLY_AUTHORITY 1", utility_text)
            self.assertIn("#define KASSIGNER_OWNER_ONLY_AUTHORITY 1", secure_text)
            self.assertIn("esp_efuse_set_digest_revoke(1)", utility_text)
            self.assertIn("esp_efuse_set_digest_revoke(2)", utility_text)
            self.assertIn("owner-only authority must be enrolled before provisioning", utility_text)
            self.assertIn("expected owner-only key", secure_text)

    def test_owner_only_profile_restores_sole_owner_secure_boot_authority(self):
        cargo = self.read("apps/signer-firmware/Cargo.toml")
        policy = self.read("apps/signer-firmware/src/feature_policy.rs")
        production = self.read("apps/signer-firmware/src/services/verify/policy/production.rs")
        pop = self.read("apps/signer-firmware/src/runtime/interactions/settings/advanced/pop_it.rs")
        pop_ui = self.read("apps/signer-firmware/src/ui/screens/device/pop_it.rs")
        boot_security = self.read("apps/signer-firmware/src/services/verify/boot_security.rs")
        owner_patch = self.read("tools/build/firmware/secure_bootloader/m5stack/owner_bootloader_patch.py")
        prepare = self.read("tools/build/firmware/prepare_m5stack_secure_release.sh")
        prepare_ps1 = self.read("tools/build/firmware/prepare_m5stack_secure_release.ps1")
        boot_build_ps1 = self.read("tools/build/firmware/secure_bootloader/m5stack/build.ps1")
        makefile = self.read("Makefile")

        self.assertIn('secure-owner-only = ["secure-provisioning-core"]', cargo)
        self.assertIn('secure-provisioning and secure-owner-only are mutually exclusive', policy)
        self.assertIn('#[cfg(feature = "secure-owner-only")]', production)
        self.assertIn('Owner-only pre-Pop mode: RSA trust root not yet fused', production)
        self.assertIn('cfg!(feature = "secure-owner-only")', pop)
        self.assertIn('Enroll the owner key before Pop It', pop)
        self.assertIn('No vendor authority remains trusted.', pop_ui)
        self.assertIn('SECURE_BOOT_DIGEST0_PURPOSE: u8 = 0x09', boot_security)
        self.assertIn('OWNER_REVOKE_WR_DIS_MASK: u32 = 1 << 5', boot_security)
        self.assertIn('#if KASSIGNER_OWNER_ONLY_AUTHORITY', owner_patch)
        self.assertIn('ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST0, 0, owner_digest', owner_patch)
        self.assertIn('esp_efuse_set_digest_revoke(1)', owner_patch)
        self.assertIn('esp_efuse_set_digest_revoke(2)', owner_patch)
        self.assertIn('owner-only enrollment refuses an existing alternate Secure Boot authority', owner_patch)
        self.assertIn('ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST1, &alternate_block', owner_patch)
        self.assertIn('ESP_EFUSE_KEY_PURPOSE_SECURE_BOOT_DIGEST2, &alternate_block', owner_patch)
        self.assertIn('--owner-only', prepare)
        self.assertIn('KASSIGNER_OWNER_SECURE_BOOT_KEY', prepare)
        self.assertIn('unset KASSIGNER_SIGNING_KEY', prepare)
        self.assertIn('stale dual-authority artifact', prepare)
        self.assertIn('stale owner-only artifact', prepare)
        self.assertIn('refusing to mix secure authority modes', prepare)
        self.assertIn('stale opposite-policy artifact', prepare_ps1)
        self.assertIn('refusing to mix secure trust policies', prepare)
        self.assertIn('OWNERKEY.KAS', prepare)
        self.assertIn('[switch]$OwnerOnly', prepare_ps1)
        self.assertIn('KASSIGNER_OWNER_SECURE_BOOT_KEY', prepare_ps1)
        self.assertIn("'owner-only'", boot_build_ps1)
        self.assertIn('secure-owner-only:', makefile)
        self.assertIn('secure-provisioning:', makefile)
        owner_build = self.read("tools/build/firmware/build_owner_firmware.sh")
        owner_build_ps1 = self.read("tools/build/firmware/build_owner_firmware.ps1")
        self.assertIn('unset KASSIGNER_SIGNING_KEY', owner_build)
        self.assertIn('Remove-Item Env:KASSIGNER_SIGNING_KEY', owner_build_ps1)

    def test_owner_authority_is_production_only_and_development_is_simulation(self):
        controller = self.read("apps/signer-firmware/src/runtime/interactions/settings/advanced/owner_firmware.rs")
        boot_control = self.read("apps/signer-firmware/src/services/persistent_wallet/device/boot_control.rs")
        production = self.read("apps/signer-firmware/src/services/verify/policy/production.rs")
        self.assertIn('#[cfg(feature = "secure-provisioning-core")]', controller)
        self.assertIn('#[cfg(not(feature = "secure-provisioning-core"))]', controller)
        self.assertGreaterEqual(controller.count('"DEVELOPMENT SIMULATION"'), 2)
        self.assertIn("request_owner_enrollment", controller)
        self.assertIn("request_owner_install", controller)
        self.assertIn('#[cfg(feature="secure-provisioning-core")]', boot_control)
        self.assertNotIn("Efuse", controller)
        self.assertIn('#[cfg(feature = "owner-firmware")]', production)
        self.assertIn("Owner firmware requires hardware Secure Boot", production)
        self.assertIn("secure_boot_enabled()", production)

    def test_dev_pop_it_indicator_helpers_exist_only_with_provisioning_ui(self):
        boot_security = self.read("apps/signer-firmware/src/services/verify/boot_security.rs")
        dev_gate = '#[cfg(all(feature = "provisioning-ui", feature = "m5stack", not(feature = "production")))]'
        self.assertGreaterEqual(boot_security.count(dev_gate), 5)
        self.assertIn("pub fn enable_dev_pop_it_indicator_demo()", boot_security)
        self.assertIn("pub fn dev_pop_it_indicator_demo_active() -> bool", boot_security)
        self.assertIn(
            'feature = "provisioning-ui",\n    not(all(feature = "m5stack", not(feature = "production")))',
            boot_security,
        )
        self.assertNotIn(
            '#[cfg(all(feature = "m5stack", not(feature = "production")))]\npub fn enable_dev_pop_it_indicator_demo()',
            boot_security,
        )

    def test_owner_firmware_menu_is_secure_profile_only(self):
        navigation = self.read("apps/signer-firmware/src/runtime/navigation/production.rs")
        menus = self.read("apps/signer-firmware/src/runtime/navigation/ui_graph/menus.rs")
        self.assertIn('#[cfg(feature = "provisioning-ui")]', navigation)
        self.assertIn('feature = "secure-provisioning-core"', navigation)
        self.assertIn('#[cfg(feature = "provisioning-ui")]', menus)
        self.assertIn('&ui_graph::ADVANCED_MENU_LABELS[..2]', navigation)

    def test_workflow_profile_cfgs_do_not_compile_unused_or_unreachable_paths(self):
        boot_security = self.read("apps/signer-firmware/src/services/verify/boot_security.rs")
        navigation = self.read("apps/signer-firmware/src/runtime/navigation/production.rs")

        # SECURE_BOOT_KEY_REVOKE0 is owner-only. Workflow tests enable the
        # provisioning UI without secure-owner-only, so importing it under the
        # broad provisioning-ui gate would fail the -D warnings build matrix.
        owner_only_import_gate = '''#[cfg(all(
    feature = "provisioning-ui",
    feature = "m5stack",
    not(feature = "qemu"),
    feature = "secure-owner-only"
))]
use esp_hal::efuse::SECURE_BOOT_KEY_REVOKE0;'''
        self.assertIn(owner_only_import_gate, boot_security)
        broad_import = boot_security.split('use esp_hal::efuse::{', 1)[1].split('};', 1)[0]
        self.assertNotIn('SECURE_BOOT_KEY_REVOKE0', broad_import)

        # Keep the two advanced-menu implementations cfg-disjoint rather than
        # returning from a cfg block and leaving an unreachable fallback.
        self.assertIn(
            '#[cfg(all(feature = "m5stack", feature = "provisioning-ui"))]\n'
            'pub(crate) fn advanced_items()',
            navigation,
        )
        self.assertIn(
            '#[cfg(not(all(feature = "m5stack", feature = "provisioning-ui")))]\n'
            'pub(crate) fn advanced_items()',
            navigation,
        )
        advanced_region = navigation.split('pub(crate) fn advanced_items()', 1)[1]
        self.assertNotIn('return ui_graph::advanced_labels', advanced_region)

    def test_mobile_signing_secrets_and_apple_team_are_not_repository_owned(self):
        ignore = self.read(".gitignore")
        project = self.read("apps/kassee-ios/KasSigner.xcodeproj/project.pbxproj")
        ios_build = self.read("scripts/mac/build/ios-build.sh")
        self.assertIn("*.jks", ignore)
        self.assertIn("*.keystore", ignore)
        self.assertNotIn("DEVELOPMENT_TEAM =", project)
        self.assertIn("KASSIGNER_IOS_DEVELOPMENT_TEAM", ios_build)
        self.assertIn('"DEVELOPMENT_TEAM=$team"', ios_build)

    def test_secure_boot_signing_uses_canonical_64k_application_padding(self):
        shell_wrapper = self.read("tools/build/firmware/secure_bootloader/m5stack/sign_app.sh")
        sign = self.read("tools/build/firmware/secure_bootloader/m5stack/sign_app.py")
        padding = self.read("tools/build/firmware/secure_pad_v2.py")
        policy = self.read("apps/signer-firmware/release-policy.env")
        self.assertIn("sign_app.py", shell_wrapper)
        self.assertIn("secure_pad_v2.py", sign)
        self.assertIn("--skip-padding", sign)
        self.assertIn("SIGNATURE_SECTOR_SIZE = 4096", sign)
        self.assertIn("verify-signature", sign)
        self.assertIn("verify_image_hash.py", sign)
        self.assertIn('EXPECTED_ESPTOOL_VERSION = "5.3.1"', padding)
        self.assertIn('image.secure_pad = "2"', padding)
        self.assertIn("MMU_PAGE_SIZE = 64 * 1024", padding)
        self.assertIn("KASSIGNER_ESPTOOL_VERSION=5.3.1", policy)

    def test_status_badge_maps_software_hardware_and_neither(self):
        boot = self.read("apps/signer-firmware/src/ui/display/boot.rs")
        security = self.read("apps/signer-firmware/src/services/verify/boot_security.rs")
        self.assertIn('include_bytes!("../../../assets/kascoin_90.raw")', boot)
        self.assertIn('include_bytes!("../../../assets/kascoin_teal_90.raw")', boot)
        self.assertIn("BootSecurityLevel::HardwareEnforced", boot)
        self.assertIn("BootSecurityLevel::SoftwareVerified", boot)
        self.assertIn("BootSecurityLevel::None", boot)
        self.assertIn("COLOR_DANGER", boot)
        self.assertIn("BootSecurityLevel::SoftwareVerified", security)
        self.assertIn("BootSecurityLevel::HardwareEnforced", security)

    def test_teal_and_white_assets_have_editable_png_sources_and_exact_roundtrip(self):
        converter = ROOT / "tools/kassigner-image.py"
        assets = []
        for name in ("kascoin_90", "kascoin_teal_90"):
            raw = ROOT / f"apps/signer-firmware/assets/{name}.raw"
            png = ROOT / f"apps/signer-firmware/assets/source/{name}.png"
            self.assertEqual(raw.stat().st_size, 90 * 90 * 2)
            header = png.read_bytes()[:24]
            self.assertEqual(header[:8], b"\x89PNG\r\n\x1a\n")
            self.assertEqual(int.from_bytes(header[16:20], "big"), 90)
            self.assertEqual(int.from_bytes(header[20:24], "big"), 90)
            assets.append((raw, png))

        try:
            import PIL  # noqa: F401
        except ImportError:
            self.skipTest("Pillow is optional and only required for hardware-asset conversion")

        for raw, _png in assets:
            with tempfile.TemporaryDirectory() as td:
                decoded = pathlib.Path(td) / "decoded.png"
                encoded = pathlib.Path(td) / "encoded.raw"
                subprocess.run(
                    [sys.executable, str(converter), "decode", str(raw), str(decoded), "90", "90"],
                    check=True,
                )
                subprocess.run(
                    [sys.executable, str(converter), "encode", str(decoded), str(encoded), "90", "90"],
                    check=True,
                )
                self.assertEqual(raw.read_bytes(), encoded.read_bytes())

    def test_hardware_asset_readme_uses_direct_converter_not_removed_make_target(self):
        readme = self.read("apps/signer-firmware/assets/source/README.md")
        self.assertIn("python3 tools/kassigner-image.py create png", readme)
        self.assertIn("python3 tools/kassigner-image.py create raw", readme)
        self.assertNotIn("make hw-assets", readme)

    def test_no_private_secure_boot_key_is_added_to_assets_or_source(self):
        forbidden_suffixes = {".pem", ".key", ".p12", ".pfx"}
        hits = [p for p in ROOT.rglob("*") if p.is_file() and p.suffix.lower() in forbidden_suffixes]
        self.assertEqual(hits, [])
        build = self.read("tools/build/firmware/secure_bootloader/m5stack/build.sh")
        self.assertIn("KASSIGNER_SECURE_BOOT_SIGNING_KEY", build)
        self.assertIn('[[ -n "$SIGNING_KEY" && -f "$SIGNING_KEY" ]]', build)

    def test_documented_trust_model_does_not_overclaim_pre_pop_physical_security(self):
        doc = self.read("docs/security/POP_IT_SECURE_BOOT.md")
        self.assertIn("Until a hardware trust root is fused, physical flash replacement can replace both application and second-stage bootloader", doc)
        self.assertIn("The Rust application never performs raw eFuse writes", doc)
        self.assertIn("checksummed one-shot request", doc)
        self.assertIn("exact RSA authority checks immediately before irreversible", doc)
        self.assertIn("private key is never placed in the enrollment record, firmware, or signer", doc)


if __name__ == "__main__":
    unittest.main()
