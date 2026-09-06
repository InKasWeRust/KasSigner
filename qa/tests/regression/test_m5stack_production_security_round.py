import hashlib
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[3]


class M5StackProductionSecurityRound(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text()

    def test_secret_root_is_static_internal_state(self):
        source = self.read("apps/signer-firmware/src/main.rs")
        secret_state = self.read("apps/signer-firmware/src/runtime/secret_state.rs")
        qr = self.read("apps/signer-firmware/src/runtime/data/qr.rs")
        self.assertIn("static APP_DATA: StaticCell<AppData>", secret_state)
        self.assertIn("runtime::secret_state::initialize()", source)
        self.assertNotIn("Box::new(AppData::new())", source)
        self.assertIn("OUTGOING_QR_BUFFER_SIZE", qr)
        self.assertNotIn("Vec<u8>", qr)

    def test_hardware_enforced_production_attestation_requires_flash_encryption_release(self):
        source = self.read("apps/signer-firmware/src/services/verify/attestation/mod.rs")
        self.assertIn("FlashEncryptionDisabled", source)
        self.assertIn("FlashEncryptionNotRelease", source)
        self.assertIn("DIS_DOWNLOAD_MANUAL_ENCRYPT", source)
        self.assertIn("if hardware_secure_boot", source)
        self.assertIn("require_release_flash_encryption()?", source)

    def test_application_descriptor_and_runtime_policy_use_secure_version_efuse(self):
        source = self.read("apps/signer-firmware/src/services/verify/anti_rollback.rs")
        self.assertIn("SECURE_VERSION", source)
        self.assertIn("count_ones()", source)
        self.assertIn("write_u32(&mut output, SECURE_VERSION_OFFSET, APP_SECURITY_VERSION)", source)
        self.assertIn("APP_SECURITY_VERSION: u32", source)

    def test_partition_layout_is_anti_rollback_ota_only(self):
        rows = [line for line in self.read("apps/signer-firmware/partitions/m5stack-cores3.csv").splitlines()
                if line.strip() and not line.lstrip().startswith("#")]
        joined = "\n".join(rows)
        self.assertIn("ota_0", joined)
        self.assertIn("ota_1", joined)
        self.assertIn("otadata", joined)
        self.assertNotIn("factory", joined.lower())

    def test_secure_bootloader_profile_is_fail_closed(self):
        source = self.read("tools/build/firmware/secure_bootloader/m5stack/sdkconfig.defaults")
        for fragment in (
            "CONFIG_SECURE_BOOT_V2_ENABLED=y",
            "CONFIG_SECURE_FLASH_ENCRYPTION_MODE_RELEASE=y",
            "CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK=y",
            "CONFIG_BOOTLOADER_APP_SEC_VER_SIZE_EFUSE_FIELD=16",
            "CONFIG_SECURE_INSECURE_ALLOW_DL_MODE=y",
        ):
            self.assertIn(fragment, source)
        build = self.read("tools/build/firmware/secure_bootloader/m5stack/build.sh")
        policy = self.read("apps/signer-firmware/release-policy.env")
        self.assertIn('CONFIG_BOOTLOADER_APP_SECURE_VERSION=%s', build)
        self.assertIn('"$KASSIGNER_SECURITY_VERSION"', build)
        self.assertIn("KASSIGNER_SECURITY_VERSION=1", policy)
        self.assertNotIn("CONFIG_BOOTLOADER_EFUSE_SECURE_VERSION_EMULATE=y", source)
        self.assertNotIn("CONFIG_SECURE_BOOT_ALLOW_JTAG=y", source)
        self.assertNotIn("CONFIG_SECURE_ENABLE_SECURE_ROM_DL_MODE=y", source)
        self.assertNotIn("CONFIG_SECURE_DISABLE_ROM_DL_MODE=y", source)

    def test_update_manifest_binds_every_release_identity_field(self):
        source = self.read("crates/signer-firmware-core/src/update/manifest/mod.rs")
        self.assertIn("KasSigner/FirmwareManifest/v3", source)
        self.assertIn("input.len() != MANIFEST_LEN", source)
        for field in ("board", "channel", "version", "release_sequence", "security_version", "image_size",
                      "partition_layout_hash", "image_hash", "signature"):
            self.assertIn(field, source)

    def test_compiled_partition_hash_matches_manifest_policy(self):
        csv = (ROOT / "apps/signer-firmware/partitions/m5stack-cores3.csv").read_bytes()
        expected = hashlib.sha256(csv).hexdigest()
        generator = self.read("tools/firmware/gen_update_manifest.rs")
        # Keep an independent plain-text guard too; host release generation now
        # hashes the authoritative partition CSV directly instead of duplicating
        # a runtime firmware-update constant.
        self.assertEqual(expected, "72e412f3797ea798adf90ab1f9ae9581ca1bf049c05e4bdf225dc5243952738a")
        self.assertIn("let partition_layout_hash = partition_hash(board, &args[7])?;", generator)
        self.assertIn("fs::read(value)", generator)
        self.assertIn("Sha256::digest(data)", generator)

    def test_production_helper_requires_schnorr_release_key(self):
        sh = self.read("tools/build/firmware/build_production.sh")
        ps = self.read("tools/build/firmware/build_production.ps1")
        for source in (sh, ps):
            self.assertIn("KASSIGNER_SIGNING_KEY", source)
            self.assertIn("m5stack,production", source)


    def test_m5_manifest_is_generated_after_secure_boot_signing(self):
        prepare = self.read("tools/build/firmware/prepare_m5stack_secure_release.sh")
        docker = self.read("Dockerfile")
        self.assertIn("kassigner-m5stack-app-secureboot-signed.bin", prepare)
        self.assertIn("--bin gen-update-manifest", prepare)
        self.assertIn("$SIGNED_APP", prepare)
        self.assertIn("KASSIGNER_SIGNING_KEY", prepare)
        self.assertNotIn("/build/kassigner-m5stack-update.ksfu", docker)

    def test_normal_release_update_manifests_use_canonical_release_policy(self):
        docker = self.read("Dockerfile")
        self.assertIn("Canonical signed KSFU v3 update manifests", docker)
        self.assertIn("source apps/signer-firmware/release-policy.env", docker)
        self.assertGreaterEqual(docker.count('"$KASSIGNER_UPDATE_SEQUENCE"'), 2)
        self.assertGreaterEqual(docker.count('"$KASSIGNER_SECURITY_VERSION"'), 2)
        self.assertNotIn("2.0.0 1 none /build/kassigner-waveshare-update.ksfu", docker)
        self.assertNotIn("2.0.0 1 none /build/kassigner-waveshare-af-update.ksfu", docker)

    def test_release_gate_requires_new_core_s3_security_evidence(self):
        model = self.read("qa/checks/release/readiness/model.py")
        for name in (
            "m5stack_flash_encryption_release.json",
            "m5stack_secure_boot_v2.json",
            "m5stack_owner_authority.json",
            "m5stack_anti_rollback.json",
            "m5stack_update_manifest_negative.json",
            "m5stack_secret_memory_map.json",
        ):
            self.assertIn(name, model)

    def test_hil_collector_is_read_only(self):
        source = self.read("qa/linux/run-m5stack-security-hil.sh")
        self.assertIn("get-security-info", source)
        self.assertNotIn("espefuse.py", source)
        for destructive in ("burn-key", "burn-efuse", "write-flash", "erase-flash"):
            self.assertNotIn(destructive, source)

    def test_normal_release_excludes_provisioning_ui_and_special_profile_is_explicit(self):
        cargo = self.read("apps/signer-firmware/Cargo.toml")
        docker = self.read("Dockerfile")
        production_sh = self.read("tools/build/firmware/build_production.sh")
        prepare = self.read("tools/build/firmware/prepare_m5stack_secure_release.sh")
        prepare_ps1 = self.read("tools/build/firmware/prepare_m5stack_secure_release.ps1")
        makefile = self.read("Makefile")
        tasks = self.read("scripts/common/lib/make_tasks.py")
        policy = self.read("apps/signer-firmware/src/feature_policy.rs")
        self.assertIn('provisioning-ui = []', cargo)
        self.assertIn('secure-provisioning-core = ["production", "m5stack", "provisioning-ui"]', cargo)
        self.assertIn('secure-provisioning = ["secure-provisioning-core"]', cargo)
        self.assertIn('secure-owner-only = ["secure-provisioning-core"]', cargo)
        self.assertIn('--features m5stack,production', docker)
        self.assertNotIn('--features m5stack,secure-provisioning', docker)
        self.assertNotIn('prepare_m5stack_secure_release.sh', docker)
        self.assertIn('m5stack-update-manifest=not-emitted-by-normal-release;secure-provisioning-is-separate', docker)
        self.assertIn('FEATURES=m5stack,production', production_sh)
        self.assertIn('--secure-provisioning', production_sh)
        self.assertIn('FEATURES=m5stack,secure-provisioning', production_sh)
        self.assertIn('--secure-owner-only', production_sh)
        self.assertIn('FEATURES=m5stack,secure-owner-only', production_sh)
        self.assertIn('build_production.sh" --secure-provisioning', prepare)
        self.assertIn('build_production.sh" --secure-owner-only', prepare)
        self.assertIn('KASSIGNER_OWNER_SECURE_BOOT_KEY', prepare)
        self.assertIn('[switch]$OwnerOnly', prepare_ps1)
        self.assertIn('KASSIGNER_OWNER_SECURE_BOOT_KEY', prepare_ps1)
        self.assertIn('secure-provisioning:', makefile)
        self.assertIn('secure-owner-only:', makefile)
        self.assertIn('def secure_release(', tasks)
        self.assertIn('production Pop It!/ownership UI requires a dedicated secure provisioning profile', policy)
        device = self.read("apps/signer-firmware/src/services/persistent_wallet/device/mod.rs")
        persistence = self.read("apps/signer-firmware/src/services/persistent_wallet/mod.rs")
        self.assertIn('#[cfg(feature = "secure-provisioning-core")]\nmod boot_control;', device)
        self.assertIn('#[cfg(feature = "provisioning-ui")]\n    OwnerFirmwareInvalid,', persistence)
        # Owner-firmware UI is also compiled by developer workflow tests, so the
        # UI-facing validation error must follow provisioning-ui rather than only
        # the destructive secure-provisioning core. Normal production still lacks it.
        self.assertNotIn('#[cfg(feature = "secure-provisioning-core")]\n    OwnerFirmwareInvalid,', persistence)

    def test_secure_bootloader_defers_all_automatic_efuse_transitions_until_pop_it(self):
        patcher = self.read("tools/build/firmware/secure_bootloader/m5stack/patch_pop_it_bootloader.py")
        secure = self.read("tools/build/firmware/secure_bootloader/m5stack/owner_secure_boot_patch.py")
        self.assertIn('!flash_encryption_enabled && kassigner_pop_it_transition_armed', patcher)
        self.assertIn('anti-rollback eFuse update deferred until Pop It', patcher)
        armed = secure.split("POP_IT_GATED_BLOCK =", 1)[1].split("POP_IT_COMMIT_BLOCK =", 1)[0]
        commit = secure.split("POP_IT_COMMIT_BLOCK =", 1)[1]
        self.assertIn('kassigner_pop_it_transition_armed = true', armed)
        self.assertNotIn('esp_secure_boot_v2_permanently_enable', armed)
        self.assertIn('esp_efuse_enable_rom_secure_download_mode()', commit)
        self.assertLess(commit.index('kassigner_bootctl_take(KASSIGNER_BOOTCTL_OP_POP_IT'),
                        commit.index('esp_efuse_enable_rom_secure_download_mode()'))
        self.assertLess(commit.index('esp_efuse_enable_rom_secure_download_mode()'),
                        commit.index('esp_secure_boot_v2_permanently_enable(image_data)'))

    def test_flash_release_is_prebuilt_signed_only_and_non_provisioning(self):
        makefile = self.read("Makefile")
        tasks = self.read("scripts/common/lib/make_tasks.py")
        self.assertIn('flash-release:', makefile)
        self.assertIn('flash-release "$(BOARD)" "$(PORT)" "$(RELEASE_DIR)"', makefile)
        self.assertIn('def flash_release(', tasks)
        self.assertIn('kassigner-m5stack-full.bin', tasks)
        self.assertIn('kassigner-waveshare-full.bin', tasks)
        self.assertIn('first run make release SIGNING_KEY=/path/to/signing-key', tasks)
        body = tasks.split('def flash_release(', 1)[1].split('def workflow_e2e(', 1)[0]
        self.assertNotIn('build_firmware(', body)
        self.assertNotIn('secure-provision', body)
        self.assertNotIn('-unsigned-full.bin', body)
        self.assertIn('["espflash", "write-bin"', body)
        self.assertIn('"0x0", str(image)', body)


if __name__ == "__main__":
    unittest.main()
