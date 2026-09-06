"""Source contracts for the KasSigner 2.0.0 security integration."""

from __future__ import annotations

from pathlib import Path


def check_security_integration_contract(root: Path, errors: list[str]) -> None:
    def read(relative: str) -> str:
        return (root / relative).read_text(encoding="utf-8")

    def require(condition: bool, message: str) -> None:
        if not condition:
            errors.append(message)

    trng = read("apps/signer-firmware/src/services/entropy/trng.rs")
    health = read("apps/signer-firmware/src/services/entropy/health.rs")
    shared_rng_health = read("crates/signer-firmware-core/src/entropy/rng_health.rs")
    require("0x6003_507C" in trng, "security integration: ESP32-S3 WDEV RNG address is missing")
    require(
        "0x6003_5144u32 as" not in trng,
        "security integration: obsolete ESP32 RNG register is still active",
    )
    require(
        "0x6000_8074" in trng
        and "1 << 10" in trng
        and "0x6002_6014" in trng
        and "1 << 15" in trng,
        "security integration: ESP32-S3 RC_FAST and APB RNG clock gates are incomplete",
    )
    require(
        trng.count("set_and_verify(") >= 3,
        "security integration: RNG clock gates are not enabled with read-back verification",
    )
    for pattern in ("StuckRegister", "StuckHalfWord", "CounterPattern"):
        require(pattern in health, f"security integration: firmware entropy adapter missing {pattern}")
    for pattern in ("HEALTH_SAMPLE_COUNT: usize = 32", "RepetitionCount", "LowDiversity", "AdaptiveProportion", "StuckBits", "CounterPattern", "Monotonic"):
        require(pattern in shared_rng_health, f"security integration: shared RNG health model missing {pattern}")

    kspt_facade = read("crates/offline-signer/src/transaction/kspt/mod.rs")
    for signer in (
        "sign_transaction_in_place_with_entropy",
        "sign_transaction_multi_addr_with_entropy",
        "sign_transaction_multisig_with_entropy",
        "sign_transaction_with_entropy",
    ):
        require(signer in kspt_facade,
                f"security integration: public KSPT facade does not export {signer}")

    flow_tests = read("apps/signer-firmware/src/crypto/unit_tests/flow_tests.rs")
    require("use crate::crypto::flow::{sequence_digest, Stage};" in flow_tests,
            "security integration: anti-glitch tests import flow through the wrong module")
    entropy_facade = read("apps/signer-firmware/src/services/entropy/mod.rs")
    require("pub(crate) use health::{inspect, HEALTH_SAMPLE_COUNT};" in entropy_facade,
            "security integration: entropy self-tests cannot reach structural health vectors")
    require("HealthReport" not in entropy_facade,
            "security integration: entropy facade leaks internal health diagnostics")

    entropy_collection = read("apps/signer-firmware/src/services/entropy/collection.rs")
    entropy_platform = read("apps/signer-firmware/src/services/entropy/platform.rs")
    entropy_seed = read("apps/signer-firmware/src/services/entropy/seed.rs")
    seed_generation = read("apps/signer-firmware/src/runtime/interactions/menu/seed_generation.rs")
    entropy_imu = read("apps/signer-firmware/src/services/entropy/imu.rs")
    entropy_ambient = read("apps/signer-firmware/src/services/entropy/ambient.rs")
    imu_hw = read("apps/signer-firmware/src/hw/waveshare/imu.rs")
    m5_imu_hw = read("apps/signer-firmware/src/hw/m5stack/imu.rs")
    firmware_manifest = read("apps/signer-firmware/Cargo.toml")
    firmware_lock = read("apps/signer-firmware/Cargo.lock")
    event_loop = read("apps/signer-firmware/src/runtime/event_loop/mod.rs")
    event_idle = read("apps/signer-firmware/src/runtime/event_loop/runner/idle.rs")
    event_touch = read("apps/signer-firmware/src/runtime/event_loop/touch.rs")
    waveshare_boot = read("apps/signer-firmware/src/boot/waveshare/mod.rs")
    m5stack_boot = "\n".join(
        read(f"apps/signer-firmware/src/boot/m5stack/{name}")
        for name in ("mod.rs", "power.rs", "display.rs", "audio.rs", "entropy.rs", "sd.rs", "camera.rs")
    )
    require(
        "trng::enable_hardware_rng()?" in entropy_collection
        and "validate_seed_entropy" in entropy_collection
        and "imu::mix_seed_sample" in entropy_collection,
        "security integration: restored IMU contribution must remain supplemental to fail-closed seed gates",
    )
    require(
        "SystemTimer::unit_value(Unit::Unit0)" in entropy_platform
        and "update_timing_pair_checked" in entropy_platform
        and "0x6002_3004" not in entropy_platform
        and "0x6002_3044" not in entropy_platform,
        "security integration: seed timing entropy must use esp-hal's value-valid/coherent SYSTIMER read instead of fixed-delay raw MMIO",
    )
    timing_before = entropy_seed.find("let timing_before = platform::timing_observation();")
    trng_draw = entropy_seed.find("let report = trng::fill_words(&mut trng_bytes)?;")
    timing_after = entropy_seed.find("let timing_after = platform::timing_observation();")
    require(
        -1 < timing_before < trng_draw < timing_after,
        "security integration: seed timing observations must bracket the checked WDEV RNG sampling loop",
    )
    require(
        '"   Entropy evidence: identity {} timing {}"' in entropy_collection
        and '"   Entropy rejected: {:?} ({})"' in seed_generation
        and "let message = error.message();" in seed_generation,
        "security integration: seed entropy rejection must expose the exact failed evidence dimension and non-empty mapped reason",
    )
    require(
        "count == sample.len()" in entropy_imu
        and "buffer_is_healthy" in entropy_imu
        and "mixer::zeroize(sample)" in entropy_imu,
        "security integration: production IMU samples must be complete, point-of-use health checked, and wiped",
    )
    require(
        "STATUS0_GYRO_DATA_READY" in imu_hw
        and "WHO_AM_I_VALUE" in imu_hw
        and "buffer_is_healthy" in imu_hw,
        "security integration: Waveshare QMI production driver lacks identity/freshness/health enforcement",
    )
    require(
        "BMI270_ADDR: u8 = 0x69" in m5_imu_hw
        and "BMI270_CHIP_ID: u8 = 0x24" in m5_imu_hw
        and "BMI270_CONFIG_FILE" in m5_imu_hw
        and "GYR_DATA_READY" in m5_imu_hw
        and "buffer_is_healthy" in m5_imu_hw,
        "security integration: CoreS3 BMI270 lacks config/identity/freshness/health enforcement",
    )
    require(
        "const BMI270_DRIVER_BUFFER_BYTES: usize = 512;" in m5_imu_hw
        and "Bmi2::<_, _, BMI270_DRIVER_BUFFER_BYTES>::new_i2c(" in m5_imu_hw
        and "        &mut *i2c,\n        &mut *delay,\n        I2cAddr::Alternative,\n        Burst::new(255)," in m5_imu_hw
        and "Burst::new(255)" in m5_imu_hw
        and "Burst::Other" not in m5_imu_hw
        and "bmi.init(&config::BMI270_CONFIG_FILE)" in m5_imu_hw
        and "bmi.init(&config::BMI270_CONFIG_FILE," not in m5_imu_hw
        and "config_buf" not in m5_imu_hw,
        "security integration: CoreS3 BMI270 adapter must match the pinned bmi2 0.1.2 blocking constructor/init API",
    )
    require(
        "ACC_CONF_NORMAL_100HZ: u8 = 0xA8" in m5_imu_hw
        and "GYR_CONF_NORMAL_200HZ: u8 = 0xA9" in m5_imu_hw
        and "GYR_RANGE_ENTROPY_250DPS: u8 = 0x03" in m5_imu_hw
        and 'write_named_reg(i2c, REG_GYR_RANGE, GYR_RANGE_ENTROPY_250DPS, "GYR_RANGE")' in m5_imu_hw
        and "PWR_CONF_NORMAL: u8 = 0x02" in m5_imu_hw
        and "PWR_CTRL_NORMAL: u8 = 0x06" in m5_imu_hw
        and "GYRO_STARTUP_MS: u32 = 350" in m5_imu_hw
        and "GYRO_SAMPLE_INTERVAL_MS: u32 = 6" in m5_imu_hw
        and "bmi.set_pwr_ctrl(PwrCtrl {" in m5_imu_hw
        and "write_normal_mode(i2c)" in m5_imu_hw
        and "normal_mode_matches(i2c)" in m5_imu_hw
        and 'BMI270 mode readback PWR_CTRL={:?} ACC_CONF={:?} GYR_CONF={:?} GYR_RANGE={:?} PWR_CONF={:?}' in m5_imu_hw
        and "PWR_CTRL_GYRO_ONLY" not in m5_imu_hw
        and "delay.delay_millis(GYRO_STARTUP_MS)" in m5_imu_hw
        and "fatal_error(i2c)" in m5_imu_hw,
        "security integration: CoreS3 BMI270 must enter verified normal gyro mode and wait through startup before health sampling",
    )
    require(
        'bmi2 = { version = "=0.1.2", optional = true }' in firmware_manifest
        and 'm5stack = ["esp-println/jtag-serial", "dep:bmi2"]' in firmware_manifest
        and 'name = "bmi2"' in firmware_lock
        and 'version = "0.1.2"' in firmware_lock
        and '48eb062697fa0234a96acdc8ed34f141e9f2951d34e358ed449f312d7e5b6469' in firmware_lock,
        "security integration: CoreS3 BMI270 dependency must remain exact-pinned/checksummed and M5-only",
    )
    require(
        "EntropyError::ImuUnavailable" in entropy_collection
        and "pre_healthy || post_healthy" in entropy_collection,
        "security integration: CoreS3 new-seed generation must fail closed without a healthy BMI270 window",
    )
    m5_camera_init = read("apps/signer-firmware/src/hw/m5stack/cameras/gc0308/initialization.rs")
    camera_entropy = read("apps/signer-firmware/src/services/entropy/camera/mod.rs")
    camera_dvp = read("apps/signer-firmware/src/services/entropy/camera/dvp.rs")
    shared_dvp = read("apps/signer-firmware/src/hw/shared/dvp.rs")
    require(
        '#[cfg(feature = "m5stack")]\npub(super) const SEED_SAMPLE_BYTES: usize = 33;' in entropy_imu
        and "count == sample.len()" in entropy_imu
        and "buffer_is_healthy" in entropy_imu,
        "security integration: CoreS3 seed IMU window must use the physically boot-proven 11-samples-per-axis window without weakening completeness/diversity checks",
    )
    require(
        "const NOISE_REMOVAL_ENABLE: u8 = 1 << 2;" in m5_camera_init
        and "prior & !NOISE_REMOVAL_ENABLE" in m5_camera_init
        and "begin_entropy_capture(i2c)" in camera_entropy
        and "end_entropy_capture(i2c, prior)" in camera_entropy,
        "security integration: CoreS3 camera entropy capture must expose temporal sensor variation by temporarily disabling ISP denoise and restore the prior camera configuration",
    )
    require(
        "MAX_CAMERA_HEALTH_WINDOWS" in camera_entropy
        and "should_retry_camera_window" in camera_entropy
        and "receive_full_frame" in camera_dvp
        and "transfer.is_done()" in shared_dvp
        and "FrameCaptureStatus::TimedOut" in shared_dvp
        and "partial transfer is stopped and must not be consumed" in shared_dvp,
        "security integration: camera entropy must use bounded complete-buffer DVP capture and bounded fresh health-window retries without accepting partial frames",
    )
    require(
        "Efuse::read_base_mac_address()" in entropy_platform
        and "OPTIONAL_UNIQUE_ID" in entropy_platform
        and "Efuse::read_field_le(OPTIONAL_UNIQUE_ID)" in entropy_platform
        and "KasSigner/optional-unique-id/v1" in entropy_platform
        and entropy_seed.count("update_optional_unique_id(&mut hasher)") == 1
        and "zero-credit deterministic device binding" in entropy_seed
        and entropy_collection.index("validate_seed_entropy(entropy_evidence)")
            < entropy_collection.index("seed::whiten(&mut pool, idle_ticks)?"),
        "security integration: factory MAC and OPTIONAL_UNIQUE_ID must be mixed only as zero-credit post-gate device binding",
    )
    require(
        "LAST_TOUCH" in entropy_ambient
        and "KasSigner-ambient-stage-v2" in entropy_ambient
        and "ambient::mix_staged" in entropy_collection
        and "stage_ambient_touch" in event_touch,
        "security integration: changed ambient touch observations are not staged into later checked fills",
    )
    require(
        "IMU_RESTAGE_TICKS" in event_loop
        and "runner::restage_imu" in event_loop
        and "stage_idle_imu" in event_idle
        and "initialize_imu" in waveshare_boot
        and "initialize_imu" in m5stack_boot
        and "imu::mix_staged" in entropy_collection,
        "security integration: board IMU initialization/staging is not wired into production randomness",
    )

    workflow = read("apps/signer-firmware/src/runtime/signing/workflow.rs")
    require("signing_entropy" in workflow and "entropy::fill" in workflow,
            "security integration: signing must obtain checked auxiliary entropy")
    require("kspt::sign_input(ad, signing_strategy, input_idx, &signing_entropy, liveness)" in workflow
            and "shared_signer::bytes::zeroize_bytes(&mut signing_entropy)" in workflow,
            "security integration: firmware per-input signing does not use the fail-closed entropy path")

    message_signing = read("apps/signer-firmware/src/runtime/interactions/tx/message_signing/service.rs")
    require(
        "entropy::fill(&mut signing_entropy)" in message_signing
        and "sign_user_message_with_entropy" in message_signing
        and "message_digest(ad)" not in message_signing,
        "security integration: domain-separated on-device message signing must fail closed on entropy health",
    )

    flow = read("apps/signer-firmware/src/crypto/flow.rs")
    require("pub enum Stage" in flow and "sequence_digest" in flow,
            "security integration: ordered anti-glitch transcript is missing")
    require("AtomicU32" in flow and "compare_exchange" in flow,
            "security integration: anti-glitch stage order is not atomically recorded")

    extended_private = read("crates/offline-signer/src/derivation/bip32/extended_private.rs")
    extended_public = read("crates/offline-signer/src/derivation/bip32/extended_public.rs")
    bip39_types = read("crates/offline-signer/src/derivation/bip39/types.rs")
    require("ZeroizeOnDrop" in extended_private and "#[derive(Zeroize, ZeroizeOnDrop)]" in extended_private,
            "security integration: extended private keys are not wiped on drop")
    require("ZeroizeOnDrop" in extended_public and "ZeroizeOnDrop" in extended_public.split("pub struct ExtendedPubKey", 1)[0],
            "security integration: extended public keys are not wiped on drop")
    require(bip39_types.count("ZeroizeOnDrop") >= 4,
            "security integration: mnemonic/seed containers are not wiped on drop")

    main = read("apps/signer-firmware/src/main.rs")
    application_boot = read("apps/signer-firmware/src/boot/shared/application.rs")
    boot = read("apps/signer-firmware/src/runtime/unit_tests/boot.rs")
    require("bip340_known_answer" in boot,
            "security integration: published BIP-340 boot vector is missing")
    require('panic!("boot cryptographic known-answer test failed")' in application_boot,
            "security integration: failed boot KAT must halt the firmware")
    require('all(feature = "skip-tests", feature = "silent")' in main,
            "security integration: production must reject skip-tests")

    lockdown = read("apps/signer-firmware/src/hw/shared/lockdown.rs")
    require("RTC_CNTL_WIFI_FORCE_PD" in lockdown and "radio_power_is_off" in lockdown,
            "security integration: radio power-domain lockdown lacks verified read-back")
    require("boot::security::early_lockdown();" in main,
            "security integration: shared lockdown is not called for both boards")

    verify_format = read("apps/signer-firmware/src/services/verify/format.rs")
    tx_summary = read("apps/signer-firmware/src/ui/screens/signing/transaction_review/summary.rs")
    require("take(8)" in verify_format or "[0..8]" in verify_format or "[..8]" in verify_format,
            "security integration: firmware verification code is not 64-bit")
    require("[..8]" in tx_summary or "take(8)" in tx_summary,
            "security integration: transaction verification code is not 64-bit")

    web_payload_reviews = (
        "apps/kassee-web/web/js/features/transactions/send/review.js",
        "apps/kassee-web/web/js/features/transactions/pskt_multisig/review.js",
    )
    for review_path in web_payload_reviews:
        review = read(review_path)
        require("slice(0, 8)" in review,
                f"security integration: KasSee payload verification code is not 64-bit in {review_path}")
        require("slice(0, 4)" not in review and "SHA-256[..4]" not in review,
                f"security integration: legacy 32-bit payload verification remains in {review_path}")

    scalar = read("crates/offline-signer/src/derivation/bip32/scalar.rs")
    require("subtle" not in scalar or "Choice" in scalar,
            "security integration: BIP32 scalar path lacks a constant-time selection primitive")
    require("conditional" in scalar.lower() or "select" in scalar.lower(),
            "security integration: BIP32 scalar comparison/reduction is not constant-time")

    sd_facade = read("apps/signer-firmware/src/hw/waveshare/storage/mod.rs")
    require("let _ = &$i2c;" in sd_facade,
            "security integration: Waveshare SD facade must consume the shared I2C argument")

    stego = read("apps/signer-firmware/src/services/stego/mod.rs")
    picture = read("crates/signer-firmware-core/src/backup/stego_picture/mod.rs")
    copyforward = read("apps/signer-firmware/src/services/stego/exif/copyforward.rs")
    template = read("apps/signer-firmware/src/services/stego/exif/template.rs")
    require("StegoCarrier" in stego and "Picture" in stego,
            "security integration: Picture carrier is absent from the stego facade")
    for leaked in ("base64_encode", "PayloadError", "PictureError"):
        require(f"pub use {leaked}" not in stego and f", {leaked}" not in stego,
                f"security integration: stego facade leaks unused internal API {leaked}")
    require(
        "fn consume_embedding_rank" in picture
        and "changed_value != 0" in picture
        and "if consume_embedding_rank" in picture
        and "payload_bit += 1" in picture,
        "security integration: Picture carrier does not implement shrinkage-safe embedding",
    )
    require("CoverStream" not in picture,
            "security integration: Picture carrier must stop after the framed payload")
    jpeg = read("apps/signer-firmware/src/services/stego/jpeg.rs")
    require("host_exif" in jpeg and "marker == 0xE1" in jpeg,
            "security integration: descriptor export does not replace stale EXIF precisely")
    require("Non-EXIF APP1" in jpeg,
            "security integration: non-EXIF metadata preservation contract is missing")
    require("build_copyforward" in copyforward,
            "security integration: existing EXIF metadata is not copied forward")
    for tag in ("0x0131", "0x0132", "0xA002", "0xA003"):
        require(tag in template, f"security integration: plausible EXIF template missing tag {tag}")

    decode = read("apps/signer-firmware/src/hw/waveshare/cameras/decode_core/mod.rs")
    require("core1_main" in decode and "JOB_STATE" in decode and "GENERATION" in decode,
            "security integration: generation-safe second-core QR worker is missing")
    decode_start = read("apps/signer-firmware/src/boot/waveshare/decode_worker.rs")
    require("CpuControl::new" in decode_start and "start_app_core" in decode_start,
            "security integration: second CPU core is not started")

    docker_base = read("Dockerfile.base")
    docker = read("Dockerfile")
    docker_runner = read("scripts/linux/build/reproducible-build.sh")
    prefetch = read("scripts/linux/build/reproducible/prefetch.py")
    toolchain_prefetch = read("scripts/linux/build/reproducible/toolchains.py")
    toolchains = read("qa/config/toolchains.env")
    require("KASSIGNER_UBUNTU_BASE_DIGEST=sha256:" in toolchains,
            "security integration: pinned Ubuntu OCI digest is missing")
    require("KASSIGNER_UBUNTU_BASE_DIGEST" in prefetch and "KASSIGNER_UBUNTU_SNAPSHOT" in prefetch,
            "security integration: host prefetch does not consume pinned Ubuntu inputs")
    require("KASSIGNER_ESP_RUST=" in toolchains,
            "security integration: central ESP Rust toolchain pin is missing")
    require("KASSIGNER_ESP_RUST" in toolchain_prefetch and "--toolchain-version" in toolchain_prefetch,
            "security integration: host prefetch does not consume the central ESP Rust pin")
    require("BUILD-INPUT-SHA256SUMS" in docker_base and "--offline" in docker_base,
            "security integration: Docker toolchain image does not verify prefetched inputs/offline Cargo")
    require(docker_runner.count("--network=none") >= 2 and "docker pull" not in docker_runner,
            "security integration: reproducible Docker builds are not fully network-disabled")
    require(
        "for PASS in 1 2 3 4 5" in docker
        and "HASHES[1]" in docker
        and "HASHES[2]" in docker
        and "HASHES[3]" in docker
        and "HASHES[4]" in docker
        and "passes 2 through 5" in docker,
        "security integration: deterministic five-pass convergence assertion is missing",
    )
    for output in (
        "kassigner-waveshare-unsigned", "kassigner-waveshare-af-unsigned",
        "kassigner-m5stack-unsigned", "kassigner-waveshare",
        "kassigner-waveshare-af", "kassigner-m5stack",
    ):
        require(output in docker, f"security integration: release output missing {output}")
    require("skip-tests" not in docker.replace("skip-tests is prohibited", ""),
            "security integration: release Dockerfile still enables skip-tests")

    installer = read("tools/install/macos/firmware.sh")
    require("--features skip-tests" not in installer,
            "security integration: installer still skips boot tests")
    for manifest in (
        "apps/signer-firmware/Cargo.toml", "apps/kassee-web/Cargo.toml",
        "crates/offline-signer/Cargo.toml", "crates/online-watcher/Cargo.toml",
        "crates/shared-signer/Cargo.toml", "qa/Cargo.toml",
    ):
        require('version = "2.0.0"' in read(manifest), f"security integration: version not aligned in {manifest}")
