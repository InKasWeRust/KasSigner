"""Canonical firmware feature combinations used by build and lint validation."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FirmwareBuild:
    features: str
    environment: tuple[tuple[str, str], ...] = ()

    def env_overrides(self) -> dict[str, str]:
        return dict(self.environment)


PSRAM_OCTAL = (("ESP_HAL_CONFIG_PSRAM_MODE", "octal"),)

FEATURE_MATRIX = (
    FirmwareBuild("waveshare", PSRAM_OCTAL),
    FirmwareBuild("waveshare,silent", PSRAM_OCTAL),
    FirmwareBuild("waveshare,production", PSRAM_OCTAL),
    FirmwareBuild("waveshare,ov5640-af", PSRAM_OCTAL),
    FirmwareBuild("m5stack"),
    FirmwareBuild("m5stack,silent"),
    FirmwareBuild("m5stack,production"),
    # Developer/QA diagnostics are compile-tested but feature_policy.rs keeps
    # them out of silent/production release images.
    FirmwareBuild("waveshare,sentinel-scan", PSRAM_OCTAL),
    FirmwareBuild("waveshare,e12-capture", PSRAM_OCTAL),
    FirmwareBuild("waveshare,rng-probe", PSRAM_OCTAL),
    FirmwareBuild("waveshare,wdev-capture", PSRAM_OCTAL),
    FirmwareBuild("waveshare,sha-bench", PSRAM_OCTAL),
    FirmwareBuild("waveshare,argon2-bench", PSRAM_OCTAL),
    FirmwareBuild("waveshare,imu-dump", PSRAM_OCTAL),
    FirmwareBuild("waveshare,icon-browser", PSRAM_OCTAL),
    FirmwareBuild("waveshare,cam640", PSRAM_OCTAL),
    FirmwareBuild("waveshare,boot-kats-full", PSRAM_OCTAL),
    FirmwareBuild("m5stack,sentinel-scan"),
    FirmwareBuild("m5stack,e12-capture"),
    FirmwareBuild("m5stack,rng-probe"),
    FirmwareBuild("m5stack,wdev-capture"),
    FirmwareBuild("m5stack,sha-bench"),
    FirmwareBuild("m5stack,argon2-bench"),
    FirmwareBuild("m5stack,icon-browser"),
    FirmwareBuild("m5stack,boot-kats-full"),
    FirmwareBuild("waveshare,workflow-tests", PSRAM_OCTAL),
    FirmwareBuild("m5stack,workflow-tests"),
    FirmwareBuild("waveshare,workflow-test-auto", PSRAM_OCTAL),
    FirmwareBuild("m5stack,workflow-test-auto"),
    FirmwareBuild("qemu"),
    FirmwareBuild("qemu-tests"),
)
