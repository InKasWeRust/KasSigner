"""Load the repository's single pinned toolchain/version policy."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
POLICY_PATH = ROOT / "qa/config/toolchains.env"

REQUIRED = {
    "KASSIGNER_STABLE_RUST",
    "KASSIGNER_BRANCH_RUST",
    "KASSIGNER_REPRO_HOST_RUST",
    "KASSIGNER_ESP_RUST",
    "KASSIGNER_ESPUP_VERSION",
    "KASSIGNER_ESPFLASH_VERSION",
    "KASSIGNER_ESP_IDF_VERSION",
    "KASSIGNER_CARGO_LLVM_COV_VERSION",
    "KASSIGNER_CARGO_CRAP_VERSION",
    "KASSIGNER_CARGO_FUZZ_VERSION",
    "KASSIGNER_CARGO_MUTANTS_VERSION",
    "KASSIGNER_RUSTUP_VERSION",
    "KASSIGNER_WASM_BINDGEN_CLI_VERSION",
    "KASSIGNER_ANDROID_JDK",
    "KASSIGNER_GRADLE_VERSION",
    "KASSIGNER_KOTLIN_CLI_VERSION",
    "KASSIGNER_ANDROID_API",
    "KASSIGNER_ANDROID_BUILD_TOOLS",
    "KASSIGNER_ANDROID_CMDLINE_TOOLS",
    "KASSIGNER_ANDROID_CMDLINE_TOOLS_LINUX_SHA256",
    "KASSIGNER_ANDROID_CMDLINE_TOOLS_WINDOWS_SHA256",
    "KASSIGNER_UBUNTU_BASE_DIGEST",
    "KASSIGNER_UBUNTU_SNAPSHOT",
    "KASSIGNER_UBUNTU_CA_CERTIFICATES",
    "KASSIGNER_UBUNTU_CURL",
    "KASSIGNER_UBUNTU_GCC",
    "KASSIGNER_UBUNTU_GXX",
    "KASSIGNER_UBUNTU_LIBSSL_DEV",
    "KASSIGNER_UBUNTU_LIBUDEV_DEV",
    "KASSIGNER_UBUNTU_LIBUSB_DEV",
    "KASSIGNER_UBUNTU_PKG_CONFIG",
    "KASSIGNER_UBUNTU_PYTHON3",
}


def load_toolchains(path: Path = POLICY_PATH) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text().splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"invalid toolchain policy line {number}: {raw!r}")
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key or not value:
            raise ValueError(f"invalid toolchain policy line {number}: {raw!r}")
        if key in values:
            raise ValueError(f"duplicate toolchain policy key: {key}")
        values[key] = value
    missing = sorted(REQUIRED - values.keys())
    if missing:
        raise ValueError("missing toolchain policy keys: " + ", ".join(missing))
    unknown = sorted(values.keys() - REQUIRED)
    if unknown:
        raise ValueError("unknown toolchain policy keys: " + ", ".join(unknown))
    return values
