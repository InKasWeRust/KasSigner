# KasSigner : Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0
#

.PHONY: firmware firmware-dev firmware-m5 firmware-mirror core-test kassee kassee-wasm all clean help

## Device firmware: Waveshare ESP32-S3-Touch-LCD-2 (default)
firmware:
	cd bootloader && ESP_HAL_CONFIG_PSRAM_MODE=octal cargo build --release

## Device firmware: Waveshare (dev build, skip self-tests)
firmware-dev:
	cd bootloader && ESP_HAL_CONFIG_PSRAM_MODE=octal cargo run --release --features skip-tests

## Device firmware: M5Stack CoreS3 Lite
firmware-m5:
	cd bootloader && cargo run --release --no-default-features --features m5stack

## Device firmware: Waveshare with live display mirror
firmware-mirror:
	cd bootloader && ESP_HAL_CONFIG_PSRAM_MODE=octal cargo run --release --features waveshare,mirror,skip-tests

## Host tests for the security-critical core crate (no hardware, no Xtensa)
core-test:
	cd core && cargo test

## KasSee companion wallet, native type check (standard Rust, any platform)
kassee:
	cd kassee && cargo build --release

## KasSee companion wallet, the real WASM artifact (needs wasm-pack)
kassee-wasm:
	cd kassee && RUSTUP_TOOLCHAIN=stable ./build.sh

## Build both (firmware requires Xtensa toolchain)
all: firmware kassee

## Clean all build artifacts
clean:
	cd bootloader && cargo clean
	cd core && cargo clean
	cd kassee && cargo clean
	cd tools && cargo clean

## Help
help:
	@echo "KasSigner build targets:"
	@echo "  make firmware         Waveshare firmware (release)"
	@echo "  make firmware-dev     Waveshare firmware (dev, skip tests)"
	@echo "  make firmware-m5      M5Stack firmware"
	@echo "  make firmware-mirror  Waveshare with display mirror"
	@echo "  make core-test        Host tests for the core crate"
	@echo "  make kassee           KasSee native type check"
	@echo "  make kassee-wasm      KasSee WASM build (wasm-pack)"
	@echo "  make all              Build firmware + kassee"
	@echo "  make clean            Clean all build artifacts"
