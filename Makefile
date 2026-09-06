# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
# License: GPL-3.0
#
# GNU Make is the small public developer interface. Detailed QA/build steps
# live under scripts/, tools/, and qa/ and are orchestrated internally.

include qa/config/toolchains.env

ifeq ($(OS),Windows_NT)
PYTHON ?= python
else
PYTHON ?= python3
endif

MAKE_TASK := $(PYTHON) scripts/common/lib/make_tasks.py

FUZZ_PASSES ?= 100000
STRICT_LOCKFILES ?=
BOARD ?= m5stack
PORT ?=
HARDWARE_TIMEOUT ?= 240
WORKFLOW_TIMEOUT ?= 480
RESUME_FROM ?=
RELEASE_DIR ?= release
SIGNING_KEY ?=
REFRESH_INPUTS ?=
OWNER_KEY ?=
OWNER_DIR ?= target/owner-firmware
SECURE_BOOT_KEY ?=
SECURE_DIR ?=

.PHONY: kassee sdk ios ios-release ios-test ios-qa android android-release android-test android-qa \
	firmware flash flash-release secure-provisioning secure-owner-only firmware-mirror owner-firmware test-hardware workflow-e2e workflow-hil \
	firmware-qemu-setup firmware-qemu firmware-qemu-test test qa release release-readiness clean help

# KASSEE / SDK
kassee:
	$(MAKE_TASK) entrypoint kassee-web-build

sdk:
	$(MAKE_TASK) entrypoint sdk-build

# IOS — real Xcode operations; these fail clearly outside macOS/Xcode.
ios:
	$(MAKE_TASK) ios build

ios-release:
	$(MAKE_TASK) ios release

ios-test:
	$(MAKE_TASK) ios test

ios-qa:
	$(MAKE_TASK) ios qa

# ANDROID — real Gradle/API-37 operations.
android:
	$(MAKE_TASK) android build

android-release:
	$(MAKE_TASK) android release

android-test:
	$(MAKE_TASK) android test

android-qa:
	$(MAKE_TASK) android qa

# FIRMWARE / DEVICE
firmware:
	$(MAKE_TASK) firmware "$(BOARD)"

flash:
	$(MAKE_TASK) flash "$(BOARD)" "$(PORT)"

flash-release:
	$(MAKE_TASK) flash-release "$(BOARD)" "$(PORT)" "$(RELEASE_DIR)"

secure-provisioning:
	$(MAKE_TASK) secure-release dual "$(SECURE_DIR)" "$(SECURE_BOOT_KEY)" "$(SIGNING_KEY)"

secure-owner-only:
	$(MAKE_TASK) secure-release owner-only "$(SECURE_DIR)" "$(OWNER_KEY)" ""

firmware-mirror:
	$(MAKE_TASK) firmware mirror

owner-firmware:
	$(MAKE_TASK) owner-firmware "$(OWNER_DIR)" "$(OWNER_KEY)"

test-hardware:
	$(MAKE_TASK) test-hardware "$(BOARD)" "$(PORT)" "$(HARDWARE_TIMEOUT)" "$(STRICT_LOCKFILES)"

workflow-e2e:
	$(MAKE_TASK) workflow-e2e "$(BOARD)" "$(PORT)" "$(WORKFLOW_TIMEOUT)" "$(RESUME_FROM)"

workflow-hil:
	$(MAKE_TASK) workflow-hil "$(BOARD)" "$(PORT)" "$(WORKFLOW_TIMEOUT)" "$(RESUME_FROM)"

firmware-qemu-setup:
	$(MAKE_TASK) entrypoint qemu-setup

firmware-qemu:
	$(MAKE_TASK) entrypoint qemu-build

firmware-qemu-test:
	$(MAKE_TASK) entrypoint qemu-test

# COMMON QA
test:
	$(MAKE_TASK) test "$(STRICT_LOCKFILES)"

qa:
	$(MAKE_TASK) qa "$(FUZZ_PASSES)" "$(STRICT_LOCKFILES)" "$(RESUME_FROM)"

# RELEASE
release:
	$(MAKE_TASK) release "$(RELEASE_DIR)" "$(SIGNING_KEY)" "$(REFRESH_INPUTS)"

release-readiness:
	$(MAKE_TASK) entrypoint release-readiness

# OTHER
clean:
	$(MAKE_TASK) clean

help:
	@$(MAKE_TASK) help
