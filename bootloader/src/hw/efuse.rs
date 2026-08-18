//! Runtime read of the eFuse bits that record how this device was
//! provisioned.
//!
//! # What this is, and what it is not
//!
//! It is **not** tamper evidence. Firmware able to run unsigned code also
//! controls this read and the screen that displays it, and would simply
//! draw whatever it liked. Anyone reading the verification screen and
//! concluding "Secure Boot is enforced, therefore this firmware is
//! trusted" has the implication backwards.
//!
//! It is a check against **our own provisioning error**: a device that was
//! flashed but never had its eFuses burned, or one where a burn silently
//! failed. `docs/EFUSE_RUNBOOK.md` has four separate burn steps, and
//! nothing on the device ever confirmed afterwards that they took. Until
//! now an unprovisioned unit presented an identical screen to a
//! provisioned one.
//!
//! Same class as two hardware defects this project has already shipped and
//! found only by measuring: the ESP32-S3 RNG address, and the battery
//! divider that was never populated.
//!
//! # Registers
//!
//! Two read-only words from the eFuse controller at base `0x6000_7000`:
//!
//! - `EFUSE_RD_REPEAT_DATA0_REG`, offset `0x0030`, TRM Register 5.13.
//!   `DIS_PAD_JTAG` at bit 19.
//! - `EFUSE_RD_REPEAT_DATA2_REG`, offset `0x0038`, TRM Register 5.15.
//!   `SECURE_BOOT_EN` (20), `SECURE_BOOT_AGGRESSIVE_REVOKE` (21),
//!   `DIS_USB_JTAG` (22), `DIS_USB_SERIAL_JTAG` (23).
//!
//! # Why five bits and not three
//!
//! **JTAG must be shut on both paths.** The USB bridge and the physical
//! pads are separate routes to the same debug port, and whoever reaches it
//! can halt the CPU and read RAM on a device holding seed material.
//! `EFUSE_RUNBOOK.md` Step 8 says so: "A board with Secure Boot burned but
//! JTAG left open is not hardened." Checking only `DIS_USB_JTAG` would let
//! a board with the pad path still open report itself hardened.
//!
//! **Download mode is deliberately left open** and is not checked here.
//! Secure Boot means the ROM refuses to *run* an image not signed with the
//! burned digest, so a host that can write flash gains nothing, while
//! closing it would leave an air-gapped device with no update path at all.
//! The runbook states the same conclusion. Reporting those fuses as "not
//! hardened" would therefore be wrong.

/// eFuse controller base address (TRM peripheral map).
const EFUSE_BASE: u32 = 0x6000_7000;

/// `EFUSE_RD_REPEAT_DATA0_REG`, BLOCK0 data register 1, RO.
const EFUSE_RD_REPEAT_DATA0_REG: u32 = EFUSE_BASE + 0x0030;

/// `EFUSE_RD_REPEAT_DATA2_REG`, BLOCK0 data register 3, RO.
const EFUSE_RD_REPEAT_DATA2_REG: u32 = EFUSE_BASE + 0x0038;

/// In DATA0.
const BIT_DIS_PAD_JTAG: u32 = 1 << 19;

// The remainder are in DATA2.
const BIT_SECURE_BOOT_EN: u32 = 1 << 20;
const BIT_SECURE_BOOT_AGGRESSIVE_REVOKE: u32 = 1 << 21;
const BIT_DIS_USB_JTAG: u32 = 1 << 22;
const BIT_DIS_USB_SERIAL_JTAG: u32 = 1 << 23;

/// The five provisioning bits, as read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecureBootState {
    /// ROM bootloader verifies the image signature. Runbook: burned.
    pub secure_boot_en: bool,
    /// Physical JTAG pads permanently disabled. Runbook: burned.
    pub dis_pad_jtag: bool,
    /// Aggressive key revocation. Runbook: not burned.
    pub aggressive_revoke: bool,
    /// USB-OTG-to-JTAG bridge disabled. Runbook: burned.
    pub dis_usb_jtag: bool,
    /// USB Serial/JTAG disabled. Runbook: **not** burned, download mode is
    /// deliberately preserved so a device can be reflashed.
    pub dis_usb_serial_jtag: bool,
}

impl SecureBootState {
    /// Does this match the end state `docs/EFUSE_RUNBOOK.md` produces?
    ///
    /// Note `dis_usb_serial_jtag` must be **false**: download mode is kept
    /// on purpose, so burning it would be a provisioning mistake in the
    /// other direction and is reported as a mismatch too.
    pub fn matches_runbook(&self) -> bool {
        self.secure_boot_en
            && !self.aggressive_revoke
            && self.dis_pad_jtag
            && self.dis_usb_jtag
            && !self.dis_usb_serial_jtag
    }

    /// One short line for the verification screen.
    ///
    /// Fits the 320 px layout at body size. The provisioned case is
    /// deliberately terse; every other case names what is wrong, because
    /// the whole point is that an unprovisioned device should not look
    /// like a provisioned one.
    pub fn screen_line(&self) -> &'static str {
        if self.matches_runbook() {
            "eFuse: SB on, JTAG off"
        } else if !self.secure_boot_en {
            "eFuse: SECURE BOOT OFF"
        } else if !self.dis_pad_jtag || !self.dis_usb_jtag {
            // Either path open means not hardened, and the message does not
            // distinguish them: the remedy is the same burn step either way.
            "eFuse: JTAG STILL OPEN"
        } else if self.dis_usb_serial_jtag {
            "eFuse: USB SERIAL BURNED"
        } else {
            // secure_boot_en, both JTAG paths shut and usb_serial preserved,
            // so the only bit left is aggressive_revoke.
            "eFuse: AGGRESSIVE REVOKE"
        }
    }
}

/// Read the provisioning state.
///
/// A single volatile load from a read-only register. No side effects, safe
/// to call at any point after boot.
pub fn read_secure_boot_state() -> SecureBootState {
    // SAFETY: both are read-only 32-bit registers in the eFuse
    // controller's memory-mapped range, present on every ESP32-S3. Reading
    // them cannot fault and has no side effects. Same access pattern as
    // `hw/lockdown.rs`.
    let d0 = unsafe { core::ptr::read_volatile(EFUSE_RD_REPEAT_DATA0_REG as *const u32) };
    let v = unsafe { core::ptr::read_volatile(EFUSE_RD_REPEAT_DATA2_REG as *const u32) };

    SecureBootState {
        secure_boot_en: v & BIT_SECURE_BOOT_EN != 0,
        dis_pad_jtag: d0 & BIT_DIS_PAD_JTAG != 0,
        aggressive_revoke: v & BIT_SECURE_BOOT_AGGRESSIVE_REVOKE != 0,
        dis_usb_jtag: v & BIT_DIS_USB_JTAG != 0,
        dis_usb_serial_jtag: v & BIT_DIS_USB_SERIAL_JTAG != 0,
    }
}
