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
//! Four read-only words from the eFuse controller at base `0x6000_7000`:
//!
//! - `EFUSE_RD_WR_DIS_REG`, offset `0x002C`, TRM Register 5.12. One bit per
//!   protectable parameter, 1 meaning programming is disabled. Table 5-1
//!   assigns `KEY_PURPOSE_0..5` to bits 8 through 13.
//! - `EFUSE_RD_REPEAT_DATA0_REG`, offset `0x0030`, TRM Register 5.13.
//!   `DIS_PAD_JTAG` at bit 19.
//! - `EFUSE_RD_REPEAT_DATA1_REG`, offset `0x0034`, TRM Register 5.14.
//!   `SECURE_BOOT_KEY_REVOKE0..2` at 21, 22, 23; `KEY_PURPOSE_0` at 27:24
//!   and `KEY_PURPOSE_1` at 31:28.
//! - `EFUSE_RD_REPEAT_DATA2_REG`, offset `0x0038`, TRM Register 5.15.
//!   `KEY_PURPOSE_2..5` at 3:0, 7:4, 11:8, 15:12; `SECURE_BOOT_EN` (20),
//!   `SECURE_BOOT_AGGRESSIVE_REVOKE` (21), `DIS_USB_JTAG` (22),
//!   `DIS_USB_SERIAL_JTAG` (23).
//!
//! # Why JTAG needs both bits
//!
//! The USB bridge and the physical pads are separate routes to the same
//! debug port, and whoever reaches it can halt the CPU and read RAM on a
//! device holding seed material. `EFUSE_RUNBOOK.md` Step 8 says so: "A
//! board with Secure Boot burned but JTAG left open is not hardened."
//! Checking only `DIS_USB_JTAG` would let a board with the pad path still
//! open report itself hardened.
//!
//! # Why the digest slots are a derived condition and not a fixed pattern
//!
//! Secure Boot V2 accepts a signature matching any of three digest slots.
//! The danger is a slot an attacker can take over, and that needs three
//! things at once: the slot is not revoked, no digest occupies it, and a
//! `KEY_PURPOSE` field is still writable so it can be aimed at a key block
//! the attacker burns. Remove any one and there is no door. The runbook
//! puts it in its own words: "A board with `SECURE_BOOT_EN` burned and a
//! slot left open is not provisioned."
//!
//! An earlier version of this check hardcoded the single-key end state,
//! `REVOKE0` clear with `REVOKE1` and `REVOKE2` burned. That is one of two
//! configurations the runbook produces, and it fails the other. A two-key
//! board carries digests in slots 0 and 1 and revokes only slot 2, so its
//! `REVOKE1` is legitimately clear. Measured on hardware 2026-08-30: one
//! board reports `Valid secure boot key blocks: 0`, the other `0 1`, and
//! both are provisioned correctly. A fixed pattern paints the second one
//! red, which is a false alarm of exactly the same family as the false
//! affirmative this module exists to remove, pointed the other way.
//!
//! Slot `k` is occupied when some `KEY_PURPOSE_n` reads `9 + k`, the values
//! `SECURE_BOOT_DIGEST0`, `DIGEST1` and `DIGEST2` from TRM Table 5-2. That
//! is the only way to tell a free slot from a used one, so the purpose
//! fields have to be read; the revoke bits alone cannot answer it.
//!
//! Write protection is the third term and it is not redundant. A board can
//! leave a slot unrevoked and empty and still be safe if every purpose
//! field is locked, because nothing can then be pointed at that slot. One
//! of the two boards measured is in exactly that state, with all six
//! purposes reading `R/-`.
//!
//! # What is deliberately not checked
//!
//! **Download mode.** Secure Boot means the ROM refuses to *run* an image
//! not signed with a burned digest, so a host that can write flash gains
//! nothing, while closing it would leave an air-gapped device with no
//! update path at all. The runbook reaches the same conclusion. Reporting
//! those fuses as "not hardened" would be wrong.
//!
//! **Which slot booted us.** `SECURE_BOOT_KEY_REVOKE0` being burned on a
//! running device would mean the image was verified against some other
//! slot, which is suggestive on a one-key board and entirely normal on a
//! two-key one. Not distinguishable from here, so not reported.

/// eFuse controller base address (TRM peripheral map).
const EFUSE_BASE: u32 = 0x6000_7000;

/// `EFUSE_RD_WR_DIS_REG`, BLOCK0 data register 0, RO.
const EFUSE_RD_WR_DIS_REG: u32 = EFUSE_BASE + 0x002C;

/// `EFUSE_RD_REPEAT_DATA0_REG`, BLOCK0 data register 1, RO.
const EFUSE_RD_REPEAT_DATA0_REG: u32 = EFUSE_BASE + 0x0030;

/// `EFUSE_RD_REPEAT_DATA1_REG`, BLOCK0 data register 2, RO.
const EFUSE_RD_REPEAT_DATA1_REG: u32 = EFUSE_BASE + 0x0034;

/// `EFUSE_RD_REPEAT_DATA2_REG`, BLOCK0 data register 3, RO.
const EFUSE_RD_REPEAT_DATA2_REG: u32 = EFUSE_BASE + 0x0038;

/// In DATA0.
const BIT_DIS_PAD_JTAG: u32 = 1 << 19;

// In DATA1. 1 means revoked.
const BIT_SECURE_BOOT_KEY_REVOKE0: u32 = 1 << 21;
const BIT_SECURE_BOOT_KEY_REVOKE1: u32 = 1 << 22;
const BIT_SECURE_BOOT_KEY_REVOKE2: u32 = 1 << 23;

// In DATA2.
const BIT_SECURE_BOOT_EN: u32 = 1 << 20;
const BIT_SECURE_BOOT_AGGRESSIVE_REVOKE: u32 = 1 << 21;
const BIT_DIS_USB_JTAG: u32 = 1 << 22;
const BIT_DIS_USB_SERIAL_JTAG: u32 = 1 << 23;

/// `KEY_PURPOSE_n` values that name a Secure Boot digest slot, TRM Table
/// 5-2. Slot `k` is claimed by purpose value `PURPOSE_DIGEST_BASE + k`.
const PURPOSE_DIGEST_BASE: u8 = 9;

/// Bit in `EFUSE_WR_DIS` guarding `KEY_PURPOSE_0`, Table 5-1. Purposes 1
/// through 5 follow at 9 through 13.
const WR_DIS_KEY_PURPOSE_0: u32 = 8;

/// The provisioning state, as read.
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
    /// Revocation bit per digest slot, index 0 to 2. True means revoked.
    pub key_revoke: [bool; 3],
    /// `KEY_PURPOSE_0` through `KEY_PURPOSE_5`, raw 4-bit values.
    pub key_purpose: [u8; 6],
    /// Programming still permitted for `KEY_PURPOSE_n`, index 0 to 5. True
    /// means the field can still be changed.
    pub key_purpose_writable: [bool; 6],
}

impl SecureBootState {
    /// Is digest slot `k` claimed by one of the six key blocks?
    pub fn slot_occupied(&self, k: usize) -> bool {
        let want = PURPOSE_DIGEST_BASE + k as u8;
        let mut i = 0;
        while i < 6 {
            if self.key_purpose[i] == want {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Can any key block still be pointed at a digest slot?
    ///
    /// If every purpose field is locked, an attacker with eFuse write
    /// access can burn a key block but cannot declare it a digest, so an
    /// empty unrevoked slot is unreachable.
    pub fn any_purpose_writable(&self) -> bool {
        let mut i = 0;
        while i < 6 {
            if self.key_purpose_writable[i] {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Is any digest slot open to takeover?
    ///
    /// Unrevoked, empty, and a purpose field still writable. All three, or
    /// the slot is not a door. See the module header for why this is
    /// derived rather than a fixed revoke pattern.
    pub fn digest_slot_open(&self) -> bool {
        if !self.any_purpose_writable() {
            return false;
        }
        let mut k = 0;
        while k < 3 {
            if !self.key_revoke[k] && !self.slot_occupied(k) {
                return true;
            }
            k += 1;
        }
        false
    }

    /// Does this match an end state `docs/EFUSE_RUNBOOK.md` produces?
    ///
    /// Both the single-key and two-key configurations pass. Note
    /// `dis_usb_serial_jtag` must be **false**: download mode is kept on
    /// purpose, so burning it is a provisioning mistake in the other
    /// direction and is reported as a mismatch too.
    pub fn matches_runbook(&self) -> bool {
        self.secure_boot_en
            && !self.aggressive_revoke
            && self.dis_pad_jtag
            && self.dis_usb_jtag
            && !self.dis_usb_serial_jtag
            && !self.digest_slot_open()
    }

    /// One short line for the verification screen.
    ///
    /// Fits the 320 px layout at body size; the longest arm is 24
    /// characters, which was already the width before the slot arm was
    /// added.
    ///
    /// The provisioned case is deliberately terse; every other case names
    /// what is wrong, because the whole point is that an unprovisioned
    /// device should not look like a provisioned one.
    ///
    /// Order is by how open the device is left, not by register layout: no
    /// Secure Boot, then a live debug port, then a slot an attacker can
    /// claim, and last the two cases where something was burned that
    /// should not have been.
    ///
    /// The final arm stays exhaustive by construction. Reaching it means
    /// every other term already holds, so the only thing left that can
    /// differ from the runbook is `aggressive_revoke`. Adding a field to
    /// this struct without adding an arm above would silently mislabel it.
    pub fn screen_line(&self) -> &'static str {
        if self.matches_runbook() {
            "eFuse: SB on, JTAG off"
        } else if !self.secure_boot_en {
            "eFuse: SECURE BOOT OFF"
        } else if !self.dis_pad_jtag || !self.dis_usb_jtag {
            // Either path open means not hardened, and the message does not
            // distinguish them: the remedy is the same burn step either way.
            "eFuse: JTAG STILL OPEN"
        } else if self.digest_slot_open() {
            // A slot that is unrevoked, empty and still assignable. Someone
            // with eFuse write access burns their own digest into a free key
            // block, points that slot at it, and the ROM honours their
            // signature. Runbook Step 4 is what closes this.
            "eFuse: DIGEST SLOT OPEN"
        } else if self.dis_usb_serial_jtag {
            "eFuse: USB SERIAL BURNED"
        } else {
            "eFuse: AGGRESSIVE REVOKE"
        }
    }
}

/// Read the provisioning state.
///
/// Four volatile loads from read-only registers. No side effects, safe to
/// call at any point after boot.
pub fn read_secure_boot_state() -> SecureBootState {
    // SAFETY: all four are read-only 32-bit registers in the eFuse
    // controller's memory-mapped range, present on every ESP32-S3. Reading
    // them cannot fault and has no side effects. Same access pattern as
    // `hw/lockdown.rs`.
    let wr = unsafe { core::ptr::read_volatile(EFUSE_RD_WR_DIS_REG as *const u32) };
    let d0 = unsafe { core::ptr::read_volatile(EFUSE_RD_REPEAT_DATA0_REG as *const u32) };
    let d1 = unsafe { core::ptr::read_volatile(EFUSE_RD_REPEAT_DATA1_REG as *const u32) };
    let v = unsafe { core::ptr::read_volatile(EFUSE_RD_REPEAT_DATA2_REG as *const u32) };

    // Purposes 0 and 1 sit in the high nibbles of DATA1; 2 through 5 in the
    // low four nibbles of DATA2.
    let key_purpose = [
        ((d1 >> 24) & 0xF) as u8,
        ((d1 >> 28) & 0xF) as u8,
        (v & 0xF) as u8,
        ((v >> 4) & 0xF) as u8,
        ((v >> 8) & 0xF) as u8,
        ((v >> 12) & 0xF) as u8,
    ];

    // WR_DIS bit set means programming is disabled, so writable is the
    // complement.
    let mut key_purpose_writable = [false; 6];
    let mut i = 0;
    while i < 6 {
        key_purpose_writable[i] = wr & (1 << (WR_DIS_KEY_PURPOSE_0 + i as u32)) == 0;
        i += 1;
    }

    SecureBootState {
        secure_boot_en: v & BIT_SECURE_BOOT_EN != 0,
        dis_pad_jtag: d0 & BIT_DIS_PAD_JTAG != 0,
        aggressive_revoke: v & BIT_SECURE_BOOT_AGGRESSIVE_REVOKE != 0,
        dis_usb_jtag: v & BIT_DIS_USB_JTAG != 0,
        dis_usb_serial_jtag: v & BIT_DIS_USB_SERIAL_JTAG != 0,
        key_revoke: [
            d1 & BIT_SECURE_BOOT_KEY_REVOKE0 != 0,
            d1 & BIT_SECURE_BOOT_KEY_REVOKE1 != 0,
            d1 & BIT_SECURE_BOOT_KEY_REVOKE2 != 0,
        ],
        key_purpose,
        key_purpose_writable,
    }
}
