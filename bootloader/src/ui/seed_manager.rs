// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// ui/seed_manager.rs — Seed slot management and passphrase input
// 100% Rust, no-std, no-alloc
//
// RAM-only seed storage with 4 slots. All data wiped on power-off.
//
// Each slot stores:
//   - BIP39 word indices (12 or 24 words)
//   - BIP39 passphrase (up to 64 chars)
//   - SHA256 fingerprint of entropy (4 bytes, instant to compute)
//
// SeedQR format (SeedSigner-compatible):
//   Standard: 4-digit zero-padded decimal per word index, concatenated
//     12 words → "000100021500..." (48 digits)
//     24 words → 96 digits
//   CompactSeedQR: raw entropy bytes (16 or 32 bytes)
//
// Fingerprint: SHA256(entropy)[0..4] displayed as hex (e.g. "a3f8e2b1")


use sha2::{Sha256, Digest};

/// Maximum seed slots in RAM
pub const MAX_SLOTS: usize = 16;

/// A single seed slot
pub struct SeedSlot {
    /// BIP39 word indices (0-2047)
    pub indices: [u16; 24],
    /// Number of words: 12 or 24 (0 = empty slot)
    pub word_count: u8,
    /// BIP39 passphrase (UTF-8, up to 64 bytes)
    pub passphrase: [u8; 64],
    pub passphrase_len: u8,
    /// SHA256(entropy)[0..4] — instant visual identifier
    pub fingerprint: [u8; 4],
}

impl SeedSlot {
        /// Create an empty seed slot.
pub const fn empty() -> Self {
        Self {
            indices: [0; 24],
            word_count: 0,
            passphrase: [0; 64],
            passphrase_len: 0,
            fingerprint: [0; 4],
        }
    }

        /// Returns true if this slot contains no seed.
pub fn is_empty(&self) -> bool {
        self.word_count == 0
    }

    /// Returns true if this slot holds a raw private key (not a mnemonic).
    /// Raw keys are stored with word_count = 1 and the 32-byte key in indices[0..16].
    pub fn is_raw_key(&self) -> bool {
        self.word_count == 1
    }

    /// Get the raw private key bytes (only valid if is_raw_key() is true).
    /// The 32 bytes are packed into indices[0..16] as little-endian u16 pairs.
    pub fn raw_key_bytes(&self, out: &mut [u8; 32]) {
        for i in 0..16 {
            let le = self.indices[i].to_le_bytes();
            out[i * 2] = le[0];
            out[i * 2 + 1] = le[1];
        }
    }

    /// Compute fingerprint from word indices.
    /// Reconstructs entropy from indices, then SHA256(entropy)[0..4].
    pub fn compute_fingerprint(&mut self) {
        let mut entropy = [0u8; 33]; // max 264 bits for 24 words
        let wc = self.word_count as usize;

        // Pack word indices into bits (11 bits each)
        let mut bit_pos: usize = 0;
        for i in 0..wc {
            let idx = self.indices[i];
            for bit in (0..11).rev() {
                let byte_idx = bit_pos / 8;
                let bit_idx = 7 - (bit_pos % 8);
                if (idx >> bit) & 1 == 1 {
                    entropy[byte_idx] |= 1 << bit_idx;
                }
                bit_pos += 1;
            }
        }

        // Entropy is the first 128 bits (16 bytes) for 12-word
        // or first 256 bits (32 bytes) for 24-word
        let entropy_len = if wc == 12 { 16 } else { 32 };

        // Hash entropy + passphrase together so that same mnemonic
        // with different passphrases produces different fingerprints
        let mut hasher = Sha256::new();
        hasher.update(&entropy[..entropy_len]);
        let pp_len = self.passphrase_len as usize;
        if pp_len > 0 {
            hasher.update(&self.passphrase[..pp_len]);
        }
        let hash = hasher.finalize();
        self.fingerprint.copy_from_slice(&hash[..4]);

        // Zeroize temp
        for b in entropy.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0); }
        }
    }

    /// Get passphrase as &str
    pub fn passphrase_str(&self) -> &str {
        core::str::from_utf8(&self.passphrase[..self.passphrase_len as usize]).unwrap_or("")
    }

    /// Format fingerprint as hex string (8 chars)
    pub fn fingerprint_hex(&self, buf: &mut [u8; 8]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for i in 0..4 {
            buf[i * 2] = HEX[(self.fingerprint[i] >> 4) as usize];
            buf[i * 2 + 1] = HEX[(self.fingerprint[i] & 0x0F) as usize];
        }
    }

    /// Secure zeroize
    pub fn zeroize(&mut self) {
        for idx in self.indices.iter_mut() {
            unsafe { core::ptr::write_volatile(idx, 0); }
        }
        for b in self.passphrase.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0); }
        }
        unsafe {
            core::ptr::write_volatile(&mut self.word_count, 0);
            core::ptr::write_volatile(&mut self.passphrase_len, 0);
        }
        self.fingerprint = [0; 4];
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Seed manager — holds up to MAX_SLOTS seeds in RAM (wiped on power off)
pub struct SeedManager {
    pub slots: [SeedSlot; MAX_SLOTS],
    /// Currently active slot index (0xFF = none)
    pub active: u8,
}

impl SeedManager {
        /// Create a new SeedManager with all slots empty.
pub const fn new() -> Self {
        Self {
            slots: [SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty(),
                    SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty(),
                    SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty(),
                    SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty(), SeedSlot::empty()],
            active: 0xFF,
        }
    }

    /// Find first free slot. Returns None if all full.
    pub fn find_free(&self) -> Option<usize> {
        for i in 0..MAX_SLOTS {
            if self.slots[i].is_empty() {
                return Some(i);
            }
        }
        None
    }

    /// Number of populated slots
    pub fn count(&self) -> usize {
        self.slots.iter().filter(|s| !s.is_empty()).count()
    }

    /// Store a seed into the next free slot.
    /// Returns slot index, or None if full.
    /// Find existing slot with matching fingerprint. Returns slot index if found.
    pub fn find_by_fingerprint(&self, fp: &[u8; 4]) -> Option<usize> {
        for i in 0..MAX_SLOTS {
            if !self.slots[i].is_empty() && self.slots[i].fingerprint == *fp {
                return Some(i);
            }
        }
        None
    }

        /// Store a mnemonic in the given slot index.
pub fn store(
        &mut self,
        indices: &[u16; 24],
        word_count: u8,
        passphrase: &[u8],
        passphrase_len: u8,
    ) -> Option<usize> {
        // Compute fingerprint INCLUDING passphrase to distinguish
        // same mnemonic with different passphrases
        let mut tmp = SeedSlot::empty();
        tmp.indices = *indices;
        tmp.word_count = word_count;
        let pp_len = (passphrase_len as usize).min(64);
        tmp.passphrase[..pp_len].copy_from_slice(&passphrase[..pp_len]);
        tmp.passphrase_len = pp_len as u8;
        tmp.compute_fingerprint();

        // If same fingerprint already exists, return that slot (no duplicate)
        if let Some(existing) = self.find_by_fingerprint(&tmp.fingerprint) {
            return Some(existing);
        }

        let slot_idx = self.find_free()?;
        let slot = &mut self.slots[slot_idx];
        slot.indices = *indices;
        slot.word_count = word_count;
        slot.passphrase[..pp_len].copy_from_slice(&passphrase[..pp_len]);
        slot.passphrase_len = pp_len as u8;
        slot.fingerprint = tmp.fingerprint;
        Some(slot_idx)
    }

    /// Store a raw 32-byte private key. Sets word_count=1 as marker.
    /// The key bytes are packed into indices[0..16] as u16 pairs.
    pub fn store_raw_key(&mut self, key: &[u8; 32]) -> Option<usize> {
        // Compute fingerprint to check for duplicates
        use sha2::{Sha256, Digest};
        let hash = Sha256::digest(key);
        let fp = [hash[0], hash[1], hash[2], hash[3]];

        if let Some(existing) = self.find_by_fingerprint(&fp) {
            return Some(existing);
        }

        let slot_idx = self.find_free()?;
        let slot = &mut self.slots[slot_idx];
        slot.word_count = 1;
        for i in 0..16 {
            slot.indices[i] = u16::from_le_bytes([key[i * 2], key[i * 2 + 1]]);
        }
        for i in 16..24 { slot.indices[i] = 0; }
        slot.passphrase_len = 0;
        slot.fingerprint = fp;
        Some(slot_idx)
    }

    /// Activate a slot (set as current for signing)
    pub fn activate(&mut self, slot_idx: usize) -> bool {
        if slot_idx < MAX_SLOTS && !self.slots[slot_idx].is_empty() {
            self.active = slot_idx as u8;
            true
        } else {
            false
        }
    }

    /// Get the currently active slot, if any
    pub fn active_slot(&self) -> Option<&SeedSlot> {
        if self.active < MAX_SLOTS as u8 {
            let slot = &self.slots[self.active as usize];
            if !slot.is_empty() {
                return Some(slot);
            }
        }
        None
    }

    /// Get the currently active slot mutably
    pub fn active_slot_mut(&mut self) -> Option<&mut SeedSlot> {
        if self.active < MAX_SLOTS as u8 {
            let slot = &mut self.slots[self.active as usize];
            if !slot.is_empty() {
                return Some(slot);
            }
        }
        None
    }

    /// Delete a specific slot
    pub fn delete(&mut self, slot_idx: usize) {
        if slot_idx < MAX_SLOTS {
            self.slots[slot_idx].zeroize();
            if self.active == slot_idx as u8 {
                self.active = 0xFF;
            }
        }
    }

    /// Zeroize everything
    pub fn zeroize_all(&mut self) {
        for slot in self.slots.iter_mut() {
            slot.zeroize();
        }
        self.active = 0xFF;
    }
}

impl Drop for SeedManager {
    fn drop(&mut self) {
        self.zeroize_all();
    }
}

// ═══════════════════════════════════════════════════════════════════
// SeedQR Format — SeedSigner compatible
// ═══════════════════════════════════════════════════════════════════

/// Encode word indices as SeedQR numeric string.
/// Each index → 4-digit zero-padded decimal.
/// Returns the number of bytes written to `buf`.
/// 12 words → 48 chars, 24 words → 96 chars.
pub fn encode_seedqr(indices: &[u16], word_count: u8, buf: &mut [u8; 96]) -> usize {
    let wc = word_count as usize;
    let out_len = wc * 4;
    for i in 0..wc {
        let idx = indices[i];
        // 4-digit zero-padded: e.g. 3 → "0003", 2047 → "2047"
        buf[i * 4]     = b'0' + ((idx / 1000) % 10) as u8;
        buf[i * 4 + 1] = b'0' + ((idx / 100) % 10) as u8;
        buf[i * 4 + 2] = b'0' + ((idx / 10) % 10) as u8;
        buf[i * 4 + 3] = b'0' + (idx % 10) as u8;
    }
    out_len
}

/// Decode SeedQR numeric string back to word indices.
/// Returns word count (12 or 24), or 0 on error.
pub fn decode_seedqr(data: &[u8], indices: &mut [u16; 24]) -> u8 {
    // Must be exactly 48 or 96 ASCII digits
    let wc = match data.len() {
        48 => 12u8,
        96 => 24u8,
        _ => return 0,
    };

    // Verify all are ASCII digits
    if !data.iter().all(|&b| b.is_ascii_digit()) {
        return 0;
    }

    for i in 0..(wc as usize) {
        let d0 = (data[i * 4] - b'0') as u16;
        let d1 = (data[i * 4 + 1] - b'0') as u16;
        let d2 = (data[i * 4 + 2] - b'0') as u16;
        let d3 = (data[i * 4 + 3] - b'0') as u16;
        let idx = d0 * 1000 + d1 * 100 + d2 * 10 + d3;
        if idx >= 2048 {
            return 0;
        }
        indices[i] = idx;
    }

    wc
}

/// Encode CompactSeedQR: raw entropy bytes.
/// 12 words → 16 bytes, 24 words → 32 bytes.
/// Returns the number of bytes written.
pub fn encode_compact_seedqr(indices: &[u16], word_count: u8, buf: &mut [u8; 32]) -> usize {
    let wc = word_count as usize;
    // Pack 11-bit indices into raw bits
    let mut bits = [0u8; 33];
    let mut bit_pos: usize = 0;
    for i in 0..wc {
        let idx = indices[i];
        for bit in (0..11).rev() {
            let byte_idx = bit_pos / 8;
            let bit_idx = 7 - (bit_pos % 8);
            if (idx >> bit) & 1 == 1 {
                bits[byte_idx] |= 1 << bit_idx;
            }
            bit_pos += 1;
        }
    }
    // Output is just the entropy portion (no checksum bits)
    let out_len = if wc == 12 { 16 } else { 32 };
    buf[..out_len].copy_from_slice(&bits[..out_len]);
    out_len
}

/// Decode CompactSeedQR: raw entropy bytes → word indices.
/// Input: 16 bytes (12-word) or 32 bytes (24-word).
/// Reconstructs indices including checksum word.
/// Returns word count (12 or 24), or 0 on error.
pub fn decode_compact_seedqr(data: &[u8], indices: &mut [u16; 24]) -> u8 {
    let (wc, entropy_len) = match data.len() {
        16 => (12u8, 16usize),
        32 => (24u8, 32usize),
        _ => return 0,
    };

    // Rebuild mnemonic from entropy using BIP39 logic
    let checksum_byte = {
        let hash = Sha256::digest(&data[..entropy_len]);
        hash[0]
    };

    // Concatenate entropy + checksum bits
    let mut combined = [0u8; 34]; // max 264 bits
    combined[..entropy_len].copy_from_slice(&data[..entropy_len]);
    if wc == 12 {
        combined[16] = checksum_byte & 0xF0; // only top 4 bits
    } else {
        combined[32] = checksum_byte; // full byte
    }

    // Extract 11-bit indices
    let total_bits = if wc == 12 { 132 } else { 264 };
    for i in 0..(wc as usize) {
        let bit_start = i * 11;
        let mut val: u16 = 0;
        for b in 0..11 {
            let pos = bit_start + b;
            if pos < total_bits {
                let byte_idx = pos / 8;
                let bit_idx = 7 - (pos % 8);
                if (combined[byte_idx] >> bit_idx) & 1 == 1 {
                    val |= 1 << (10 - b);
                }
            }
        }
        if val >= 2048 {
            return 0;
        }
        indices[i] = val;
    }

    wc
}

// ═══════════════════════════════════════════════════════════════════
// Passphrase Input Helper
// ═══════════════════════════════════════════════════════════════════

/// Passphrase input state for BIP39 passphrase entry.
/// Supports a-z, A-Z, 0-9, space, and basic symbols.
pub struct PassphraseInput {
    pub buf: [u8; 128],
    pub len: usize,
    /// Cursor position (0 = before first char, len = after last char)
    pub cursor: usize,
    /// Keyboard page: 0=lowercase, 1=uppercase, 2=digits+symbols
    pub page: u8,
}

impl PassphraseInput {
        /// Create a new empty passphrase input.
pub fn new() -> Self {
        Self {
            buf: [0; 128],
            len: 0,
            cursor: 0,
            page: 0,
        }
    }

        /// Insert a character at cursor position.
pub fn push_char(&mut self, c: u8) {
        if self.len < 128 {
            // Shift everything after cursor right by 1
            let mut i = self.len;
            while i > self.cursor {
                self.buf[i] = self.buf[i - 1];
                i -= 1;
            }
            self.buf[self.cursor] = c;
            self.len += 1;
            self.cursor += 1;
        }
    }

        /// Delete character before cursor (backspace).
pub fn backspace(&mut self) {
        if self.cursor > 0 {
            // Shift everything after cursor left by 1
            let mut i = self.cursor - 1;
            while i + 1 < self.len {
                self.buf[i] = self.buf[i + 1];
                i += 1;
            }
            self.len -= 1;
            self.buf[self.len] = 0;
            self.cursor -= 1;
        }
    }

        /// Move cursor left.
pub fn cursor_left(&mut self) {
        if self.cursor > 0 {
            self.cursor -= 1;
        }
    }

        /// Move cursor right.
pub fn cursor_right(&mut self) {
        if self.cursor < self.len {
            self.cursor += 1;
        }
    }

        /// Clear the passphrase buffer completely.
pub fn reset(&mut self) {
        for b in self.buf.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0); }
        }
        self.len = 0;
        self.cursor = 0;
        self.page = 0;
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }

        /// Cycle to the next keyboard page (lowercase → uppercase → symbols).
pub fn next_page(&mut self) {
        self.page = (self.page + 1) % 4;
    }

        /// Get the current passphrase as a UTF-8 string slice.
pub fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }

    /// Get keyboard rows for current page
    pub fn rows(&self) -> [&'static [u8]; 3] {
        match self.page {
            0 => [b"abcdefghij", b"klmnopqrst", b"uvwxyz "],
            1 => [b"ABCDEFGHIJ", b"KLMNOPQRST", b"UVWXYZ "],
            _ => [b"0123456789", b"!@#$%^&*()", b"-_=+.,?/ "],
        }
    }

        /// Get the label for the current keyboard page.
pub fn page_label(&self) -> &'static str {
        match self.page {
            0 => "a-z",
            1 => "A-Z",
            _ => "0-9",
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: 12-word SeedQR encode/decode round-trip.
pub fn test_seedqr_roundtrip_12() -> bool {
    // "abandon" x 11 + "about" → indices [0,0,0,0,0,0,0,0,0,0,0,3]
    let indices: [u16; 24] = [0,0,0,0,0,0,0,0,0,0,0,3, 0,0,0,0,0,0,0,0,0,0,0,0];
    let mut buf = [0u8; 96];
    let len = encode_seedqr(&indices, 12, &mut buf);
    if len != 48 { return false; }
    // Should be "000000000000000000000000000000000000000000000003"
    if &buf[44..48] != b"0003" { return false; }
    if &buf[0..4] != b"0000" { return false; }

    // Decode back
    let mut decoded = [0u16; 24];
    let wc = decode_seedqr(&buf[..len], &mut decoded);
    if wc != 12 { return false; }
    for i in 0..11 {
        if decoded[i] != 0 { return false; }
    }
    decoded[11] == 3
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: 24-word SeedQR encode/decode round-trip.
pub fn test_seedqr_roundtrip_24() -> bool {
    let mut indices = [0u16; 24];
    indices[0] = 2047; // "zoo"
    indices[23] = 104; // "art"
    let mut buf = [0u8; 96];
    let len = encode_seedqr(&indices, 24, &mut buf);
    if len != 96 { return false; }
    if &buf[0..4] != b"2047" { return false; }
    if &buf[92..96] != b"0104" { return false; }

    let mut decoded = [0u16; 24];
    let wc = decode_seedqr(&buf[..len], &mut decoded);
    if wc != 24 { return false; }
    decoded[0] == 2047 && decoded[23] == 104
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: CompactSeedQR encoding for 12 words.
pub fn test_compact_seedqr_12() -> bool {
    // All-zero entropy → "abandon" x 11 + "about"
    let entropy = [0u8; 16];
    let mut indices = [0u16; 24];
    let wc = decode_compact_seedqr(&entropy, &mut indices);
    if wc != 12 { return false; }
    for i in 0..11 {
        if indices[i] != 0 { return false; }
    }
    // Last word should be "about" = index 3
    indices[11] == 3
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: seed fingerprint computation.
pub fn test_fingerprint() -> bool {
    let mut slot = SeedSlot::empty();
    slot.word_count = 12;
    // All zeros → "abandon" x 11 + "about"
    slot.indices = [0,0,0,0,0,0,0,0,0,0,0,3, 0,0,0,0,0,0,0,0,0,0,0,0];
    slot.compute_fingerprint();
    // SHA256 of 16 zero bytes: known hash
    // Just check fingerprint is not all zeros (entropy is all zeros but hash isn't)
    // Actually SHA256(0x00 * 16) = 374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb
    slot.fingerprint[0] == 0x37 && slot.fingerprint[1] == 0x47
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: seed manager store/delete operations.
pub fn test_seed_manager_store_delete() -> bool {
    let mut mgr = SeedManager::new();
    let indices = [0u16; 24];
    let slot = mgr.store(&indices, 12, b"", 0);
    if slot != Some(0) { return false; }
    if mgr.count() != 1 { return false; }

    mgr.activate(0);
    if mgr.active != 0 { return false; }

    mgr.delete(0);
    if mgr.count() != 0 { return false; }
    if mgr.active != 0xFF { return false; }
    true
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Run all seed manager tests.
pub fn run_seed_manager_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 5u32;

    if test_seedqr_roundtrip_12() { passed += 1; }
    if test_seedqr_roundtrip_24() { passed += 1; }
    if test_compact_seedqr_12() { passed += 1; }
    if test_fingerprint() { passed += 1; }
    if test_seed_manager_store_delete() { passed += 1; }

    (passed, total)
}
