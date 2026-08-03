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
//   - Display fingerprint (4 bytes), set lazily once the slot's key exists
//
// SeedQR format (SeedSigner-compatible):
//   Standard: 4-digit zero-padded decimal per word index, concatenated
//     12 words → "000100021500..." (48 digits)
//     24 words → 96 digits
//   CompactSeedQR: raw entropy bytes (16 or 32 bytes)
//
// Fingerprint: SHA256(the slot's controlling private key)[0..4], displayed as
// hex (e.g. "a3f8e2b1"). One rule for all three slot kinds:
//
//   word_count 12/24 : the account key at m/44'/111111'/0'
//   word_count 2     : the imported xprv's account key (handlers/sd.rs)
//   word_count 1     : the raw private key itself (store_raw_key)
//
// It is NOT computed from entropy and passphrase directly. That construction
// was a passphrase-testing oracle: an attacker holding the mnemonic could test
// each passphrase guess against the displayed value at the cost of one SHA-256,
// skipping the 2048-round PBKDF2 stretch that BIP39 derivation imposes and that
// the threat model assumes an attacker has to pay. Deriving the fingerprint
// from the account key puts every guess back behind the full stretch plus three
// hardened BIP32 derivations.
//
// Because the account key only exists after that stretch, the fingerprint is
// filled in lazily by app::signing::refresh_active_fingerprint, called from the
// two places that produce a valid account key. A slot that has been stored but
// whose key has not been derived yet renders as "--------".


use sha2::{Sha256, Digest};

/// Maximum seed slots in RAM
pub const MAX_SLOTS: usize = 16;

/// A single seed slot
pub struct SeedSlot {
    /// Storage for the kind-dependent payload. PRIVATE, and that is the point
    /// of H-08: for a mnemonic slot these are BIP39 word indices, for a raw-key
    /// or xprv slot they are a little-endian packed 32-byte PRIVATE KEY. No
    /// code outside this module can now read one as the other.
    ///
    /// Access through `as_mnemonic`, `as_raw_key`, `as_xprv`, `as_passphrase`,
    /// which check `kind()` first, or write through `set_raw_key` / `set_xprv`,
    /// which set the kind and the payload together.
    indices: [u16; 24],
    /// Slot kind discriminant: 0 empty, 1 raw key, 2 xprv, 12 or 24 mnemonic.
    /// Still public because callers legitimately need the word count for
    /// display and iteration. Use `kind()` when asking what the slot IS.
    pub word_count: u8,
    /// Mnemonic slots: the BIP39 passphrase. Xprv slots: 32 bytes of chain code
    /// followed by one depth byte. Private, for the same reason as `indices`.
    passphrase: [u8; 64],
    passphrase_len: u8,
    /// SHA256(controlling private key)[0..4] — visual identifier.
    /// All zeros means "not derived yet", not a real fingerprint value.
    pub fingerprint: [u8; 4],
}

/// What a `SeedSlot` actually holds (H-08).
///
/// `word_count` is the discriminant of an untyped union: 0 empty, 1 raw key,
/// 2 xprv, 12 or 24 mnemonic. The other fields mean different things per kind,
/// and the names are true for one kind and misleading for the rest:
///
/// | field | mnemonic | raw key | xprv |
/// |---|---|---|---|
/// | `indices` | BIP39 word indices | private key, LE-packed | private key, LE-packed |
/// | `passphrase` | BIP39 passphrase | unused | chain code (0..32), depth (32) |
///
/// Nothing enforces the pairing, so any code touching `slot.indices` without
/// first checking `word_count` compiles and reads whatever the last kind left
/// there. That is not theoretical: it produced H-10 (a fingerprint lookup that
/// returned a mnemonic slot to the xprv import path, which then activated it
/// and set `word_count = 2`), it is the same shape as H-07, and the comment at
/// `handlers/seed.rs:656` records an earlier panic caused by reading packed key
/// bytes as word indices.
///
/// This enum plus the accessors below are step one of removing the class: the
/// storage is unchanged for now, so nothing breaks, but every read can be made
/// kind-checked. Once no code outside this module touches the raw fields, the
/// fields become private and the storage becomes the enum itself, at which
/// point a mismatch stops compiling instead of being caught by review.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SlotKind {
    Empty,
    RawKey,
    Xprv,
    Mnemonic { word_count: u8 },
}

impl SeedSlot {
    /// What this slot holds. The only correct way to ask.
    pub fn kind(&self) -> SlotKind {
        match self.word_count {
            0 => SlotKind::Empty,
            1 => SlotKind::RawKey,
            2 => SlotKind::Xprv,
            wc => SlotKind::Mnemonic { word_count: wc },
        }
    }

    /// The 32-byte private key of a raw-key slot, or `None`.
    pub fn as_raw_key(&self) -> Option<[u8; 32]> {
        if self.kind() != SlotKind::RawKey {
            return None;
        }
        Some(self.unpack_key())
    }

    /// `(private key, chain code, depth)` of an xprv slot, or `None`.
    pub fn as_xprv(&self) -> Option<([u8; 32], [u8; 32], u8)> {
        if self.kind() != SlotKind::Xprv {
            return None;
        }
        let mut cc = [0u8; 32];
        cc.copy_from_slice(&self.passphrase[..32]);
        Some((self.unpack_key(), cc, self.passphrase[32]))
    }

    /// `(word indices, word count)` of a mnemonic slot, or `None`.
    pub fn as_mnemonic(&self) -> Option<(&[u16; 24], u8)> {
        match self.kind() {
            SlotKind::Mnemonic { word_count } => Some((&self.indices, word_count)),
            _ => None,
        }
    }

    /// The BIP39 passphrase of a mnemonic slot, or `None`.
    ///
    /// Returns `None` for an xprv slot, where those same bytes are the chain
    /// code and reading them as a passphrase is the bug this exists to prevent.
    pub fn as_passphrase(&self) -> Option<&[u8]> {
        match self.kind() {
            SlotKind::Mnemonic { .. } => {
                Some(&self.passphrase[..self.passphrase_len as usize])
            }
            _ => None,
        }
    }

    /// Fill this slot as an xprv slot from an account key.
    ///
    /// The counterpart to `as_xprv`. Both construction sites previously packed
    /// the encoding by hand, including `passphrase_len = 33`, which is not a
    /// length: it is 32 chain-code bytes plus one depth byte occupying a field
    /// named for a passphrase. Two hand-written copies of that layout is how a
    /// third one ends up subtly different.
    ///
    /// Sets `word_count = 2`, so the kind and the contents are written together.
    pub fn set_xprv(&mut self, key: &[u8; 32], chain_code: &[u8; 32], depth: u8) {
        self.indices = [0u16; 24];
        for i in 0..16 {
            self.indices[i] = u16::from_le_bytes([key[i * 2], key[i * 2 + 1]]);
        }
        self.passphrase = [0u8; 64];
        self.passphrase[..32].copy_from_slice(chain_code);
        self.passphrase[32] = depth;
        self.passphrase_len = 33;
        self.word_count = 2;
    }

    /// Fill this slot as a raw-key slot. Sets `word_count = 1`.
    pub fn set_raw_key(&mut self, key: &[u8; 32]) {
        self.indices = [0u16; 24];
        for i in 0..16 {
            self.indices[i] = u16::from_le_bytes([key[i * 2], key[i * 2 + 1]]);
        }
        self.passphrase = [0u8; 64];
        self.passphrase_len = 0;
        self.word_count = 1;
    }

    /// Unpack the LE-packed 32-byte key that raw-key and xprv slots store in
    /// `indices`. Private: callers go through `as_raw_key` or `as_xprv`, which
    /// check the kind first.
    fn unpack_key(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..16 {
            let le = self.indices[i].to_le_bytes();
            out[i * 2] = le[0];
            out[i * 2 + 1] = le[1];
        }
        out
    }
}

impl SeedSlot {
        /// Create an empty seed slot.
pub fn empty() -> Self {
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

    /// True once this slot's fingerprint has been derived.
    ///
    /// All-zero is the "not derived yet" marker. A real fingerprint can be
    /// all-zero with probability 2^-32, in which case the slot renders as
    /// "--------" and the value is recomputed on the next key derivation.
    /// Cosmetic only, no security or correctness consequence.
    pub fn has_fingerprint(&self) -> bool {
        !crate::crypto::constant_time::is_zero(&self.fingerprint)
    }

    /// Set the display fingerprint from the slot's controlling private key.
    ///
    /// `key` is the account key at m/44'/111111'/0' for mnemonic and xprv
    /// slots, or the raw key itself for raw-key slots. The caller owns the
    /// key material and is responsible for zeroizing it; this function keeps
    /// no copy beyond the four bytes it stores.
    ///
    /// Deliberately NOT derived from the mnemonic entropy and passphrase.
    /// See the construction note in this file's header.
    /// `key` is a slice, not `&[u8; 32]`, so callers can hash straight out of
    /// a larger buffer such as `AppData::acct_key_raw` without first copying
    /// 32 bytes onto the stack. That copy sat on the seed-load path, which has
    /// no headroom on M5Stack.
    pub fn set_fingerprint_from_key(&mut self, key: &[u8]) {
        let hash = Sha256::digest(key);
        self.fingerprint.copy_from_slice(&hash[..4]);
    }

    /// True if this slot already holds exactly this mnemonic and passphrase.
    ///
    /// Replaces the old 4-byte fingerprint comparison used for duplicate
    /// detection (L-04): two different seeds collide on 4 bytes once in 2^32,
    /// and the collision silently discarded the new seed and activated the
    /// other one. Compares the full material in constant time.
    pub fn matches_mnemonic(
        &self,
        indices: &[u16; 24],
        word_count: u8,
        passphrase: &[u8],
    ) -> bool {
        if self.word_count != word_count {
            return false;
        }
        if self.passphrase_len as usize != passphrase.len() {
            return false;
        }
        // Compare the full 24-entry array regardless of word count: the tail
        // beyond word_count is zero in every stored slot, so this stays
        // correct and keeps the comparison length independent of the secret.
        let mut idx_bytes = [0u8; 48];
        let mut other_bytes = [0u8; 48];
        for i in 0..24 {
            let a = self.indices[i].to_le_bytes();
            let b = indices[i].to_le_bytes();
            idx_bytes[i * 2] = a[0];
            idx_bytes[i * 2 + 1] = a[1];
            other_bytes[i * 2] = b[0];
            other_bytes[i * 2 + 1] = b[1];
        }
        let same_words = crate::crypto::constant_time::eq(&idx_bytes, &other_bytes);
        let pp_len = self.passphrase_len as usize;
        let same_pp = crate::crypto::constant_time::eq(
            &self.passphrase[..pp_len],
            passphrase,
        );
        for b in idx_bytes.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0); }
        }
        for b in other_bytes.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0); }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        same_words && same_pp
    }

    /// Get passphrase as &str
    pub fn passphrase_str(&self) -> &str {
        core::str::from_utf8(&self.passphrase[..self.passphrase_len as usize]).unwrap_or("")
    }

    /// Format fingerprint as hex string (8 chars).
    ///
    /// Renders "--------" until the slot's key has been derived, since the
    /// fingerprint now comes from the account key rather than from the words.
    /// The dashes resolve to hex the first time the slot is used for anything
    /// that needs its key.
    pub fn fingerprint_hex(&self, buf: &mut [u8; 8]) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        if !self.has_fingerprint() {
            *buf = *b"--------";
            return;
        }
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

/// Wipe a `SeedSlot` whenever one is dropped (H-06).
///
/// The finding was a full copy of the mnemonic and passphrase left on the stack
/// by `SeedManager::store`, which built a `SeedSlot` temporary purely to compute
/// a fingerprint. That temporary is gone, but its absence was the fix for one
/// instance rather than for the hazard: `SeedSlot` had no destructor, so any
/// future stack temporary would leak the same way and nothing would say so.
///
/// With `Drop`, every `SeedSlot` clears itself wherever it lives, and the
/// compiler enforces it rather than the next author remembering.
///
/// Cost: `SeedSlot::empty` and `SeedManager::new` stop being `const fn`, since
/// a type with a destructor cannot be constructed in a const context. Nothing
/// required that.
impl Drop for SeedSlot {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SeedManager {
    /// Create a new SeedManager with all slots empty.
    ///
    /// No longer `const fn`. `SeedSlot` now implements `Drop` (H-06), and a
    /// type with a destructor cannot be built in a const context. Nothing
    /// needed it: the only caller is `AppData::new`, at runtime, and there is
    /// no `static` or `const` of this type anywhere in the tree.
    pub fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| SeedSlot::empty()),
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
    /// Find an existing slot of a given kind with this fingerprint.
    ///
    /// `word_count` is the slot kind and is REQUIRED, not optional. Every slot
    /// kind now derives its fingerprint the same way, as
    /// `SHA256(controlling private key)[0..4]`, which is deliberate: a mnemonic
    /// and the xprv exported from it describe one wallet and should show one
    /// identifier. The consequence is that a 24-word slot and its own xprv slot
    /// collide by construction rather than by chance.
    ///
    /// Without the kind filter, importing an xprv after its mnemonic has been
    /// primed returns the mnemonic slot. The caller sees a non-empty slot, skips
    /// population, activates it, and sets `word_count = 2`, leaving a 24-word
    /// slot dispatched as an xprv with a stale `acct_key_raw`. Same class as
    /// H-07: slot-type dispatch without a slot-type check.
    ///
    /// Only meaningful for kinds whose fingerprint exists at store time:
    /// raw-key (1) and xprv (2). Mnemonic slots dedup on full material via
    /// `find_matching`, because their fingerprint does not exist until the
    /// account key has been derived.
    ///
    /// Never matches an underived slot: an all-zero `fp` returns None rather
    /// than colliding with every mnemonic slot still waiting for its key.
    pub fn find_by_fingerprint(&self, fp: &[u8; 4], word_count: u8) -> Option<usize> {
        if crate::crypto::constant_time::is_zero(fp) {
            return None;
        }
        for i in 0..MAX_SLOTS {
            if !self.slots[i].is_empty()
                && self.slots[i].word_count == word_count
                && self.slots[i].has_fingerprint()
                && crate::crypto::constant_time::eq(&self.slots[i].fingerprint, fp)
            {
                return Some(i);
            }
        }
        None
    }

    /// Find a mnemonic slot already holding exactly this material.
    pub fn find_matching(
        &self,
        indices: &[u16; 24],
        word_count: u8,
        passphrase: &[u8],
    ) -> Option<usize> {
        for i in 0..MAX_SLOTS {
            if self.slots[i].is_empty() {
                continue;
            }
            if self.slots[i].matches_mnemonic(indices, word_count, passphrase) {
                return Some(i);
            }
        }
        None
    }

    /// Store a mnemonic in the first free slot.
    ///
    /// Does no key derivation. The fingerprint stays all-zero (rendered as
    /// "--------") until `app::signing::refresh_active_fingerprint` fills it
    /// from the account key. Deriving here would have run the full PBKDF2
    /// stretch a second time: every caller of this function goes on to prime
    /// the account key immediately afterwards, which performs that stretch
    /// anyway.
    ///
    /// No `SeedSlot` temporary is built. The previous version assembled a
    /// complete copy of the mnemonic and passphrase on the stack purely to
    /// compute a fingerprint, and `SeedSlot` has no `Drop`, so that copy
    /// survived all three return paths (H-06).
    pub fn store(
        &mut self,
        indices: &[u16; 24],
        word_count: u8,
        passphrase: &[u8],
        passphrase_len: u8,
    ) -> Option<usize> {
        let pp_len = (passphrase_len as usize).min(64).min(passphrase.len());

        // Duplicate detection on the full material, not on 4 truncated bytes.
        if let Some(existing) = self.find_matching(indices, word_count, &passphrase[..pp_len]) {
            return Some(existing);
        }

        let slot_idx = self.find_free()?;
        let slot = &mut self.slots[slot_idx];
        slot.indices = *indices;
        slot.word_count = word_count;
        slot.passphrase[..pp_len].copy_from_slice(&passphrase[..pp_len]);
        slot.passphrase_len = pp_len as u8;
        slot.fingerprint = [0; 4];
        Some(slot_idx)
    }

    /// Store a raw 32-byte private key. Sets word_count=1 as marker.
    /// The key bytes are packed into indices[0..16] as u16 pairs.
    pub fn store_raw_key(&mut self, key: &[u8; 32]) -> Option<usize> {
        // Raw-key slots ARE their own key, so the fingerprint exists at store
        // time and follows the same rule as every other slot kind:
        // SHA256(controlling private key)[0..4].
        let hash = Sha256::digest(key);
        let fp = [hash[0], hash[1], hash[2], hash[3]];

        if let Some(existing) = self.find_by_fingerprint(&fp, 1) {
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
    /// Maximum characters this screen will accept.
    ///
    /// This widget is shared by fifteen entry screens whose destination
    /// buffers differ (BIP39 passphrase 64, stego hint 64, stego descriptor 96,
    /// commit-reveal secret 33, message 128). Previously push_char capped at
    /// 128, the widget's own buffer size, and every consumer silently trimmed
    /// afterwards. A 65-to-128 byte BIP39 passphrase was cut to 64 at
    /// SeedManager::store with no warning, producing a wallet that cannot be
    /// restored anywhere else (H-09).
    ///
    /// Set once per frame from AppState::keyboard_max_len(). Blocking the
    /// keystroke matches WordInput::push_char (prefix_len < 8) and the hex
    /// import handler (hex_input_len < 64), which is the convention already
    /// used elsewhere in this codebase.
    pub max_len: usize,
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
            max_len: 128,
            cursor: 0,
            page: 0,
        }
    }

        /// Insert a character at cursor position.
pub fn push_char(&mut self, c: u8) {
        if self.len < self.max_len.min(128) {
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
        // Back to the buffer size. The per-screen cap is reapplied every frame
        // from AppState::keyboard_max_len(); leaving a lower cap here would
        // carry it into whichever screen is entered next.
        self.max_len = 128;
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
/// Test: fingerprint derivation from the account key (known-answer).
///
/// Vector: BIP39 "abandon" x11 + "about", empty passphrase. Its account key at
/// m/44'/111111'/0' is the constant below, checked against an independent
/// PBKDF2 + BIP32 implementation. Expected fingerprint 2f27cc04.
///
/// The account key is hardcoded on purpose. Deriving it here would run the
/// full PBKDF2 stretch inside a boot test, adding seconds to every verbose
/// boot to re-verify something the BIP39 and BIP32 KATs already cover. This
/// test isolates the one step those do not: key bytes to display fingerprint.
pub fn test_fingerprint() -> bool {
    const ACCT_KEY_ABANDON: [u8; 32] = [
        0xe9, 0x68, 0x2a, 0xa6, 0x31, 0xff, 0x9c, 0x50,
        0x1a, 0x3c, 0x54, 0xd7, 0xd0, 0x61, 0x7e, 0x4d,
        0xa5, 0x06, 0x39, 0x71, 0x71, 0x15, 0xa5, 0xa9,
        0xc3, 0x19, 0x2a, 0xe8, 0xc2, 0x85, 0x91, 0xd7,
    ];
    let mut slot = SeedSlot::empty();
    slot.word_count = 12;
    slot.indices = [0,0,0,0,0,0,0,0,0,0,0,3, 0,0,0,0,0,0,0,0,0,0,0,0];

    // Before derivation the slot must report no fingerprint and render dashes.
    if slot.has_fingerprint() { return false; }
    let mut hex = [0u8; 8];
    slot.fingerprint_hex(&mut hex);
    if hex != *b"--------" { return false; }

    slot.set_fingerprint_from_key(&ACCT_KEY_ABANDON);
    if !slot.has_fingerprint() { return false; }
    slot.fingerprint_hex(&mut hex);
    hex == *b"2f27cc04"
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: duplicate detection uses full material, not 4 truncated bytes (L-04).
///
/// Two distinct mnemonics forced into the same 4-byte fingerprint must still
/// occupy separate slots, and the same mnemonic with a different passphrase
/// must not be treated as already present.
pub fn test_fingerprint_collision_dedup() -> bool {
    let mut mgr = SeedManager::new();

    let a = [0u16; 24];
    let mut b = [0u16; 24];
    b[0] = 1; // different mnemonic

    let sa = match mgr.store(&a, 12, b"", 0) { Some(i) => i, None => return false };
    let sb = match mgr.store(&b, 12, b"", 0) { Some(i) => i, None => return false };
    if sa == sb { return false; }

    // Force a fingerprint collision between the two occupied slots.
    mgr.slots[sa].fingerprint = [0xAB, 0xCD, 0xEF, 0x01];
    mgr.slots[sb].fingerprint = [0xAB, 0xCD, 0xEF, 0x01];

    // A mnemonic slot must never be returned to an xprv or raw-key lookup.
    // Since every kind now uses SHA256(controlling private key), a 24-word slot
    // and its own xprv slot collide by construction, and an unfiltered lookup
    // would hand the mnemonic slot to the xprv import path.
    if mgr.find_by_fingerprint(&[0xAB, 0xCD, 0xEF, 0x01], 2).is_some() { return false; }
    if mgr.find_by_fingerprint(&[0xAB, 0xCD, 0xEF, 0x01], 1).is_some() { return false; }
    if mgr.find_by_fingerprint(&[0xAB, 0xCD, 0xEF, 0x01], 12) != Some(sa) { return false; }

    // Re-storing A must return A's slot, not B's, despite identical bytes.
    if mgr.store(&a, 12, b"", 0) != Some(sa) { return false; }
    if mgr.store(&b, 12, b"", 0) != Some(sb) { return false; }

    // Same mnemonic, different passphrase: a distinct wallet, distinct slot.
    let sc = match mgr.store(&a, 12, b"TREZOR", 6) { Some(i) => i, None => return false };
    if sc == sa { return false; }
    // And storing it again must land on the same slot, not a fourth.
    if mgr.store(&a, 12, b"TREZOR", 6) != Some(sc) { return false; }

    mgr.count() == 3
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
    let total = 6u32;

    if test_seedqr_roundtrip_12() { passed += 1; }
    if test_seedqr_roundtrip_24() { passed += 1; }
    if test_compact_seedqr_12() { passed += 1; }
    if test_fingerprint() { passed += 1; }
    if test_fingerprint_collision_dedup() { passed += 1; }
    if test_seed_manager_store_delete() { passed += 1; }

    (passed, total)
}
