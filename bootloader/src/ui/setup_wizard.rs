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

// ui/setup_wizard.rs — Dice entropy, word import, and setup wizards
// 100% Rust, no-std, no-alloc
//
// First-boot flow for creating or importing a wallet.
// Manages the entire setup state machine from welcome screen
// through to having an unlocked wallet ready for signing.
//
// Flows:
//   A) New wallet (TRNG entropy)
//   B) New wallet (dice roll — 99 rolls for 12 words, 198 for 24)
//   C) Import 12/24 words manually
//   D) Calc last word (enter 11 or 23 words, compute checksum)
//
// After mnemonic is established:
//   → Show seed words for backup
//   → Set PIN (enter + confirm)
//   → Encrypt mnemonic with PIN → write to NVS flash
//   → Derive Kaspa keys → ready


use crate::wallet::bip39;

// ═══════════════════════════════════════════════════════════════════
// Setup States
// ═══════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq)]
/// Setup wizard state machine states.
pub enum SetupState {
    /// Welcome screen — first boot detected
    Welcome,

    /// Choose action: New Wallet / Import / Calc Last Word
    ChooseAction,

    /// Sub-menu for new wallet: TRNG / Dice Roll
    ChooseEntropy,

    /// Choose word count: 12 or 24
    ChooseWordCount,

    /// Dice rolling: collecting entropy from dice
    DiceRoll,

    /// Show generated mnemonic word by word for backup
    ShowWords { word_idx: u8 },

    /// Verify: ask user to confirm specific words
    VerifyWords { verify_idx: u8, word_pos: u8 },

    /// Import: enter words one by one via word selector
    ImportWords { word_idx: u8 },

    /// Calc last word: enter 11 or 23 words, auto-compute last
    CalcLastWord { word_idx: u8 },

    /// Set PIN (first entry)
    SetPin,

    /// Confirm PIN (second entry, must match)
    ConfirmPin,

    /// Saving to flash (encrypting + writing)
    Saving,

    /// Setup complete — transition to main wallet app
    Complete,

    /// Error state
    Error,
}

// ═══════════════════════════════════════════════════════════════════
// Menu Choices
// ═══════════════════════════════════════════════════════════════════

/// Main action menu items
pub const ACTION_MENU: &[&str] = &[
    "Create New Wallet",
    "Import Seed Words",
    "Calc Last Word",
];

/// Entropy source menu
pub const ENTROPY_MENU: &[&str] = &[
    "Device Random (TRNG)",
    "Dice Roll (manual)",
];

/// Word count menu
pub const WORDCOUNT_MENU: &[&str] = &[
    "12 Words",
    "24 Words",
];

// ═══════════════════════════════════════════════════════════════════
// Dice Roll Entropy
// ═══════════════════════════════════════════════════════════════════

/// Dice roll entropy collector.
///
/// Each dice roll (1-6) contributes log2(6) ≈ 2.585 bits of entropy.
/// For 128 bits: need 50 rolls minimum, we use 99 for safety margin.
/// For 256 bits: need 100 rolls minimum, we use 198.
///
/// Method: Hash all rolls with SHA256 to extract uniform entropy.
/// This is the same approach used by SeedSigner and ColdCard.
pub struct DiceCollector {
    /// Raw dice values (1-6)
    pub rolls: [u8; 200],
    /// Number of rolls collected
    pub count: usize,
    /// Target number of rolls
    pub target: usize,
    /// Target entropy bytes (16 for 12-word, 32 for 24-word)
    pub entropy_bytes: usize,
}

impl DiceCollector {
        /// Create a dice collector targeting 12-word mnemonic (128 bits).
pub fn new_12_word() -> Self {
        Self {
            rolls: [0; 200],
            count: 0,
            target: 99,
            entropy_bytes: 16,
        }
    }

        /// Create a dice collector targeting 24-word mnemonic (256 bits).
pub fn new_24_word() -> Self {
        Self {
            rolls: [0; 200],
            count: 0,
            target: 198,
            entropy_bytes: 32,
        }
    }

    /// Add a dice roll (value 1-6)
    pub fn add_roll(&mut self, value: u8) -> bool {
        if !(1..=6).contains(&value) || self.count >= self.target {
            return false;
        }
        self.rolls[self.count] = value;
        self.count += 1;
        true
    }

    /// Remove last roll
    pub fn undo(&mut self) {
        if self.count > 0 {
            self.count -= 1;
            self.rolls[self.count] = 0;
        }
    }

    /// Check if we have enough rolls
    pub fn is_complete(&self) -> bool {
        self.count >= self.target
    }

    /// Extract entropy by hashing all rolls with SHA256.
    /// Returns 16 bytes (12-word) or 32 bytes (24-word).
    pub fn extract_entropy_16(&self) -> [u8; 16] {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&self.rolls[..self.count]);
        let hash = hasher.finalize();
        let mut entropy = [0u8; 16];
        entropy.copy_from_slice(&hash[..16]);
        entropy
    }

        /// Extract collected dice entropy as a 32-byte array.
pub fn extract_entropy_32(&self) -> [u8; 32] {
        use sha2::{Sha256, Digest};

        // For 32 bytes, use SHA256 of rolls + SHA256 of (rolls reversed)
        // and concatenate the first 16 bytes of each.
        // Alternative: use two rounds with different prefixes.
        let mut hasher1 = Sha256::new();
        hasher1.update(b"KasSigner-dice-entropy-1:");
        hasher1.update(&self.rolls[..self.count]);
        let hash1 = hasher1.finalize();

        let mut hasher2 = Sha256::new();
        hasher2.update(b"KasSigner-dice-entropy-2:");
        hasher2.update(&self.rolls[..self.count]);
        let hash2 = hasher2.finalize();

        let mut entropy = [0u8; 32];
        entropy[..16].copy_from_slice(&hash1[..16]);
        entropy[16..].copy_from_slice(&hash2[..16]);
        entropy
    }
}

// ═══════════════════════════════════════════════════════════════════
// Calc Last Word
// ═══════════════════════════════════════════════════════════════════

/// Calculate the last word of a BIP39 mnemonic given the first 11 or 23 words.
///
/// The last word contains the checksum bits. For 12-word:
///   - 11 words = 121 bits (11 × 11 bits)
///   - Need 132 bits total (128 entropy + 4 checksum)
///   - Last word's 11 bits = 7 bits entropy + 4 bits checksum
///   - So there are 2^7 = 128 valid last words. We pick the first valid one.
///
/// For 24-word:
///   - 23 words = 253 bits
///   - Need 264 bits total (256 entropy + 8 checksum)
///   - Last word's 11 bits = 3 bits entropy + 8 bits checksum
///   - So there are 2^3 = 8 valid last words.
///
/// Returns the index (0-2047) of the valid last word.
pub fn calc_last_word_12(indices: &[u16; 11]) -> u16 {
    use sha2::{Sha256, Digest};

    // Reconstruct 121 bits from 11 words
    // Then try all possible last words and find one with valid checksum
    // The entropy is in the first 128 bits, checksum = first 4 bits of SHA256(entropy)

    // Pack 11 indices (121 bits) into bytes
    let mut bits = [0u8; 17]; // 132 bits = 16.5 bytes, round up
    let mut bit_pos: usize = 0;

    for &idx in indices.iter() {
        for bit in (0..11).rev() {
            let byte_idx = bit_pos / 8;
            let bit_idx = 7 - (bit_pos % 8);
            if (idx >> bit) & 1 == 1 {
                bits[byte_idx] |= 1 << bit_idx;
            }
            bit_pos += 1;
        }
    }

    // bit_pos is now 121. The last word adds 11 more bits (to 132).
    // Bits 0..127 = entropy, bits 128..131 = checksum.
    // Try all 2048 possible last words, find valid one.
    for candidate in 0u16..2048 {
        // Set bits 121..131 from candidate
        let mut test_bits = bits;
        let mut bp = 121;
        for bit in (0..11).rev() {
            let byte_idx = bp / 8;
            let bit_idx = 7 - (bp % 8);
            if (candidate >> bit) & 1 == 1 {
                test_bits[byte_idx] |= 1 << bit_idx;
            } else {
                test_bits[byte_idx] &= !(1 << bit_idx);
            }
            bp += 1;
        }

        // Extract 16 bytes of entropy (bits 0..127)
        let entropy: [u8; 16] = [
            test_bits[0], test_bits[1], test_bits[2], test_bits[3],
            test_bits[4], test_bits[5], test_bits[6], test_bits[7],
            test_bits[8], test_bits[9], test_bits[10], test_bits[11],
            test_bits[12], test_bits[13], test_bits[14], test_bits[15],
        ];

        // Compute checksum = first 4 bits of SHA256(entropy)
        let hash = Sha256::digest(entropy);
        let checksum_nibble = hash[0] >> 4; // top 4 bits

        // Extract bits 128..131 from test_bits
        let stored_checksum = (test_bits[16] >> 4) & 0x0F;

        if checksum_nibble == stored_checksum {
            return candidate;
        }
    }

    // Should never reach here — there's always at least one valid word
    0
}

/// Same for 24 words (23 given + calc last)
pub fn calc_last_word_24(indices: &[u16; 23]) -> u16 {
    use sha2::{Sha256, Digest};

    let mut bits = [0u8; 33]; // 264 bits
    let mut bit_pos: usize = 0;

    for &idx in indices.iter() {
        for bit in (0..11).rev() {
            let byte_idx = bit_pos / 8;
            let bit_idx = 7 - (bit_pos % 8);
            if (idx >> bit) & 1 == 1 {
                bits[byte_idx] |= 1 << bit_idx;
            }
            bit_pos += 1;
        }
    }

    // 253 bits from 23 words. Need 264 total (256 entropy + 8 checksum).
    for candidate in 0u16..2048 {
        let mut test_bits = bits;
        let mut bp = 253;
        for bit in (0..11).rev() {
            let byte_idx = bp / 8;
            let bit_idx = 7 - (bp % 8);
            if (candidate >> bit) & 1 == 1 {
                test_bits[byte_idx] |= 1 << bit_idx;
            } else {
                test_bits[byte_idx] &= !(1 << bit_idx);
            }
            bp += 1;
        }

        // 32 bytes entropy
        let mut entropy = [0u8; 32];
        entropy.copy_from_slice(&test_bits[..32]);

        // Checksum = first 8 bits of SHA256(entropy)
        let hash = Sha256::digest(entropy);
        let checksum_byte = hash[0];

        // Stored checksum at bits 256..263 = test_bits[32]
        if checksum_byte == test_bits[32] {
            return candidate;
        }
    }

    0
}

// ═══════════════════════════════════════════════════════════════════
// Word Input Helper
// ═══════════════════════════════════════════════════════════════════

/// Word input state for importing mnemonics
pub struct WordInput {
    /// Current prefix being typed (up to 8 chars)
    pub prefix: [u8; 8],
    pub prefix_len: usize,
    /// Matching word index from wordlist (-1 = no match)
    pub matched_index: Option<u16>,
    /// Number of matches for current prefix
    pub match_count: u16,
    /// First few matching indices (for showing suggestions)
    pub suggestions: [u16; 4],
    pub num_suggestions: u8,
}

impl WordInput {
    pub fn new() -> Self {
        Self {
            prefix: [0; 8],
            prefix_len: 0,
            matched_index: None,
            match_count: 0,
            suggestions: [0; 4],
            num_suggestions: 0,
        }
    }

    /// Add a character to the prefix and update matches
    pub fn push_char(&mut self, c: u8) {
        if self.prefix_len < 8 {
            self.prefix[self.prefix_len] = c;
            self.prefix_len += 1;
            self.update_matches();
        }
    }

    /// Remove last character
    pub fn backspace(&mut self) {
        if self.prefix_len > 0 {
            self.prefix_len -= 1;
            self.prefix[self.prefix_len] = 0;
            self.update_matches();
        }
    }

    /// Reset for next word
    pub fn reset(&mut self) {
        self.prefix = [0; 8];
        self.prefix_len = 0;
        self.matched_index = None;
        self.match_count = 0;
        self.num_suggestions = 0;
    }

    /// Update matching words from the BIP39 wordlist
    fn update_matches(&mut self) {
        use crate::wallet::bip39_wordlist::WORDLIST;

        self.match_count = 0;
        self.matched_index = None;
        self.num_suggestions = 0;

        if self.prefix_len == 0 {
            return;
        }

        let prefix = &self.prefix[..self.prefix_len];

        for (idx, &word) in WORDLIST.iter().enumerate() {
            let word_bytes = word.as_bytes();
            if word_bytes.len() >= self.prefix_len {
                let matches = word_bytes[..self.prefix_len]
                    .iter()
                    .zip(prefix.iter())
                    .all(|(a, b)| *a == *b);

                if matches {
                    self.match_count += 1;

                    if (self.num_suggestions as usize) < 4 {
                        self.suggestions[self.num_suggestions as usize] = idx as u16;
                        self.num_suggestions += 1;
                    }

                    // Exact match?
                    if word_bytes.len() == self.prefix_len {
                        self.matched_index = Some(idx as u16);
                    }
                }
            }
        }

        // If only one match, auto-select it
        if self.match_count == 1 {
            self.matched_index = Some(self.suggestions[0]);
        }
    }

    /// Get the prefix as a str
    pub fn prefix_str(&self) -> &str {
        core::str::from_utf8(&self.prefix[..self.prefix_len]).unwrap_or("")
    }
}

// ═══════════════════════════════════════════════════════════════════
// Setup Wizard Controller
// ═══════════════════════════════════════════════════════════════════

/// Setup wizard orchestrating the full seed creation flow.
pub struct SetupWizard {
    pub state: SetupState,
    /// Whether creating 12 or 24 word mnemonic
    pub word_count: u8, // 12 or 24
    /// Generated/imported mnemonic indices
    pub mnemonic: [u16; 24],
    /// How many words have been entered (for import)
    pub words_entered: u8,
    /// Dice collector (only allocated when in DiceRoll state)
    pub dice: DiceCollector,
    /// Word input (for import mode)
    pub word_input: WordInput,
    /// Whether setup was cancelled
    pub cancelled: bool,
}

impl SetupWizard {
        /// Create a new setup wizard in initial state.
pub fn new() -> Self {
        Self {
            state: SetupState::Welcome,
            word_count: 12,
            mnemonic: [0; 24],
            words_entered: 0,
            dice: DiceCollector::new_12_word(),
            word_input: WordInput::new(),
            cancelled: false,
        }
    }

    /// Generate mnemonic from TRNG
    /// Caller must provide random bytes from hardware RNG
    pub fn generate_from_entropy(&mut self, entropy: &[u8]) {
        if self.word_count == 12 {
            let mut e16 = [0u8; 16];
            e16.copy_from_slice(&entropy[..16]);
            let m = bip39::mnemonic_from_entropy_12(&e16);
            self.mnemonic[..12].copy_from_slice(&m.indices);
        } else {
            let mut e32 = [0u8; 32];
            e32.copy_from_slice(&entropy[..32]);
            let m = bip39::mnemonic_from_entropy_24(&e32);
            self.mnemonic[..24].copy_from_slice(&m.indices);
        }
    }

    /// Generate mnemonic from completed dice rolls
    pub fn generate_from_dice(&mut self) {
        if self.word_count == 12 {
            let entropy = self.dice.extract_entropy_16();
            let m = bip39::mnemonic_from_entropy_12(&entropy);
            self.mnemonic[..12].copy_from_slice(&m.indices);
        } else {
            let entropy = self.dice.extract_entropy_32();
            let m = bip39::mnemonic_from_entropy_24(&entropy);
            self.mnemonic[..24].copy_from_slice(&m.indices);
        }
    }
    /// Serialize mnemonic indices to bytes for encryption
    /// Format: [count][idx0_hi][idx0_lo][idx1_hi][idx1_lo]...
    pub fn serialize_mnemonic(&self, buf: &mut [u8]) -> usize {
        let count = self.word_count as usize;
        let needed = 1 + count * 2;
        if buf.len() < needed {
            return 0;
        }

        buf[0] = self.word_count;
        for i in 0..count {
            let idx = self.mnemonic[i];
            buf[1 + i * 2] = (idx >> 8) as u8;
            buf[1 + i * 2 + 1] = (idx & 0xFF) as u8;
        }

        needed
    }

    /// Deserialize mnemonic from bytes
    pub fn deserialize_mnemonic(buf: &[u8], mnemonic: &mut [u16; 24]) -> Option<u8> {
        if buf.is_empty() {
            return None;
        }

        let count = buf[0] as usize;
        if count != 12 && count != 24 {
            return None;
        }

        let needed = 1 + count * 2;
        if buf.len() < needed {
            return None;
        }

        for i in 0..count {
            let hi = buf[1 + i * 2] as u16;
            let lo = buf[1 + i * 2 + 1] as u16;
            mnemonic[i] = (hi << 8) | lo;
        }

        Some(count as u8)
    }

    /// Zeroize sensitive data
    pub fn zeroize(&mut self) {
        for idx in self.mnemonic.iter_mut() {
            unsafe { core::ptr::write_volatile(idx, 0); }
        }
        for roll in self.dice.rolls.iter_mut() {
            unsafe { core::ptr::write_volatile(roll, 0); }
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for SetupWizard {
    fn drop(&mut self) {
        self.zeroize();
    }
}

// ═══════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: dice entropy collection for 12 words.
pub fn test_dice_entropy_12() -> bool {
    let mut dice = DiceCollector::new_12_word();
    // Roll 99 dice (all 3s for test)
    for _ in 0..99 {
        dice.add_roll(3);
    }
    if !dice.is_complete() { return false; }

    let entropy = dice.extract_entropy_16();
    // Entropy should not be all zeros (SHA256 of "333...3" is not zero)
    entropy.iter().any(|&b| b != 0)
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: last word calculation for 12-word mnemonic.
pub fn test_calc_last_word_12() -> bool {
    // "abandon" x11 → last word should be "about" (index 3)
    let indices: [u16; 11] = [0; 11]; // "abandon" = index 0

    let last = calc_last_word_12(&indices);

    // Verify by constructing full mnemonic and validating
    let mut full = bip39::Mnemonic12 { indices: [0; 12] };
    full.indices[..11].copy_from_slice(&indices);
    full.indices[11] = last;

    bip39::validate_mnemonic_12(&full).is_ok()
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: mnemonic serialization round-trip.
pub fn test_serialize_deserialize_mnemonic() -> bool {
    let mut wiz = SetupWizard::new();
    wiz.word_count = 12;
    wiz.mnemonic[0] = 100;
    wiz.mnemonic[1] = 2000;
    wiz.mnemonic[11] = 1500;

    let mut buf = [0u8; 50];
    let len = wiz.serialize_mnemonic(&mut buf);

    let mut restored = [0u16; 24];
    let count = SetupWizard::deserialize_mnemonic(&buf[..len], &mut restored);

    count == Some(12)
        && restored[0] == 100
        && restored[1] == 2000
        && restored[11] == 1500
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: word input prefix matching.
pub fn test_word_input_matching() -> bool {
    let mut input = WordInput::new();
    input.push_char(b'a');
    input.push_char(b'b');
    // "ab" should match: abandon, ability, able, about, above, absent, absorb, abstract, absurd, abuse
    let has_matches = input.match_count > 5;

    input.push_char(b'o');
    input.push_char(b'u');
    input.push_char(b't');
    // "about" should match exactly one
    let exact = input.matched_index == Some(3); // "about" = index 3

    has_matches && exact
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Run all setup wizard tests.
pub fn run_setup_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 4u32;

    if test_dice_entropy_12() { passed += 1; }
    if test_calc_last_word_12() { passed += 1; }
    if test_serialize_deserialize_mnemonic() { passed += 1; }
    if test_word_input_matching() { passed += 1; }

    (passed, total)
}
