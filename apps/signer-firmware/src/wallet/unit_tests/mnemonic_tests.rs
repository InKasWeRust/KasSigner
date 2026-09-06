use super::*;

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
/// Test: Touch Seed transcript accepts movement only and cannot finalize early.
pub fn test_touch_entropy_collector() -> bool {
    let mut collector = TouchEntropyCollector::new();
    if collector.finish().is_some() || collector.count() != 0 { return false; }
    if !collector.record(1, 100, 100) { return false; }
    if collector.record(2, 100, 100) || collector.count() != 1 { return false; }
    let target = collector.target();
    for sample in 1..target {
        let x = 100u16.wrapping_add((sample & 0x7f) as u16);
        let y = 100u16.wrapping_add(((sample >> 7) & 0x7f) as u16);
        if !collector.record((sample as u32).wrapping_mul(977), x, y) { return false; }
    }
    if collector.count() != target { return false; }
    let Some(digest) = collector.finish() else { return false; };
    digest.iter().any(|byte| *byte != 0) && collector.count() == 0
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Run all mnemonic-domain tests.
pub fn run_mnemonic_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 4u32;

    if test_dice_entropy_12() { passed += 1; }
    if test_calc_last_word_12() { passed += 1; }
    if test_word_input_matching() { passed += 1; }
    if test_touch_entropy_collector() { passed += 1; }

    (passed, total)
}

#[test]
fn mnemonic_vectors_pass() {
    let (passed, total) = run_mnemonic_tests();
    assert_eq!(passed, total);
}
