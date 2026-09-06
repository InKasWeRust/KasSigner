use super::*;

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
    assert!(slot.set_mnemonic_source(12));
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

    mgr.active = 0;
    if mgr.active != 0 { return false; }

    mgr.delete(0);
    if mgr.count() != 0 { return false; }
    if mgr.active != 0xFF { return false; }
    true
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: imported account-key slot reconstructs its exact 65-byte payload.
pub fn test_account_key_slot_roundtrip() -> bool {
    let mut raw = [0u8; 65];
    for (index, byte) in raw.iter_mut().enumerate() {
        *byte = index as u8;
    }

    let mut manager = SeedManager::new();
    let fingerprint = [1, 2, 3, 4];
    let first = manager.store_account_key(&raw, [9, 8, 7, 6], fingerprint);
    let duplicate = manager.store_account_key(&raw, [9, 8, 7, 6], fingerprint);
    let distinct_metadata = manager.store_account_key(&raw, [9, 8, 7, 5], fingerprint);
    let mut reconstructed = [0u8; 65];
    let mut rejected_output = [0xA5u8; 65];
    let invalid_slot = SeedSlot::empty();
    first == Some(0)
        && duplicate == first
        && distinct_metadata == Some(1)
        && manager.slots[0].account_key_raw(&mut reconstructed)
        && reconstructed == raw
        && !invalid_slot.account_key_raw(&mut rejected_output)
        && rejected_output == [0u8; 65]
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Test: one-time mnemonic slots never dirty or replace persistent selection metadata.
pub fn test_transient_seed_manager_is_persistence_neutral() -> bool {
    let mut manager = SeedManager::new();
    let indices = [0u16; 24];
    let Some(saved) = manager.store(&indices, 12, b"", 0) else { return false; };
    if !manager.set_active(saved) { return false; }
    let saved_revision = manager.revision();
    let saved_name_revision = manager.name_revision();

    let Some(transient) = manager.store_transient(&indices, 12, b"session", 7) else { return false; };
    if transient == saved || manager.revision() != saved_revision { return false; }
    if !manager.set_slot_name(transient, b"One Time")
        || manager.name_revision() != saved_name_revision
        || !manager.set_active(transient)
        || manager.persistent_active() != saved as u8
        || manager.revision() != saved_revision
    {
        return false;
    }
    manager.delete(transient);
    manager.persistent_active() == saved as u8
        && manager.revision() == saved_revision
        && manager.name_revision() == saved_name_revision
}

#[cfg(any(test, feature = "verbose-boot"))]
/// Run all seed manager tests.
pub fn run_seed_manager_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 7u32;

    if test_seedqr_roundtrip_12() { passed += 1; }
    if test_seedqr_roundtrip_24() { passed += 1; }
    if test_compact_seedqr_12() { passed += 1; }
    if test_fingerprint() { passed += 1; }
    if test_seed_manager_store_delete() { passed += 1; }
    if test_account_key_slot_roundtrip() { passed += 1; }
    if test_transient_seed_manager_is_persistence_neutral() { passed += 1; }

    (passed, total)
}

#[test]
fn seed_manager_vectors_pass() {
    let (passed, total) = run_seed_manager_tests();
    assert_eq!(passed, total);
}
