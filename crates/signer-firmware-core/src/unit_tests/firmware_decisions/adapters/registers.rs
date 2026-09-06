use crate::camera::registers::{id_pair_matches, write_banked, write_pairs, write_pairs_with_hook};

#[test]
fn register_tables_preserve_pair_and_bank_order() {
    let mut pairs = std::vec::Vec::new();
    assert_eq!(
        write_pairs(&[(1, 2), (3, 4)], "pair", |register, value| {
            pairs.push((register, value));
            true
        }),
        Ok(()),
    );
    assert_eq!(pairs, [(1, 2), (3, 4)]);

    let mut banked = std::vec::Vec::new();
    assert_eq!(
        write_banked(&[(1, 2, 3), (4, 5, 6)], "bank", |register, value, bank| {
            banked.push((register, value, bank));
            true
        }),
        Ok(()),
    );
    assert_eq!(banked, [(1, 2, 3), (4, 5, 6)]);
}

#[test]
fn register_tables_run_hooks_and_report_failures() {
    let mut hooks = std::vec::Vec::new();
    assert_eq!(
        write_pairs_with_hook(
            &[(0xfe, 0x80), (1, 2)],
            "write",
            |register, _| register != 1,
            |register, value| hooks.push((register, value)),
        ),
        Err("write"),
    );
    assert_eq!(hooks, [(0xfe, 0x80)]);
    assert!(id_pair_matches(0x26, 0x41, 0x26, &[0x41, 0x42]));
    assert!(!id_pair_matches(0x26, 0x43, 0x26, &[0x41, 0x42]));
}

#[test]
fn register_tables_cover_each_failure_boundary_and_id_high_mismatch() {
    let mut pair_calls = 0usize;
    assert_eq!(
        write_pairs(&[(1u8, 2u8), (3, 4)], "pair", |register, _| {
            pair_calls += 1;
            register != 1
        }),
        Err("pair"),
    );
    assert_eq!(pair_calls, 1);

    let mut bank_calls = 0usize;
    assert_eq!(
        write_banked(&[(1u8, 2u8, 3u8), (4, 5, 6)], "bank", |register, _, _| {
            bank_calls += 1;
            register != 4
        }),
        Err("bank"),
    );
    assert_eq!(bank_calls, 2);

    let mut hooks = std::vec::Vec::new();
    assert_eq!(
        write_pairs_with_hook(
            &[(7u8, 8u8), (9, 10)],
            "hook",
            |_, _| true,
            |register, value| hooks.push((register, value)),
        ),
        Ok(()),
    );
    assert_eq!(hooks, [(7, 8), (9, 10)]);

    assert!(!id_pair_matches(0x25, 0x41, 0x26, &[0x41, 0x42]));
    assert!(!id_pair_matches(0x26, 0x41, 0x26, &[]));
}
