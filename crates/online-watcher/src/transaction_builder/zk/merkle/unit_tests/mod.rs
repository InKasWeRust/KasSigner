use super::*;
use crate::{account::utxo::UtxoEntry, wasm_api::test_support::ready};

fn utxo(byte: u8, amount: u64) -> UtxoEntry {
    UtxoEntry {
        tx_id: format!("{byte:02x}").repeat(32),
        index: u32::from(byte),
        amount,
        script_public_key: vec![0x51],
        block_daa_score: 0,
        covenant_id: None,
    }
}

#[test]
fn merkle_builder_and_balance_boundaries_are_exact() {
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(build_remote("bad", "bad", "51", "[]", 1, 1, "ws://unused")).is_err());

    let mut exact = vec![utxo(1, 1), utxo(2, 4), utxo(3, 2), utxo(4, 3)];
    limit_merkle_utxos(&mut exact);
    assert_eq!(
        exact.iter().map(|entry| entry.amount).collect::<Vec<_>>(),
        vec![1, 4, 2, 3]
    );
    let mut over = exact.clone();
    over.push(utxo(5, 10));
    limit_merkle_utxos(&mut over);
    assert_eq!(over.len(), 4);
    assert_eq!(over[0].amount, 10);

    assert_eq!(require_merkle_balance(9, 1, 10, 10), Ok(0));
    assert!(require_merkle_balance(10, 1, 11, 10).is_err());
}
