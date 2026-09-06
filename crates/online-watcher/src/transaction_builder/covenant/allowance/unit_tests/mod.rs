use super::*;

fn utxo(amount: u64) -> UtxoEntry {
    UtxoEntry {
        tx_id: "11".repeat(32),
        index: 0,
        amount,
        script_public_key: vec![0x51],
        block_daa_score: 0,
        covenant_id: None,
    }
}

#[test]
fn allowance_requires_utxos_and_accepts_exact_funding() {
    assert!(require_utxos(&[]).is_err());
    assert_eq!(require_utxos(&[utxo(1)]), Ok(()));
    assert_eq!(ensure_funded(10, 10, 9, 1), Ok(()));
    assert!(ensure_funded(11, 10, 10, 1).is_err());
}
