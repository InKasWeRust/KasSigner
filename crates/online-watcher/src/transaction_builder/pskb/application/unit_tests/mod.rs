use super::*;
use crate::account::utxo::UtxoEntry;

#[test]
fn pskb_application_encode_returns_canonical_envelope() {
    let prepared = PreparedSweep {
        utxos: vec![UtxoEntry {
            tx_id: "11".repeat(32),
            index: 0,
            amount: 20_000,
            script_public_key: vec![0x51],
            block_daa_score: 0,
            covenant_id: None,
        }],
        total: 20_000,
        send_amount: 19_000,
        source_script_public_key: vec![0x51],
        destination_script_public_key: vec![0x52],
    };
    let global = PskbGlobalPlan::standard();
    let policy = SweepInputPolicy::p2pk(serde_json::json!({}));
    let wire = encode(&prepared, global, &policy).expect("encoded sweep");
    let bytes = hex::decode(wire).expect("wire hex");
    assert_eq!(&bytes[..4], b"PSKB");
}
