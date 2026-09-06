use super::*;

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
fn payjoin_fee_split_and_required_fee_are_amount_exact() {
    assert_eq!(required_fee(2), Ok(348_335));
    let covenant = [utxo(1, 1_000_000)];
    let mixing = utxo(2, 1_000_000);
    let amounts = calculate_amounts(&covenant, &mixing, 400_000).expect("amounts");
    assert_eq!(amounts.total, 2_000_000);
    assert_eq!(amounts.fee, 400_000);
    assert_eq!(amounts.send, 700_000);
    assert_eq!(amounts.change, 900_000);

    let low = [utxo(3, 300_000)];
    assert!(calculate_amounts(&low, &utxo(4, 200_000), 400_000).is_err());
}

#[test]
fn payjoin_outputs_and_wire_preserve_zero_change_and_nonzero_change() {
    let scripts = Scripts {
        covenant: "000051".into(),
        destination: "000052".into(),
        mixing: "000053".into(),
    };
    let one = build_outputs(&scripts, 7, 0);
    assert_eq!(one.len(), 1);
    assert_eq!(one[0]["amount"], 7);
    let two = build_outputs(&scripts, 7, 1);
    assert_eq!(two.len(), 2);
    assert_eq!(two[1]["amount"], 1);

    let wire = encode_pskb(Vec::new(), two, 0, 2).expect("PSKB wire");
    let bytes = hex::decode(wire).expect("wire hex");
    assert_eq!(&bytes[..4], b"PSKB");
}
