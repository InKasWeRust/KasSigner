use super::*;

#[test]
fn shipping_script_and_pskb_helpers_return_real_encodings() {
    let address = crate::account::address::encode_p2pk_address(&[0x42; 32], "kaspa");
    let expected = crate::account::address::address_to_script_pubkey(&address).expect("script");
    assert_eq!(
        script_pubkey_hex(&address),
        Ok(format!("0000{}", hex::encode(expected)))
    );
    assert!(script_pubkey_hex("not-an-address").is_err());

    let wire = encode_pskb(
        serde_json::json!({
            "txVersion": 0,
            "fallbackLockTime": null,
            "inputsModifiableFlag": false,
            "outputsModifiableFlag": false,
            "inputCount": 0,
            "outputCount": 0,
            "bip32Derivations": [],
            "proprietaries": []
        }),
        Vec::new(),
        serde_json::json!([]),
    )
    .expect("PSKB wire");
    assert!(wire.len() > 8);
    assert_eq!(&wire[..8], "50534b42");
}
