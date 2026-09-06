use super::super::push_int_sigscript;

#[test]
fn sigscript_integer_encoding_is_byte_exact_across_sign_boundaries() {
    for (value, expected) in [
        (0u64, vec![0x00]),
        (1, vec![0x51]),
        (16, vec![0x60]),
        (17, vec![0x01, 0x11]),
        (127, vec![0x01, 0x7f]),
        (128, vec![0x02, 0x80, 0x00]),
        (255, vec![0x02, 0xff, 0x00]),
        (256, vec![0x02, 0x00, 0x01]),
        (65_535, vec![0x03, 0xff, 0xff, 0x00]),
        (65_536, vec![0x03, 0x00, 0x00, 0x01]),
    ] {
        let mut encoded = Vec::new();
        push_int_sigscript(&mut encoded, value);
        assert_eq!(encoded, expected, "value {value}");
    }
}

#[test]
fn state_machine_builder_emits_signature_and_redeem_byte_exactly() {
    use super::super::build_p2sh_state_machine_sig_script;
    use serde_json::{json, Map, Value};

    let mut signatures = Map::<String, Value>::new();
    signatures.insert(
        format!("02{}", "44".repeat(32)),
        json!({"schnorr": "55".repeat(64)}),
    );
    let redeem = [0xb9, 0x51, 0x75];
    let actual =
        build_p2sh_state_machine_sig_script(&redeem, &signatures).expect("state-machine witness");

    let mut expected = Vec::with_capacity(70);
    expected.push(65); // 64-byte Schnorr signature + SIGHASH_ALL.
    expected.extend_from_slice(&[0x55; 64]);
    expected.push(0x01);
    expected.extend_from_slice(&[3, 0xb9, 0x51, 0x75]);

    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 70);
}
