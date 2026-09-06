use serde_json::json;

use super::super::exact_json::{canonicalize_pskt_exact_fields, parse_exact_u64};

#[test]
fn exact_u64_accepts_decimal_string_and_safe_legacy_number() {
    assert_eq!(
        parse_exact_u64(&json!("18446744073709551615"), "amount").unwrap(),
        u64::MAX
    );
    assert_eq!(
        parse_exact_u64(&json!(9_007_199_254_740_991u64), "amount").unwrap(),
        9_007_199_254_740_991
    );
}

#[test]
fn exact_u64_rejects_noncanonical_and_unsafe_numeric_forms() {
    for invalid in ["", "01", "1x", "+1", "-1"] {
        assert!(
            parse_exact_u64(&json!(invalid), "amount").is_err(),
            "accepted noncanonical decimal form {invalid:?}"
        );
    }
    assert!(parse_exact_u64(&json!(9_007_199_254_740_992u64), "amount").is_err());
    assert!(parse_exact_u64(&json!(1.5), "amount").is_err());
}

#[test]
fn canonicalizer_emits_exact_fields_as_decimal_strings() {
    let mut pskt = json!({
        "global": {"fallbackLockTime": 7, "gas": 0},
        "inputs": [{"sequence": 0, "utxoEntry": {"amount": 10, "blockDaaScore": 11}}],
        "outputs": [{"amount": 9}]
    });
    canonicalize_pskt_exact_fields(&mut pskt).unwrap();
    assert_eq!(pskt["global"]["fallbackLockTime"], "7");
    assert_eq!(pskt["inputs"][0]["utxoEntry"]["amount"], "10");
    assert_eq!(pskt["inputs"][0]["utxoEntry"]["blockDaaScore"], "11");
    assert_eq!(pskt["outputs"][0]["amount"], "9");
}

#[test]
fn canonicalizer_allows_missing_input_amount_but_requires_output_amount() {
    let mut finalization_only = json!({
        "global": {},
        "inputs": [{"utxoEntry": {"scriptPublicKey": "000051"}}],
        "outputs": [{"amount": 1}]
    });
    canonicalize_pskt_exact_fields(&mut finalization_only).unwrap();
    assert!(finalization_only["inputs"][0]["utxoEntry"]
        .get("amount")
        .is_none());
    assert_eq!(finalization_only["outputs"][0]["amount"], "1");

    let mut missing_output_amount = json!({
        "global": {},
        "inputs": [],
        "outputs": [{"scriptPublicKey": "000051"}]
    });
    assert_eq!(
        canonicalize_pskt_exact_fields(&mut missing_output_amount).unwrap_err(),
        "missing amount"
    );
}
