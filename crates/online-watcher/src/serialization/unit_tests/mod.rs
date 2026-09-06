use serde::{Deserialize, Serialize};

use super::decimal_u64;

#[derive(Debug, Deserialize)]
struct Wrapper {
    #[serde(with = "decimal_u64")]
    value: u64,
}

#[test]
fn accepts_canonical_decimal_string() {
    let parsed: Wrapper = serde_json::from_str(r#"{"value":"18446744073709551615"}"#).unwrap();
    assert_eq!(parsed.value, u64::MAX);
}

#[test]
fn rejects_unsafe_legacy_json_number() {
    let error = serde_json::from_str::<Wrapper>(r#"{"value":9007199254740992}"#).unwrap_err();
    assert!(error.to_string().contains("MAX_SAFE_INTEGER"));
}

#[test]
fn rejects_noncanonical_decimal_string() {
    assert!(serde_json::from_str::<Wrapper>(r#"{"value":"01"}"#).is_err());
}

#[derive(Debug, Serialize)]
struct SerializeWrapper {
    #[serde(with = "decimal_u64")]
    value: u64,
}

#[test]
fn serializes_consensus_u64_as_decimal_string() {
    let encoded = serde_json::to_string(&SerializeWrapper { value: u64::MAX }).unwrap();
    assert_eq!(encoded, r#"{"value":"18446744073709551615"}"#);
}

#[test]
fn accepts_safe_legacy_integer_at_javascript_boundary() {
    let parsed: Wrapper = serde_json::from_str(r#"{"value":9007199254740991}"#).unwrap();
    assert_eq!(parsed.value, 9_007_199_254_740_991);
}

#[test]
fn rejects_empty_nondigit_and_overflow_decimal_strings_independently() {
    for encoded in [
        r#"{"value":""}"#,
        r#"{"value":"12x"}"#,
        r#"{"value":"18446744073709551616"}"#,
    ] {
        assert!(serde_json::from_str::<Wrapper>(encoded).is_err());
    }
}
