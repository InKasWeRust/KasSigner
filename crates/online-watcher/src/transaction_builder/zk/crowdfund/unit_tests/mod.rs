use super::*;
use crate::wasm_api::test_support::ready;

fn contribution(address: String, redeem: &str) -> ContributionRef {
    ContributionRef {
        address,
        contributor_pubkey_hex: "11".repeat(32),
        redeem_script_hex: redeem.to_string(),
        crowdfund_salt_hex: "22".repeat(8),
    }
}

fn contribution_json(count: usize) -> String {
    serde_json::to_string(
        &(0..count)
            .map(|index| {
                serde_json::json!({
                    "address": format!("kaspa:item{index}"),
                    "contributor_pubkey_hex": "11".repeat(32),
                    "redeem_script_hex": "51",
                    "crowdfund_salt_hex": "22".repeat(8),
                })
            })
            .collect::<Vec<_>>(),
    )
    .unwrap()
}

fn invalid_request<'a>(json: &'a str) -> CrowdfundSweepRequest<'a> {
    CrowdfundSweepRequest {
        contributions_json: json,
        organizer_address: "bad",
        goal_sompi: 1,
        locktime_daa: 1,
        verifying_key_hex: "00",
        proof_hex: "00",
        public_input_hex: "00",
        requested_fee: 1,
        fetched: Vec::new(),
    }
}

#[test]
fn crowdfund_async_entrypoints_preserve_validation_errors() {
    assert!(ready(inspect_crowdfund_contributions_string(
        "not-json",
        "ws://unused"
    ))
    .is_err());
    assert!(ready(create_crowdfund_sweep_string(
        "not-json",
        "bad",
        1,
        1,
        "00",
        "00",
        "00",
        1,
        "ws://unused"
    ))
    .is_err());
    assert!(ready(submit_crowdfund_sweep(
        invalid_request("not-json"),
        "ws://unused"
    ))
    .is_err());
    assert!(ready(fetch_contributions_json("not-json", "ws://unused")).is_err());
    #[cfg(not(target_arch = "wasm32"))]
    assert!(ready(fetch_contributions(
        &[contribution("kaspa:invalid".into(), "51")],
        "ws://unused"
    ))
    .is_err());
}

#[test]
fn canonical_contribution_checks_address_and_redeem_independently() {
    let canonical = [0x51];
    let address = crate::protocol::script::p2sh::script_to_address(&canonical, "kaspa").unwrap();
    assert!(validate_canonical_contribution(&contribution(address, "52"), &canonical).is_err());
    let other = crate::protocol::script::p2sh::script_to_address(&[0x52], "kaspa").unwrap();
    assert!(validate_canonical_contribution(&contribution(other, "51"), &canonical).is_err());
}

#[test]
fn contribution_count_sweep_totals_fee_and_hex_boundaries_are_exact() {
    assert!(parse_contributions("[]").is_err());
    assert_eq!(
        parse_contributions(&contribution_json(CROWDFUND_MAX_CONTRIBUTORS))
            .unwrap()
            .len(),
        CROWDFUND_MAX_CONTRIBUTORS
    );
    assert!(parse_contributions(&contribution_json(CROWDFUND_MAX_CONTRIBUTORS + 1)).is_err());
    let duplicate = serde_json::json!([
        {"address":"kaspa:x","contributor_pubkey_hex":"11","redeem_script_hex":"51","crowdfund_salt_hex":"22"},
        {"address":"kaspa:x","contributor_pubkey_hex":"11","redeem_script_hex":"51","crowdfund_salt_hex":"22"}
    ]).to_string();
    assert!(parse_contributions(&duplicate).is_err());

    let total = 100u64;
    let public = proof::serialize_total(total).unwrap();
    assert_eq!(validate_sweep_totals(total, total, 1, &public), Ok(()));
    let below = proof::serialize_total(total - 1).unwrap();
    assert!(validate_sweep_totals(total - 1, total, 1, &below).is_err());
    assert!(validate_sweep_totals(total, total, 0, &public).is_err());
    assert_eq!(
        validate_sweep_totals(total, total, CROWDFUND_MAX_TX_INPUTS as usize, &public),
        Ok(())
    );
    assert!(
        validate_sweep_totals(total, total, CROWDFUND_MAX_TX_INPUTS as usize + 1, &public).is_err()
    );

    let expected_floor = cost::groth16_min_fee_sompi(1).checked_mul(12).unwrap() / 10;
    assert_eq!(calculate_fee(0, 1), Ok(expected_floor));
    assert_eq!(
        calculate_fee(CROWDFUND_MAX_SWEEP_FEE_SOMPI, 1),
        Ok(CROWDFUND_MAX_SWEEP_FEE_SOMPI)
    );
    assert!(calculate_fee(CROWDFUND_MAX_SWEEP_FEE_SOMPI + 1, 1).is_err());

    assert_eq!(
        decode_hex_bounded("aabb", "field", 2).unwrap(),
        vec![0xaa, 0xbb]
    );
    assert!(decode_hex_bounded("aabbcc", "field", 2).is_err());
}
