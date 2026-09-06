use crate::UtxoEntry;

use super::{fee::DepositFeePolicy, selection::select};

fn utxo(byte: u8, amount: u64) -> UtxoEntry {
    UtxoEntry {
        tx_id: format!("{byte:02x}").repeat(32),
        index: u32::from(byte),
        amount,
        script_public_key: vec![0x20; 34],
        block_daa_score: 0,
        covenant_id: None,
    }
}

#[test]
fn covenant_selection_handles_automatic_and_manual_fee_recalculation() {
    let policy = DepositFeePolicy::new(0, false);
    // One input cannot cover the send plus its calculated mass fee, while two can.
    let values = vec![utxo(1, 300_000), utxo(2, 300_000), utxo(3, 300_000)];
    let automatic = select(&values, 100_000, 1, "", policy).expect("automatic selection");
    assert!(!automatic.used_manual_selection);
    assert_eq!(automatic.selected.len(), 2);
    assert_eq!(automatic.total, 600_000);
    assert!(automatic.fee >= 100_000);
    assert_eq!(automatic.target, 100_000 + automatic.fee);

    let manual = select(&values, 50_000, 1, "2, 0", policy).expect("manual selection");
    assert!(manual.used_manual_selection);
    assert_eq!(manual.selected.len(), 2);
    assert_eq!(manual.total, 600_000);
    assert!(manual.fee >= 100_000);
    assert_eq!(manual.target, 50_000 + manual.fee);
}

#[test]
fn covenant_selection_rejects_ranges_and_checked_arithmetic_overflow() {
    let policy = DepositFeePolicy::new(32, true);
    let values = vec![utxo(1, u64::MAX), utxo(2, 1)];

    assert!(matches!(
        select(&values, 1, 1, "9", policy),
        Err(error) if error.contains("out of range")
    ));
    assert!(matches!(
        select(&values, u64::MAX, 1, "", policy),
        Err(error) if error.contains("monetary range")
    ));
    assert!(matches!(
        select(&values, 0, 0, "0,1", policy),
        Err(error) if error.contains("Selected UTXO total")
    ));
}

#[test]
fn deposit_fee_policy_accounts_for_payload_and_tagged_genesis_mass() {
    let plain = DepositFeePolicy::new(0, false)
        .calculate(1)
        .expect("fee calculation");
    let payload = DepositFeePolicy::new(512, false)
        .calculate(1)
        .expect("fee calculation");
    let tagged = DepositFeePolicy::new(0, true)
        .calculate(1)
        .expect("fee calculation");
    let more_inputs = DepositFeePolicy::new(0, false)
        .calculate(3)
        .expect("fee calculation");
    assert!(payload > plain);
    assert!(tagged >= plain);
    assert!(more_inputs > plain);
}

fn decode_covenant_wire(wire: &str) -> serde_json::Value {
    let envelope = hex::decode(wire).expect("outer wire hex");
    assert_eq!(&envelope[..4], b"PSKB");
    let json_hex = core::str::from_utf8(&envelope[4..]).expect("json hex");
    serde_json::from_slice(&hex::decode(json_hex).expect("json bytes")).expect("json")
}

#[test]
fn covenant_planning_covers_manual_adjustment_payload_and_genesis_policy() {
    use super::{
        builder::{encode_from_utxos, CovenantPlanInput},
        model::CovenantEncoding,
    };

    let covenant_script = [0x51, 0xac];
    let change_script = [0x20, 0x01, 0xac];
    let calculated_fee = DepositFeePolicy::new(2, false)
        .calculate(1)
        .expect("fee calculation");
    let manual = encode_from_utxos(
        CovenantPlanInput {
            send_amount: 200_000,
            fee: 1,
            dust_policy: super::model::CovenantDustPolicy::Preserve,
            utxo_indices_csv: "0",
            encoding: CovenantEncoding::Payload {
                payload_hex: "",
                tag_genesis: false,
            },
            covenant_script: &covenant_script,
            change_script: &change_script,
            payload: Some(&[0xaa, 0xbb]),
        },
        vec![utxo(1, calculated_fee + 50_000)],
    )
    .expect("manual selection adjusts to available amount");
    let document = decode_covenant_wire(&manual);
    assert_eq!(document[0]["outputs"][0]["amount"], "50000");
    assert_eq!(document[0]["global"]["txPayload"], "aabb");

    let tagged = encode_from_utxos(
        CovenantPlanInput {
            send_amount: 0,
            fee: 1,
            dust_policy: super::model::CovenantDustPolicy::Preserve,
            utxo_indices_csv: "",
            encoding: CovenantEncoding::Payload {
                payload_hex: "",
                tag_genesis: true,
            },
            covenant_script: &covenant_script,
            change_script: &change_script,
            payload: Some(&[]),
        },
        vec![utxo(2, 20_000_000)],
    )
    .expect("tagged genesis sweep");
    let document = decode_covenant_wire(&tagged);
    let amount = document[0]["outputs"][0]["amount"]
        .as_str()
        .expect("exact covenant amount must be a decimal string")
        .parse::<u64>()
        .expect("valid u64 covenant amount");
    assert!(amount >= 10_000_000);
    assert!(document[0]["outputs"][0]["covenantBinding"].is_object());
}

#[test]
fn covenant_planning_rejects_insufficient_small_and_invalid_genesis_funding() {
    use super::{
        builder::{encode_from_utxos, CovenantPlanInput},
        model::CovenantEncoding,
    };
    let script = [0x51];
    let base = |encoding, send_amount, csv| CovenantPlanInput {
        send_amount,
        fee: 1,
        dust_policy: super::model::CovenantDustPolicy::Preserve,
        utxo_indices_csv: csv,
        encoding,
        covenant_script: &script,
        change_script: &script,
        payload: None,
    };

    assert!(encode_from_utxos(
        base(
            CovenantEncoding::Payload {
                payload_hex: "",
                tag_genesis: false
            },
            1_000_000,
            ""
        ),
        vec![utxo(1, 100_000)],
    )
    .unwrap_err()
    .contains("Insufficient funds"));

    assert!(encode_from_utxos(
        base(
            CovenantEncoding::Payload {
                payload_hex: "",
                tag_genesis: true
            },
            1,
            ""
        ),
        vec![utxo(1, 500_000)],
    )
    .unwrap_err()
    .contains("too small"));

    assert!(encode_from_utxos(
        base(
            CovenantEncoding::Payload {
                payload_hex: "",
                tag_genesis: false
            },
            1,
            "0"
        ),
        vec![utxo(1, 500_000)],
    )
    .unwrap_err()
    .contains("requires payload bytes"));

    let mut bad = utxo(1, 20_000_000);
    bad.tx_id = "00".into();
    assert!(encode_from_utxos(
        base(CovenantEncoding::BoundGenesis, 10_000_000, ""),
        vec![bad],
    )
    .unwrap_err()
    .contains("txid not 32 bytes"));

    assert!(encode_from_utxos(
        base(CovenantEncoding::BoundGenesis, 10_000_000, ""),
        Vec::new(),
    )
    .is_err());
}

#[test]
fn covenant_request_preparation_covers_payload_bound_and_invalid_hex_paths() {
    use super::{
        builder::prepare_request,
        model::{CovenantBuildRequest, CovenantEncoding},
    };
    use crate::WalletData;

    let wallet = WalletData {
        kpub: String::new(),
        receive_addresses: Vec::new(),
        change_addresses: Vec::new(),
        next_receive_index: 0,
        next_change_index: 0,
    };
    let covenant_address = crate::account::address::encode_p2pk_address(&[0x61; 32], "kaspa");
    let change_address = crate::account::address::encode_p2pk_address(&[0x62; 32], "kaspa");
    fn request<'a>(
        wallet: &'a WalletData,
        covenant_address: &'a str,
        change_address: &'a str,
        encoding: CovenantEncoding<'a>,
    ) -> CovenantBuildRequest<'a> {
        CovenantBuildRequest {
            wallet,
            covenant_address,
            covenant_type: "",
            send_amount: 20_000_000,
            fee: 1_000,
            change_address,
            utxo_indices_csv: "",
            websocket_url: "ws://unused.invalid",
            encoding,
        }
    }

    let payload = request(
        &wallet,
        &covenant_address,
        &change_address,
        CovenantEncoding::Payload {
            payload_hex: "aabb",
            tag_genesis: false,
        },
    );
    assert!(prepare_request(&payload).is_ok());

    let bound = request(
        &wallet,
        &covenant_address,
        &change_address,
        CovenantEncoding::BoundGenesis,
    );
    assert!(prepare_request(&bound).is_ok());

    let invalid = request(
        &wallet,
        &covenant_address,
        &change_address,
        CovenantEncoding::Payload {
            payload_hex: "not-hex",
            tag_genesis: false,
        },
    );
    assert!(matches!(
        prepare_request(&invalid),
        Err(error) if error.contains("Bad payload hex")
    ));
}

#[test]
fn covenant_builder_boundary_rejects_invalid_addresses_before_network_io() {
    use super::{
        builder::build,
        model::{CovenantBuildRequest, CovenantEncoding},
    };
    use crate::{wasm_api::test_support::ready, WalletData};

    let wallet = WalletData {
        kpub: String::new(),
        receive_addresses: Vec::new(),
        change_addresses: Vec::new(),
        next_receive_index: 0,
        next_change_index: 0,
    };
    let request = CovenantBuildRequest {
        wallet: &wallet,
        covenant_address: "not-an-address",
        covenant_type: "",
        send_amount: 20_000_000,
        fee: 300_000,
        change_address: "not-an-address",
        utxo_indices_csv: "",
        websocket_url: "ws://unused",
        encoding: CovenantEncoding::BoundGenesis,
    };
    assert!(ready(build(request)).is_err());
}

#[test]
fn deposit_fee_policy_is_byte_mass_exact_across_payload_tag_and_input_boundaries() {
    assert_eq!(
        DepositFeePolicy::new(0, false)
            .calculate(0)
            .expect("fee calculation"),
        100_000
    );
    assert_eq!(
        DepositFeePolicy::new(0, false)
            .calculate(1)
            .expect("fee calculation"),
        222_985
    );
    assert_eq!(
        DepositFeePolicy::new(512, false)
            .calculate(1)
            .expect("fee calculation"),
        281_865
    );
    assert_eq!(
        DepositFeePolicy::new(0, true)
            .calculate(1)
            .expect("fee calculation"),
        226_665
    );
    assert_eq!(
        DepositFeePolicy::new(0, false)
            .calculate(3)
            .expect("fee calculation"),
        479_435
    );
    assert_eq!(
        DepositFeePolicy::new(32, true)
            .calculate(2)
            .expect("fee calculation"),
        358_570
    );
}

#[test]
fn covenant_fee_shape_preserves_p2sh_accounting_and_overflow_checks() {
    use super::fee::CovenantFeeShape;

    let plain = CovenantFeeShape {
        p2pk_inputs: 1,
        redeem_bytes: 0,
        payload_bytes: 0,
        binding_bytes: 0,
    }
    .calculate()
    .expect("plain fee");
    let p2sh = CovenantFeeShape {
        p2pk_inputs: 1,
        redeem_bytes: 64,
        payload_bytes: 0,
        binding_bytes: 0,
    }
    .calculate()
    .expect("p2sh fee");
    assert!(p2sh > plain);

    assert!(matches!(
        CovenantFeeShape {
            p2pk_inputs: 0,
            redeem_bytes: u64::MAX,
            payload_bytes: 0,
            binding_bytes: 0,
        }
        .calculate(),
        Err(error) if error.contains("P2SH input-byte estimate overflow")
    ));
}

#[test]
fn deposit_fee_policy_reports_overflow_instead_of_panicking() {
    assert!(matches!(
        DepositFeePolicy::new(u64::MAX, false).calculate(1),
        Err(error) if error.contains("overflow")
    ));
    assert!(matches!(
        DepositFeePolicy::new(0, false).calculate(u64::MAX),
        Err(error) if error.contains("overflow")
    ));
}

#[test]
fn covenant_adjustment_and_change_boundaries_are_amount_exact() {
    use super::{
        builder::{encode_from_utxos, CovenantPlanInput},
        model::CovenantEncoding,
    };

    let covenant_script = [0x51, 0xac];
    let change_script = [0x20, 0x01, 0xac];
    let input = |send_amount, fee, csv, encoding, payload| CovenantPlanInput {
        send_amount,
        fee,
        dust_policy: super::model::CovenantDustPolicy::Preserve,
        utxo_indices_csv: csv,
        encoding,
        covenant_script: &covenant_script,
        change_script: &change_script,
        payload,
    };

    let manual = encode_from_utxos(
        input(
            10_000_000,
            300_000,
            "0",
            CovenantEncoding::Payload {
                payload_hex: "",
                tag_genesis: false,
            },
            Some(&[]),
        ),
        vec![utxo(0x71, 10_200_000)],
    )
    .expect("manual shortfall adjusts send");
    let manual_doc = decode_covenant_wire(&manual);
    assert_eq!(manual_doc[0]["outputs"].as_array().unwrap().len(), 1);
    assert_eq!(manual_doc[0]["outputs"][0]["amount"], "9900000");

    assert!(encode_from_utxos(
        input(
            1_000_000,
            300_000,
            "0",
            CovenantEncoding::Payload {
                payload_hex: "",
                tag_genesis: false
            },
            Some(&[]),
        ),
        vec![utxo(0x72, 300_000)],
    )
    .unwrap_err()
    .contains("Insufficient funds"));

    assert!(encode_from_utxos(
        input(
            10_000_000,
            300_000,
            "",
            CovenantEncoding::Payload {
                payload_hex: "",
                tag_genesis: false
            },
            Some(&[]),
        ),
        vec![utxo(0x73, 10_200_000)],
    )
    .unwrap_err()
    .contains("Insufficient funds"));

    let change = encode_from_utxos(
        input(
            10_000_000,
            300_000,
            "",
            CovenantEncoding::Payload {
                payload_hex: "",
                tag_genesis: false,
            },
            Some(&[]),
        ),
        vec![utxo(0x74, 12_000_000)],
    )
    .expect("plain covenant change");
    let change_doc = decode_covenant_wire(&change);
    assert_eq!(change_doc[0]["outputs"].as_array().unwrap().len(), 2);
    assert_eq!(change_doc[0]["outputs"][0]["amount"], "10000000");
    assert_eq!(change_doc[0]["outputs"][1]["amount"], "1700000");
}

#[test]
fn tagged_genesis_policy_observes_zero_send_and_exact_floor_boundaries() {
    use super::{
        builder::{encode_from_utxos, CovenantPlanInput},
        model::CovenantEncoding,
    };

    let covenant_script = [0x51, 0xac];
    let change_script = [0x20, 0x01, 0xac];
    let tagged_fee = DepositFeePolicy::new(0, true)
        .calculate(1)
        .expect("fee calculation");
    let make = |send_amount, tag_genesis, total| {
        encode_from_utxos(
            CovenantPlanInput {
                send_amount,
                fee: 1,
                dust_policy: super::model::CovenantDustPolicy::Preserve,
                utxo_indices_csv: "",
                encoding: CovenantEncoding::Payload {
                    payload_hex: "",
                    tag_genesis,
                },
                covenant_script: &covenant_script,
                change_script: &change_script,
                payload: Some(&[]),
            },
            vec![utxo(0x75, total)],
        )
    };

    let exact = make(0, true, tagged_fee + 10_000_000).expect("exact tagged floor");
    let exact_doc = decode_covenant_wire(&exact);
    assert_eq!(exact_doc[0]["outputs"].as_array().unwrap().len(), 1);
    assert_eq!(exact_doc[0]["outputs"][0]["amount"], "10000000");

    assert!(make(0, true, tagged_fee + 9_999_999)
        .unwrap_err()
        .contains("too small"));

    let plain_fee = DepositFeePolicy::new(0, false)
        .calculate(1)
        .expect("fee calculation");
    let zero_plain = make(0, false, plain_fee + 10_000_000).expect("plain zero send");
    let zero_doc = decode_covenant_wire(&zero_plain);
    assert_eq!(zero_doc[0]["outputs"][0]["amount"], "0");
    assert_eq!(zero_doc[0]["outputs"][1]["amount"], "10000000");

    let tagged_nonzero = make(10_000_000, true, tagged_fee + 12_000_000)
        .expect("tagged nonzero send remains explicit");
    let tagged_doc = decode_covenant_wire(&tagged_nonzero);
    assert_eq!(tagged_doc[0]["outputs"][0]["amount"], "10000000");
    assert_eq!(tagged_doc[0]["outputs"][1]["amount"], "2000000");
}

#[test]
fn covenant_dust_policy_maps_only_explicit_fold_types() {
    use super::model::CovenantDustPolicy;

    for covenant_type in [
        "additive",
        "timelocked-savings",
        "dms",
        "global-spending-limit",
        "global-allowance",
    ] {
        assert_eq!(
            CovenantDustPolicy::for_type(covenant_type),
            CovenantDustPolicy::FoldSubKip9Change,
            "{covenant_type} must fold sub-KIP-9 manual change"
        );
    }

    for covenant_type in ["", "allowance", "crowdfund", "private-swap", "unknown"] {
        assert_eq!(
            CovenantDustPolicy::for_type(covenant_type),
            CovenantDustPolicy::Preserve,
            "{covenant_type} must preserve explicit change"
        );
    }
}

#[test]
fn covenant_dust_policy_folds_only_opted_in_manual_sub_kip9_change() {
    use super::{
        builder::{encode_from_utxos, CovenantPlanInput},
        model::{CovenantDustPolicy, CovenantEncoding},
    };

    let covenant_script = [0x51, 0xac];
    let change_script = [0x20, 0x01, 0xac];
    let fee = DepositFeePolicy::new(0, false)
        .calculate(1)
        .expect("fee calculation");
    let total = fee + 15_000_000;
    let build = |policy| {
        encode_from_utxos(
            CovenantPlanInput {
                send_amount: 10_000_000,
                fee: 1,
                dust_policy: policy,
                utxo_indices_csv: "0",
                encoding: CovenantEncoding::Payload {
                    payload_hex: "",
                    tag_genesis: false,
                },
                covenant_script: &covenant_script,
                change_script: &change_script,
                payload: Some(&[]),
            },
            vec![utxo(0x76, total)],
        )
    };

    let preserved = decode_covenant_wire(&build(CovenantDustPolicy::Preserve).expect("preserved"));
    assert_eq!(preserved[0]["outputs"].as_array().unwrap().len(), 2);
    assert_eq!(preserved[0]["outputs"][1]["amount"], "5000000");

    let folded =
        decode_covenant_wire(&build(CovenantDustPolicy::FoldSubKip9Change).expect("folded"));
    assert_eq!(folded[0]["outputs"].as_array().unwrap().len(), 1);
    assert_eq!(folded[0]["outputs"][0]["amount"], "15000000");
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn allowance_remote_boundary_is_host_exercised_and_fails_closed() {
    use super::allowance::build_remote;
    use crate::{account::address, wasm_api::test_support::ready};

    let covenant = address::encode_p2pk_address(&[0x43; 32], "kaspa");
    let destination = address::encode_p2pk_address(&[0x44; 32], "kaspa");
    assert!(matches!(
        ready(build_remote(
            &covenant,
            &destination,
            "51",
            20_000_000,
            1_000_000,
            "wss://host-coverage.invalid",
        )),
        Err(error) if error.contains("browser WebSocket transport is unavailable on native hosts")
    ));
}

#[test]
fn allowance_remote_result_composes_fetch_success_and_failure() {
    use super::allowance::build_remote_result;
    use crate::account::address;

    let covenant = address::encode_p2pk_address(&[0x41; 32], "kaspa");
    let destination = address::encode_p2pk_address(&[0x42; 32], "kaspa");
    let values = vec![utxo(10, 50_000_000)];

    let withdrawal = build_remote_result(
        Ok(values),
        &covenant,
        &destination,
        "51",
        20_000_000,
        1_000_000,
    )
    .expect("fetched allowance UTXOs compose into a withdrawal");
    assert_eq!(withdrawal.total_balance, 50_000_000);
    assert_eq!(withdrawal.return_amount, 29_000_000);

    assert!(matches!(
        build_remote_result(
            Err("transport failed".to_string()),
            &covenant,
            &destination,
            "51",
            20_000_000,
            1_000_000,
        ),
        Err(error) if error == "transport failed"
    ));
}

#[test]
fn allowance_prepare_material_covers_validation_error_paths() {
    use super::allowance::prepare_material;
    use crate::account::address;

    let covenant = address::encode_p2pk_address(&[0x51; 32], "kaspa");
    let destination = address::encode_p2pk_address(&[0x52; 32], "kaspa");
    let funded = [utxo(12, 50_000_000)];

    assert!(matches!(
        prepare_material(&covenant, &destination, "zz", 1, 0, &funded),
        Err(error) if error.contains("Bad redeem hex")
    ));
    assert!(matches!(
        prepare_material(&covenant, &destination, "51", u64::MAX, 1, &[utxo(13, u64::MAX)]),
        Err(error) if error.contains("overflows u64")
    ));
    assert!(matches!(
        prepare_material(
            &covenant,
            &destination,
            "51",
            1,
            0,
            &[utxo(14, u64::MAX), utxo(15, 1)],
        ),
        Err(error) if error.contains("balance overflows u64")
    ));
    assert!(prepare_material("not-an-address", &destination, "51", 1, 0, &funded).is_err());
    assert!(prepare_material(&covenant, "not-an-address", "51", 1, 0, &funded).is_err());
}

#[test]
fn allowance_prepare_material_has_host_native_coverage() {
    use super::allowance::prepare_material;
    use crate::account::address;

    let covenant = address::encode_p2pk_address(&[0x31; 32], "kaspa");
    let destination = address::encode_p2pk_address(&[0x32; 32], "kaspa");
    let values = [utxo(9, 50_000_000)];

    assert!(prepare_material(
        &covenant,
        &destination,
        "51",
        20_000_000,
        1_000_000,
        &values,
    )
    .is_ok());

    assert!(prepare_material(&covenant, &destination, "51", 1, 1, &[]).is_err());
    assert!(matches!(
        prepare_material(
            &covenant,
            &destination,
            "51",
            49_500_000,
            1_000_000,
            &values,
        ),
        Err(error) if error.contains("total balance")
    ));
    assert!(matches!(
        prepare_material(
            &covenant,
            &destination,
            "51",
            49_000_001,
            0,
            &values,
        ),
        Err(error) if error.contains("too small")
    ));
}
