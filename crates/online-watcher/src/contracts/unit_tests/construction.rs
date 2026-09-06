use crate::contracts::{
    covenant::script::{
        build_oracle_v1_covenant_script, build_piggy_bank_script, build_timelocked_savings_script,
        oracle_v1_script_commits_to, ORACLE_V1_SIG_OP_COUNT,
    },
    crowdfund::script::{
        crowdfund_campaign_id, crowdfund_redeem_script, CrowdfundScript,
        CROWDFUND_MAX_SWEEP_FEE_SOMPI, CROWDFUND_SIG_OP_COUNT,
    },
    merkle::script::build_merkle_whitelist_script,
    seq_commit::stamp_stealth_proof,
    vault::script::{build_split_vault_script, build_tagged_vault_script, compute_covenant_id},
    zk::cost::{
        groth16_script_units, groth16_sig_op_count, GROTH16_SIG_OP_COUNT, RISC0_SIG_OP_COUNT,
    },
};

#[test]
fn critical_contract_script_builders_and_costs_are_covered() {
    let owner = [0x11; 32];
    let root = [0x22; 32];
    let merkle_zero = build_merkle_whitelist_script(&owner, &root, 0, 100);
    let merkle_three = build_merkle_whitelist_script(&owner, &root, 3, 100);
    assert!(merkle_three.len() > merkle_zero.len());
    assert_eq!(merkle_zero.last(), Some(&0x68));

    let tagged = build_tagged_vault_script(&owner);
    let split = build_split_vault_script(&owner);
    assert!(!tagged.is_empty());
    assert!(split.len() > tagged.len());
    assert_eq!(
        tagged
            .iter()
            .filter(|&&opcode| opcode == crate::protocol::script::opcode::OP_CHECKSIGVERIFY)
            .count(),
        1,
        "tagged vault must contain exactly one signature-check opcode",
    );

    assert_eq!(
        RISC0_SIG_OP_COUNT,
        u8::MAX,
        "RISC0-backed contract verification must retain its conservative sig-op cost",
    );

    let beneficiary = [0x33; 32];
    let oracle = [0x44; 32];
    let commitment = [0x55; 32];
    let oracle_script = build_oracle_v1_covenant_script(
        &owner,
        &beneficiary,
        &oracle,
        &commitment,
        123_456,
        &[0x66; 16],
    );
    assert_eq!(oracle_script.first(), Some(&0x10));
    assert!(oracle_v1_script_commits_to(
        &oracle_script,
        &commitment,
        &oracle
    ));
    let mut noncanonical_oracle = oracle_script.clone();
    noncanonical_oracle.insert(noncanonical_oracle.len() - 1, 0x51);
    assert!(
        crate::contracts::covenant::script::oracle_v1_attestation_binding(&noncanonical_oracle)
            .is_none()
    );
    assert_eq!(
        oracle_script
            .iter()
            .filter(|&&opcode| opcode == crate::protocol::script::opcode::OP_CHECKSIGFROMSTACK)
            .count(),
        1,
        "Oracle-v1 must contain exactly one fixed-message oracle signature check",
    );
    assert_eq!(ORACLE_V1_SIG_OP_COUNT, 2);
    assert!(
        !oracle_script.contains(&crate::protocol::script::opcode::OP_TX_INPUT_SPK),
        "oracle role must not have a covenant-spend heartbeat branch"
    );

    let contributor = [0x71; 32];
    let vk_hash = [0x72; 32];
    let mut organizer_spk = vec![0, 0, 0x20];
    organizer_spk.extend_from_slice(&[0x73; 32]);
    organizer_spk.push(crate::protocol::script::opcode::OP_CHECKSIG);
    let crowdfund = crowdfund_redeem_script(CrowdfundScript {
        contributor_pubkey: &contributor,
        goal_sompi: 100_000_000,
        locktime_daa: 654_321,
        verifying_key_hash: &vk_hash,
        organizer_output_spk: &organizer_spk,
        salt: &[0x74; 8],
    })
    .expect("crowdfunding script");
    for opcode in [
        crate::protocol::script::opcode::OP_ZK_PRECOMPILE,
        crate::protocol::script::opcode::OP_TX_INPUT_COUNT,
        crate::protocol::script::opcode::OP_TX_INPUT_AMOUNT,
        crate::protocol::script::opcode::OP_TX_OUTPUT_COUNT,
        crate::protocol::script::opcode::OP_TX_OUTPUT_SPK,
    ] {
        assert!(
            crowdfund.contains(&opcode),
            "crowdfunding script must retain transaction/proof invariant opcode {opcode:#x}"
        );
    }
    assert!(
        crowdfund.contains(&crate::protocol::script::opcode::OP_TX_INPUT_SCRIPT_SIG_SUBSTR),
        "Crowdfunding sweep must inspect every input's campaign fingerprint"
    );
    assert!(
        crowdfund.contains(&crate::protocol::script::opcode::OP_TX_INPUT_SCRIPT_SIG_LEN),
        "Crowdfunding sweep must locate the canonical redeem-script tail"
    );
    assert!(
        !crowdfund.contains(&crate::protocol::script::opcode::OP_CHECKSIGFROMSTACK),
        "Crowdfunding sweep must not contain a wallet/raw-hash signature check"
    );
    let campaign_id = crowdfund_campaign_id(100_000_000, 654_321, &vk_hash, &organizer_spk);
    assert_eq!(
        &crowdfund[crowdfund.len() - 34..crowdfund.len() - 2],
        campaign_id.as_slice()
    );
    assert_ne!(
        campaign_id,
        crowdfund_campaign_id(100_000_001, 654_321, &vk_hash, &organizer_spk)
    );
    assert_ne!(
        campaign_id,
        crowdfund_campaign_id(100_000_000, 654_322, &vk_hash, &organizer_spk)
    );
    let mut other_spk = organizer_spk.clone();
    other_spk[2] ^= 1;
    assert_ne!(
        campaign_id,
        crowdfund_campaign_id(100_000_000, 654_321, &vk_hash, &other_spk)
    );
    const { assert!(CROWDFUND_MAX_SWEEP_FEE_SOMPI > 0) };
    assert_eq!(CROWDFUND_SIG_OP_COUNT, GROTH16_SIG_OP_COUNT);
    assert_eq!(GROTH16_SIG_OP_COUNT, groth16_sig_op_count(1));
    assert!(groth16_script_units(1) > 0);
}

#[test]
fn crowdfund_configuration_validation_boundaries_are_covered() {
    let contributor = [0x81; 32];
    let vk_hash = [0x82; 32];
    let salt = [0x83; 8];
    let valid_spk = [0x84; 35];

    let build = |goal_sompi, locktime_daa, organizer_output_spk: &[u8], salt: &[u8; 8]| {
        crowdfund_redeem_script(CrowdfundScript {
            contributor_pubkey: &contributor,
            goal_sompi,
            locktime_daa,
            verifying_key_hash: &vk_hash,
            organizer_output_spk,
            salt,
        })
    };

    assert!(build(0, 1, &valid_spk, &salt).is_err());
    assert!(build(1, 0, &valid_spk, &salt).is_err());
    assert!(build(1, 1, &[0; 2], &salt).is_err());
    assert!(build(1, 1, &[0; 261], &salt).is_err());
    assert!(build(1, 1, &valid_spk, &[0; 8]).is_err());
}

#[test]
fn groth16_sig_op_count_saturates_at_u8_max() {
    assert_eq!(groth16_sig_op_count(44), 253);
    assert_eq!(groth16_sig_op_count(45), u8::MAX);
}

#[test]
fn vault_covenant_identity_is_deterministic_and_binds_funding_output() {
    let owner = [0x11; 32];
    let covenant_script = build_tagged_vault_script(&owner);
    let first = compute_covenant_id(&[1; 32], 1, &[(0, 80_000, 0, covenant_script.as_slice())]);
    let repeated = compute_covenant_id(&[1; 32], 1, &[(0, 80_000, 0, covenant_script.as_slice())]);
    assert_eq!(first, repeated);
    assert_ne!(
        first,
        compute_covenant_id(&[2; 32], 1, &[(0, 80_000, 0, covenant_script.as_slice())]),
        "funding transaction ID must bind the covenant identity",
    );
    assert_ne!(
        first,
        compute_covenant_id(&[1; 32], 1, &[(0, 80_001, 0, covenant_script.as_slice())]),
        "genesis amount must bind the covenant identity",
    );
}

#[test]
fn savings_scripts_cover_unconditional_goal_deadline_and_recovery_layouts() {
    let owner = [0x61u8; 32];
    let recovery = [0x62u8; 32];
    let salt = [0x63u8; 8];

    let unconditional = build_piggy_bank_script(&owner, 0, 0, &salt);
    let goal_only = build_piggy_bank_script(&owner, 50_000_000, 0, &salt);
    let deadline_only = build_piggy_bank_script(&owner, 0, 123_456, &salt);
    let both = build_piggy_bank_script(&owner, 50_000_000, 123_456, &salt);
    assert!(goal_only.len() > unconditional.len());
    assert!(deadline_only.len() > unconditional.len());
    assert!(both.len() >= goal_only.len());
    assert_eq!(&unconditional[1..9], salt.as_slice());
    assert!(deadline_only
        .windows(2)
        .any(|window| window == [0x00, 0x67]));
    assert!(goal_only.windows(2).any(|window| window == [0x00, 0x68]));

    let timelocked = build_timelocked_savings_script(&owner, &recovery, 123_456);
    assert!(timelocked.windows(32).any(|window| window == owner));
    assert!(timelocked.windows(32).any(|window| window == recovery));
    assert_eq!(timelocked.last(), Some(&0x68));
}

#[test]
fn stealth_sequence_commit_proof_rejects_invalid_transaction_wire() {
    assert!(stamp_stealth_proof("00", &[0x71u8; 32], 0x72).is_err());
}

#[test]
fn browser_neutral_contract_constructors_cover_direct_success_paths() {
    use crate::contracts::{
        commit_reveal::application as commit_reveal_app,
        covenant::{construction, oracle_v1},
        zk::crowdfund as zk_crowdfund,
    };

    // Deterministic valid secp256k1 x-only public keys for 1G, 2G, and 3G.
    // These exercise constructors that perform real x-only key validation rather
    // than relying on arbitrary 32-byte placeholders that may not lie on-curve.
    let owner = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_owned();
    let beneficiary = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5".to_owned();
    let third = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9".to_owned();
    let commitment = "44".repeat(32);
    let address_a = crate::account::address::encode_p2pk_address(&[0x51; 32], "kaspa");
    let address_b = crate::account::address::encode_p2pk_address(&[0x52; 32], "kaspa");

    let documents = [
        construction::additive::build_json(&owner, 1, 2, "kaspa"),
        construction::allowance::build_local_json(&owner, &beneficiary, 1, 2, 3, "kaspa"),
        construction::allowance::build_global_json(&owner, &beneficiary, 1, 2, 3, "kaspa"),
        construction::dms::build_json(&owner, &beneficiary, 10, "kaspa"),
        construction::escrow::build_json(
            &owner,
            &beneficiary,
            &third,
            &address_a,
            &address_b,
            "kaspa",
            [0x61; 8],
        ),
        construction::escrow::build_random_json(
            &owner,
            &beneficiary,
            &third,
            &address_a,
            &address_b,
            "kaspa",
        ),
        construction::escrow::build_timelocked_json(
            &owner,
            &beneficiary,
            &address_a,
            &address_b,
            10,
            "kaspa",
        ),
        construction::payjoin::build_json(&owner, &beneficiary, 10, 2, 2, "kaspa"),
        construction::private_swap::build_json(
            &owner,
            &beneficiary,
            &address_a,
            10,
            &"71".repeat(16),
            "kaspa",
        ),
        construction::savings::build_json(&owner, &beneficiary, 10, "kaspa"),
        construction::spending_limit::build_global_json(&owner, 1, 2, "kaspa"),
        commit_reveal_app::build_json(&owner, &commitment, 10, "kaspa"),
        oracle_v1::build_json(
            &owner,
            &beneficiary,
            &third,
            &commitment,
            "release when condition is met",
            10,
            "kaspa",
        ),
        zk_crowdfund::build_address_json(&owner, &address_a, 100_000_000, 10, "abcd", "kaspa"),
    ];

    for document in documents {
        let document = document.expect("browser-neutral constructor");
        let parsed: serde_json::Value = serde_json::from_str(&document).expect("constructor JSON");
        assert!(parsed
            .get("address")
            .and_then(serde_json::Value::as_str)
            .is_some());
    }
}
