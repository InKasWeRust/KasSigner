#[test]
fn merkle_and_script_construction_helpers_have_direct_function_coverage() {
    let first = crate::account::address::encode_p2pk_address(&[0x11; 32], "kaspa");
    let second = crate::account::address::encode_p2pk_address(&[0x22; 32], "kaspa");
    let addresses = serde_json::to_string(&vec![first.clone(), second]).expect("addresses JSON");

    let root_json = crate::contracts::merkle::application::root_from_addresses(&addresses)
        .expect("merkle root");
    let root: serde_json::Value = serde_json::from_str(&root_json).expect("root JSON");
    let root_hex = root["root"].as_str().expect("root hex");
    assert_eq!(root_hex.len(), 64);

    let proof_json = crate::contracts::merkle::application::proof_for_address(&addresses, &first)
        .expect("merkle proof");
    let proof: serde_json::Value = serde_json::from_str(&proof_json).expect("proof JSON");
    assert_eq!(proof["leaf_index"].as_u64(), Some(0));

    let whitelist = crate::contracts::merkle::application::build_whitelist_json(
        &"33".repeat(32),
        root_hex,
        1,
        100,
        "kaspa",
    )
    .expect("whitelist covenant");
    assert!(whitelist.contains("redeem_script_hex"));

    let commit = crate::contracts::commit_reveal::script::build_commit_reveal_script(
        &[0x44; 32],
        &[0x55; 32],
        77,
    );
    assert!(!commit.is_empty());

    let escrow = crate::contracts::covenant::script::build_escrow_script(
        &[0x61; 32],
        &[0x62; 32],
        &[0x63; 32],
        &[0x20; 34],
        &[0x21; 34],
        &[0x64; 8],
    );
    assert!(!escrow.is_empty());

    let timed = crate::contracts::covenant::script::build_timelocked_escrow_script(
        &[0x71; 32],
        &[0x72; 32],
        &[0x20; 34],
        &[0x21; 34],
        1234,
    );
    assert!(!timed.is_empty());
}

#[test]
fn oracle_and_zk_helpers_have_direct_function_coverage() {
    let heartbeat = crate::contracts::oracle::genesis::build_heartbeat_json("kaspa")
        .expect("heartbeat covenant");
    assert!(heartbeat.contains("redeem_script_hex"));

    let total = crate::contracts::zk::proof::serialize_total(123).expect("field serialization");
    assert!(!total.is_empty());

    assert!(crate::contracts::zk::proof::verify_proof(&[], &[], &[]).is_err());

    let versioned = crate::contracts::zk::crowdfund::versioned_spk(&[0x51, 0xac]);
    assert_eq!(versioned, vec![0, 0, 0x51, 0xac]);

    assert!(crate::contracts::covenant::oracle_v1::verify_attestation("00", "00", "00").is_err());
}
