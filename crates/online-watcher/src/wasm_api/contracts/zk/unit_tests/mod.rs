use serde_json::json;

fn address(byte: u8) -> String {
    crate::account::address::encode_p2pk_address(&[byte; 32], "kaspa")
}

fn utxo(byte: u8, amount: u64) -> crate::account::utxo::UtxoEntry {
    crate::account::utxo::UtxoEntry {
        tx_id: format!("{byte:02x}").repeat(32),
        index: u32::from(byte),
        amount,
        script_public_key: Vec::new(),
        block_daa_score: 0,
        covenant_id: None,
    }
}

#[test]
fn commit_reveal_builders_cover_valid_requests_and_malformed_hex() {
    let json = super::commit_reveal::build_commit_reveal_json(
        &"11".repeat(32),
        &"22".repeat(32),
        99,
        "testnet-12",
    )
    .unwrap();
    let document: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(document["address"]
        .as_str()
        .unwrap()
        .starts_with("kaspatest:"));
    assert_eq!(document["locktime_daa"], "99");
    assert!(
        super::commit_reveal::build_commit_reveal_json("00", &"22".repeat(32), 0, "mainnet")
            .is_err()
    );
    assert!(
        super::commit_reveal::build_commit_reveal_json(&"11".repeat(32), "00", 0, "mainnet")
            .is_err()
    );

    let request = json!({
        "covenant_address": address(3),
        "dest_address": address(4),
        "redeem_script_hex": "51",
        "part_a_hex": "aa",
        "part_b_hex": "bb",
        "payload_hex": "cc",
        "fee": "7",
        "ws_url": "ws://unused"
    })
    .to_string();
    let parsed = super::commit_reveal::parse_commit_reveal_spend(&request).unwrap();
    assert_eq!(parsed.fee, 7);
    assert_eq!(parsed.redeem_script, vec![0x51]);
    assert_eq!(parsed.payload, vec![0xcc]);

    for (field, value) in [
        ("redeem_script_hex", "zz"),
        ("part_a_hex", "zz"),
        ("part_b_hex", "zz"),
        ("payload_hex", "zz"),
        ("fee", "not-a-number"),
    ] {
        let mut document: serde_json::Value = serde_json::from_str(&request).unwrap();
        document[field] = json!(value);
        assert!(super::commit_reveal::parse_commit_reveal_spend(&document.to_string()).is_err());
    }
}

fn p2sh_address(script: &[u8]) -> String {
    crate::protocol::script::p2sh::script_to_address(script, "kaspa").unwrap()
}

#[test]
fn merkle_spend_planning_covers_selection_change_and_validation() {
    let redeem = vec![0x51];
    let covenant = p2sh_address(&redeem);
    let destination = address(8);
    let proof = json!([
        {"sibling": "11".repeat(32), "direction": 0},
        {"sibling": "22".repeat(32), "direction": 1}
    ])
    .to_string();
    let mut request = super::merkle::MerkleSpendRequest {
        covenant_address: &covenant,
        destination_address: &destination,
        redeem_script_hex: "51",
        proof_json: &proof,
        send_amount: 10,
        requested_fee: 1,
        utxos: vec![
            utxo(1, 1_000_000),
            utxo(2, 900_000),
            utxo(3, 800_000),
            utxo(4, 700_000),
            utxo(5, 1),
        ],
    };
    let prepared = super::merkle::build_merkle_whitelist_spend(&mut request).unwrap();
    assert_eq!(request.utxos.len(), 4);
    assert_eq!(
        request.utxos.iter().map(|utxo| utxo.amount).sum::<u64>(),
        3_400_000,
    );
    assert!(!prepared.wire.is_empty());

    for (send_amount, fee, utxos, proof_json, redeem_hex) in [
        (0, 0, vec![utxo(1, 100)], proof.as_str(), "51"),
        (100, u64::MAX, vec![utxo(1, 100)], proof.as_str(), "51"),
        (1, 0, Vec::new(), proof.as_str(), "51"),
        (1, 0, vec![utxo(1, 100)], "not-json", "51"),
        (1, 0, vec![utxo(1, 100)], proof.as_str(), "zz"),
    ] {
        let mut bad = super::merkle::MerkleSpendRequest {
            covenant_address: &covenant,
            destination_address: &destination,
            redeem_script_hex: redeem_hex,
            proof_json,
            send_amount,
            requested_fee: fee,
            utxos,
        };
        assert!(super::merkle::build_merkle_whitelist_spend(&mut bad).is_err());
    }

    let mut overflow = super::merkle::MerkleSpendRequest {
        covenant_address: &covenant,
        destination_address: &destination,
        redeem_script_hex: "51",
        proof_json: &proof,
        send_amount: 1,
        requested_fee: 0,
        utxos: vec![utxo(1, u64::MAX), utxo(2, 1)],
    };
    assert!(super::merkle::build_merkle_whitelist_spend(&mut overflow).is_err());
}

#[test]
fn zk_wasm_boundaries_cover_hash_merkle_and_commit_reveal() {
    let owner = "31".repeat(32);
    let committed = super::hashes::commit_hash("abcd").expect("commit hash");
    assert_eq!(committed.len(), 64);

    let addresses = vec![address(0x41), address(0x42), address(0x43)];
    let addresses_json = serde_json::to_string(&addresses).unwrap();
    let root_json = super::merkle::merkle_root_from_addresses(&addresses_json).expect("root");
    let root_doc: serde_json::Value = serde_json::from_str(&root_json).unwrap();
    let root = root_doc["root"].as_str().unwrap();
    assert_eq!(root.len(), 64);
    assert_eq!(root_doc["depth"], 2);
    assert_eq!(root_doc["leaf_count"], 3);
    let proof =
        super::merkle::merkle_proof_for_address(&addresses_json, &addresses[1]).expect("proof");
    assert!(proof.contains("sibling"));
    assert!(
        super::merkle::covenant_merkle_whitelist(&owner, root, 2, 77, "mainnet")
            .unwrap()
            .contains("redeem_script_hex")
    );

    assert!(
        super::commit_reveal::covenant_commit_reveal(&owner, &committed, 88, "mainnet")
            .unwrap()
            .contains("locktime_daa")
    );
}

#[test]
fn crowdfunding_proof_round_trip_and_transaction_constraints_are_native_testable() {
    use crate::{
        account::{address as account_address, utxo::UtxoEntry},
        protocol::script::p2sh,
    };

    let (pk, vk) = crate::contracts::zk::proof::crowdfund_trusted_setup().expect("crowdfund setup");
    assert!(crate::contracts::zk::proof::crowdfund_generate_proof(&pk, &[]).is_err());
    assert!(crate::contracts::zk::proof::crowdfund_generate_proof(&pk, &[1; 9]).is_err());
    assert!(crate::contracts::zk::proof::crowdfund_generate_proof(&pk, &[u64::MAX, 1]).is_err());
    let (max_proof, max_public, max_total) =
        crate::contracts::zk::proof::crowdfund_generate_proof(&pk, &[1; 8])
            .expect("exact maximum contributor proof");
    assert_eq!(max_total, 8);
    assert!(
        crate::contracts::zk::proof::verify_proof(&vk, &max_proof, &max_public)
            .expect("max proof verification")
    );
    let proof_json = super::crowdfund::build_proof_json(
        &hex::encode(&pk),
        &hex::encode(&vk),
        r#"["70000000","50000000"]"#,
    )
    .expect("crowdfund proof");
    let proof_doc: serde_json::Value = serde_json::from_str(&proof_json).unwrap();
    assert_eq!(proof_doc["total_sompi"], "120000000");
    assert_eq!(proof_doc["verified"], true);
    assert!(
        super::crowdfund::build_proof_json(&hex::encode(&pk), &hex::encode(&vk), "[1]").is_err(),
        "consensus quantities must enter the browser proof boundary as exact decimal strings"
    );

    let contributor = "81".repeat(32);
    let organizer = account_address::encode_p2pk_address(&[0x82; 32], "kaspa");
    let campaign_json = super::crowdfund::build_crowdfund_address_json(
        &contributor,
        &organizer,
        100_000_000,
        123_456,
        &hex::encode(&vk),
        "mainnet",
    )
    .expect("crowdfund address");
    let campaign: serde_json::Value = serde_json::from_str(&campaign_json).unwrap();
    let expected_campaign_id = super::crowdfund::compute_campaign_id_hex(
        &organizer,
        100_000_000,
        123_456,
        &hex::encode(&vk),
    )
    .expect("campaign identity");
    assert_eq!(campaign["campaign_id"], expected_campaign_id);
    let second_campaign_json = super::crowdfund::build_crowdfund_address_json(
        &contributor,
        &organizer,
        100_000_000,
        123_456,
        &hex::encode(&vk),
        "mainnet",
    )
    .expect("second crowdfund address");
    let second_campaign: serde_json::Value = serde_json::from_str(&second_campaign_json).unwrap();
    assert_eq!(
        second_campaign["campaign_id"], expected_campaign_id,
        "contributor-specific salts must not split one campaign identity"
    );
    let address = campaign["address"].as_str().unwrap().to_string();
    let redeem = campaign["redeem_script_hex"].as_str().unwrap().to_string();
    let salt = campaign["crowdfund_salt_hex"].as_str().unwrap().to_string();
    let spk = account_address::address_to_script_pubkey(&address).unwrap();
    let contribution = super::crowdfund::ContributionRef {
        address: address.clone(),
        contributor_pubkey_hex: contributor,
        redeem_script_hex: redeem,
        crowdfund_salt_hex: salt,
    };
    let utxo = UtxoEntry {
        tx_id: "83".repeat(32),
        index: 0,
        amount: 120_000_000,
        script_public_key: spk,
        block_daa_score: 0,
        covenant_id: None,
    };
    let contributions_json = serde_json::to_string(&vec![serde_json::json!({
        "address": contribution.address,
        "contributor_pubkey_hex": contribution.contributor_pubkey_hex,
        "redeem_script_hex": contribution.redeem_script_hex,
        "crowdfund_salt_hex": contribution.crowdfund_salt_hex,
    })])
    .unwrap();
    let public_input = proof_doc["public_input_hex"].as_str().unwrap();
    let vk_hex = hex::encode(&vk);
    let request = super::crowdfund::CrowdfundSweepRequest {
        contributions_json: &contributions_json,
        organizer_address: &organizer,
        goal_sompi: 100_000_000,
        locktime_daa: 123_456,
        verifying_key_hex: &vk_hex,
        proof_hex: proof_doc["proof_hex"].as_str().unwrap(),
        public_input_hex: public_input,
        requested_fee: 400_000,
        fetched: vec![(contribution, vec![utxo])],
    };
    let transaction = super::crowdfund::prepare_crowdfund_sweep(request).expect("crowdfund sweep");
    assert_eq!(transaction.inputs.len(), 1);
    assert_eq!(transaction.outputs.len(), 1);
    assert_eq!(
        transaction.outputs[0].spk_script,
        account_address::address_to_script_pubkey(&organizer).unwrap()
    );
    assert!(transaction.outputs[0].value < 120_000_000);
    assert_eq!(p2sh::blake2b_hash(&vk).len(), 32);
}
