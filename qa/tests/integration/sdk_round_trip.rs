use kassigner_sdk::{
    attach_input_derivation, complete, finalize, prepare, AddressBranch, Network, SdkErrorKind,
    SigningRequest,
};
use offline_signer::{
    derivation::bip32::{derive_account_key, derive_address_key},
    transaction::{
        kspt::{
            parse_compact_kspt, serialize_compact_kspt_vec,
            sign_transaction_account_multi_addr_with_entropy, PsktError,
        },
        model::{SigHashType, Transaction},
    },
};
use serde_json::{json, Value};

#[test]
fn sdk_round_trip_uses_actual_offline_signer_at_high_derivation_index() {
    let seed = [0x31u8; 64];
    let account = derive_account_key(&seed).expect("account");
    let child = derive_address_key(&account, 500).expect("receive child 500");
    let original = attach_input_derivation(
        &pskb(child.public_key_x_only().expect("x-only key"), 0x77),
        0,
        AddressBranch::Receive,
        500,
    )
    .expect("attach derivation");
    let request = prepare(&original, Network::Mainnet).expect("SDK prepare");
    let signed_hex = sign_request(&request, &account).expect("offline signing");
    let signed = complete(&request, &signed_hex).expect("SDK complete");
    let finalized: Value = serde_json::from_str(&finalize(&signed).expect("SDK finalize")).expect("JSON");
    assert!(!finalized["inputs"][0]["signatureScript"].as_str().unwrap_or_default().is_empty());
}

#[test]
fn sdk_offline_signer_rejects_wrong_derivation_hint() {
    let seed = [0x41u8; 64];
    let account = derive_account_key(&seed).expect("account");
    let child = derive_address_key(&account, 500).expect("receive child 500");
    let original = attach_input_derivation(
        &pskb(child.public_key_x_only().expect("x-only key"), 0x78),
        0,
        AddressBranch::Receive,
        499,
    )
    .expect("wrong derivation");
    assert_signer_refuses(&prepare(&original, Network::Mainnet).expect("request"), &account);
}

#[test]
fn sdk_offline_signer_rejects_right_index_for_wrong_pubkey() {
    let seed = [0x51u8; 64];
    let account = derive_account_key(&seed).expect("account");
    let wrong_child = derive_address_key(&account, 499).expect("receive child 499");
    let original = attach_input_derivation(
        &pskb(wrong_child.public_key_x_only().expect("x-only key"), 0x79),
        0,
        AddressBranch::Receive,
        500,
    )
    .expect("derivation");
    assert_signer_refuses(&prepare(&original, Network::Mainnet).expect("request"), &account);
}

#[test]
fn sdk_complete_rejects_response_from_different_transaction() {
    let seed = [0x61u8; 64];
    let account = derive_account_key(&seed).expect("account");
    let child = derive_address_key(&account, 12).expect("child");
    let key = child.public_key_x_only().expect("x-only key");
    let first = attach_input_derivation(&pskb(key, 0x81), 0, AddressBranch::Receive, 12).expect("first");
    let second = attach_input_derivation(&pskb(key, 0x82), 0, AddressBranch::Receive, 12).expect("second");
    let first_request = prepare(&first, Network::Mainnet).expect("first request");
    let second_request = prepare(&second, Network::Mainnet).expect("second request");
    let second_response = sign_request(&second_request, &account).expect("second response");
    assert_eq!(
        complete(&first_request, &second_response).unwrap_err().kind(),
        SdkErrorKind::TransactionMismatch,
    );
}

fn assert_signer_refuses(
    request: &SigningRequest,
    account: &offline_signer::derivation::bip32::ExtendedPrivKey,
) {
    let wire = hex::decode(&request.kspt_hex).expect("KSPT hex");
    let mut transaction = Transaction::try_new().expect("transaction allocation");
    parse_compact_kspt(&wire, &mut transaction).expect("parse");
    assert_eq!(
        sign_transaction_account_multi_addr_with_entropy(
            &mut transaction,
            account,
            SigHashType::All,
            &[0x55; 32],
        ),
        Err(PsktError::NoInputs),
    );
}

fn sign_request(
    request: &SigningRequest,
    account: &offline_signer::derivation::bip32::ExtendedPrivKey,
) -> Result<String, String> {
    let wire = hex::decode(&request.kspt_hex).map_err(|error| error.to_string())?;
    let mut transaction = Transaction::try_new().map_err(|_| "transaction allocation".to_string())?;
    parse_compact_kspt(&wire, &mut transaction).map_err(|error| format!("parse: {error:?}"))?;
    sign_transaction_account_multi_addr_with_entropy(
        &mut transaction,
        account,
        SigHashType::All,
        &[0xa5; 32],
    )
    .map_err(|error| format!("sign: {error:?}"))?;
    serialize_compact_kspt_vec(&transaction)
        .map(hex::encode)
        .map_err(|error| format!("serialize: {error:?}"))
}

fn pskb(input_key: [u8; 32], tx_byte: u8) -> String {
    let script = format!("000020{}ac", hex::encode(input_key));
    let document = json!({
        "global": {
            "txVersion": 0,
            "fallbackLockTime": "0",
            "subnetworkId": "0000000000000000000000000000000000000000",
            "gas": "0",
            "txPayload": ""
        },
        "inputs": [{
            "previousOutpoint": { "transactionId": hex::encode([tx_byte; 32]), "index": 0 },
            "utxoEntry": { "amount": "100000", "scriptPublicKey": script },
            "sequence": "0",
            "sigOpCount": 1,
            "partialSigs": {},
            "proprietaries": {}
        }],
        "outputs": [{ "amount": "90000", "scriptPublicKey": script, "proprietaries": {} }]
    });
    let inner = serde_json::to_vec(&json!([document])).expect("JSON");
    let mut wire = b"PSKB".to_vec();
    wire.extend_from_slice(hex::encode(inner).as_bytes());
    hex::encode(wire)
}
