use crate::{
    account::address,
    serialization::input::{decode_named_32, decode_pubkey32},
};

pub(crate) fn build_random_json(
    alice_pubkey_hex: &str,
    bob_pubkey_hex: &str,
    arbiter_pubkey_hex: &str,
    alice_address: &str,
    bob_address: &str,
    network: &str,
) -> Result<String, String> {
    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt).map_err(|error| format!("RNG failed: {error}"))?;
    build_json(
        alice_pubkey_hex,
        bob_pubkey_hex,
        arbiter_pubkey_hex,
        alice_address,
        bob_address,
        network,
        salt,
    )
}

pub(crate) fn build_json(
    alice_pubkey_hex: &str,
    bob_pubkey_hex: &str,
    arbiter_pubkey_hex: &str,
    alice_address: &str,
    bob_address: &str,
    network: &str,
    salt: [u8; 8],
) -> Result<String, String> {
    let alice = decode_pubkey32(alice_pubkey_hex)?;
    let bob = decode_pubkey32(bob_pubkey_hex)?;
    let arbiter = decode_pubkey32(arbiter_pubkey_hex)?;
    let alice_script = address::address_to_script_pubkey(alice_address)?;
    let bob_script = address::address_to_script_pubkey(bob_address)?;
    let script = crate::contracts::covenant::script::build_escrow_script(
        &alice,
        &bob,
        &arbiter,
        &alice_script,
        &bob_script,
        &salt,
    );
    let covenant_address = crate::protocol::script::p2sh::script_to_address(
        &script,
        address::network_prefix(network),
    )?;
    serde_json::to_string(&serde_json::json!({
        "address": covenant_address,
        "redeem_script_hex": hex::encode(&script),
        "salt": hex::encode(salt),
    }))
    .map_err(|error| error.to_string())
}

pub(crate) fn build_timelocked_json(
    alice_pubkey_hex: &str,
    bob_pubkey_hex: &str,
    alice_address: &str,
    bob_address: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, String> {
    let alice = decode_named_32(alice_pubkey_hex, "alice pubkey")?;
    let bob = decode_named_32(bob_pubkey_hex, "bob pubkey")?;
    let alice_script = address::address_to_script_pubkey(alice_address)?;
    let bob_script = address::address_to_script_pubkey(bob_address)?;
    let script = crate::contracts::covenant::script::build_timelocked_escrow_script(
        &alice,
        &bob,
        &alice_script,
        &bob_script,
        locktime_daa,
    );
    let covenant_address = crate::protocol::script::p2sh::script_to_address(
        &script,
        address::network_prefix(network),
    )?;
    serde_json::to_string(&serde_json::json!({
        "address": covenant_address,
        "redeem_script_hex": hex::encode(&script),
        "locktime_daa": locktime_daa.to_string(),
    }))
    .map_err(|error| error.to_string())
}
