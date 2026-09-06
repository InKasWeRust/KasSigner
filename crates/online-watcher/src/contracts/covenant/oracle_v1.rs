//! Browser-neutral Oracle-v1 covenant construction and attestation validation.

use sha2::{Digest, Sha256};

use crate::{account::address::network_prefix, serialization::input::decode_pubkey32};

const MAX_ATTEST_TEXT_BYTES: usize = 256;
const STATEMENT_PREFIX: &str = "KasSigner Oracle v1 ";

type OracleKeys = ([u8; 32], [u8; 32], [u8; 32], [u8; 32]);
pub(crate) type OracleAttestation = ([u8; 32], [u8; 64], [u8; 32]);

pub(crate) fn build_json(
    owner_pubkey_hex: &str,
    beneficiary_pubkey_hex: &str,
    oracle_pubkey_hex: &str,
    oracle_covenant_key_id_hex: &str,
    release_statement: &str,
    locktime_daa: u64,
    network: &str,
) -> Result<String, String> {
    let (owner, beneficiary, oracle, oracle_key_id) = checked_inputs(
        owner_pubkey_hex,
        beneficiary_pubkey_hex,
        oracle_pubkey_hex,
        oracle_covenant_key_id_hex,
        locktime_daa,
    )?;
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|error| format!("RNG failed: {error}"))?;
    let statement = bound_statement(release_statement, &salt)?;
    let commitment: [u8; 32] = Sha256::digest(statement.as_bytes()).into();
    let script = crate::contracts::covenant::script::build_oracle_v1_covenant_script(
        &owner,
        &beneficiary,
        &oracle,
        &commitment,
        locktime_daa,
        &salt,
    );
    let address =
        crate::protocol::script::p2sh::script_to_address(&script, network_prefix(network))?;
    serde_json::to_string(&serde_json::json!({
        "address": address,
        "redeem_script_hex": hex::encode(script),
        "locktime_daa": locktime_daa.to_string(),
        "owner_pubkey_hex": owner_pubkey_hex,
        "beneficiary_pubkey_hex": beneficiary_pubkey_hex,
        "oracle_pubkey_hex": oracle_pubkey_hex,
        "oracle_covenant_key_id_hex": hex::encode(oracle_key_id),
        "salt": hex::encode(salt),
        "attestation_statement": statement,
        "message_commitment_hex": hex::encode(commitment),
        "type": "oracle-v1",
    }))
    .map_err(|error| error.to_string())
}

pub(crate) fn verify_attestation(
    oracle_pubkey_hex: &str,
    oracle_signature_hex: &str,
    message_commitment_hex: &str,
) -> Result<bool, String> {
    let (public_key, signature, commitment) = decode_attestation(
        oracle_pubkey_hex,
        oracle_signature_hex,
        message_commitment_hex,
    )?;
    crate::protocol::schnorr::bip340_verify(&public_key, &commitment, &signature)
}

pub(crate) fn checked_redeem_and_attestation(
    redeem_script_hex: &str,
    oracle_pubkey_hex: &str,
    oracle_signature_hex: &str,
    message_commitment_hex: &str,
) -> Result<Vec<u8>, String> {
    let redeem =
        hex::decode(redeem_script_hex).map_err(|error| format!("Bad redeem hex: {error}"))?;
    let (public_key, signature, commitment) = decode_attestation(
        oracle_pubkey_hex,
        oracle_signature_hex,
        message_commitment_hex,
    )?;
    if !crate::contracts::covenant::script::oracle_v1_script_commits_to(
        &redeem,
        &commitment,
        &public_key,
    ) {
        return Err("Oracle attestation commitment/key do not belong to this covenant".to_string());
    }
    if !crate::protocol::schnorr::bip340_verify(&public_key, &commitment, &signature)? {
        return Err("Oracle signature is invalid for this covenant".to_string());
    }
    Ok(redeem)
}

fn checked_inputs(
    owner_pubkey_hex: &str,
    beneficiary_pubkey_hex: &str,
    oracle_pubkey_hex: &str,
    oracle_covenant_key_id_hex: &str,
    locktime_daa: u64,
) -> Result<OracleKeys, String> {
    if locktime_daa == 0 {
        return Err("Oracle refund timeout must be non-zero".to_string());
    }
    let owner = checked_xonly_pubkey(owner_pubkey_hex, "owner")?;
    let beneficiary = checked_xonly_pubkey(beneficiary_pubkey_hex, "beneficiary")?;
    let oracle = checked_xonly_pubkey(oracle_pubkey_hex, "oracle")?;
    let oracle_key_id = checked_key_id(oracle_covenant_key_id_hex)?;
    if owner == beneficiary || owner == oracle || beneficiary == oracle {
        return Err("Oracle owner, beneficiary, and oracle keys must be distinct".to_string());
    }
    Ok((owner, beneficiary, oracle, oracle_key_id))
}

fn bound_statement(release_statement: &str, salt: &[u8; 16]) -> Result<String, String> {
    let trimmed = release_statement.trim();
    if trimmed.is_empty() {
        return Err("Oracle release statement is required".to_string());
    }
    let statement = format!("{STATEMENT_PREFIX}{}: {trimmed}", hex::encode(salt));
    if statement.len() > MAX_ATTEST_TEXT_BYTES {
        return Err("Oracle release statement exceeds 256 UTF-8 bytes after binding".to_string());
    }
    Ok(statement)
}

fn checked_key_id(value: &str) -> Result<[u8; 32], String> {
    let bytes =
        hex::decode(value).map_err(|_| "Oracle covenant key ID must be 32-byte hex".to_string())?;
    if bytes.len() != 32 {
        return Err("Oracle covenant key ID must be 32 bytes".to_string());
    }
    let mut key_id = [0u8; 32];
    key_id.copy_from_slice(&bytes);
    if key_id == [0u8; 32] {
        return Err("Oracle covenant key ID cannot be zero".to_string());
    }
    Ok(key_id)
}

fn checked_xonly_pubkey(value: &str, role: &str) -> Result<[u8; 32], String> {
    let public_key =
        decode_pubkey32(value).map_err(|_| format!("Oracle {role} key must be 32-byte hex"))?;
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02;
    compressed[1..].copy_from_slice(&public_key);
    k256::PublicKey::from_sec1_bytes(&compressed)
        .map_err(|_| format!("Oracle {role} key is not a valid secp256k1 x-only public key"))?;
    Ok(public_key)
}

pub(crate) fn decode_attestation(
    oracle_pubkey_hex: &str,
    signature_hex: &str,
    commitment_hex: &str,
) -> Result<OracleAttestation, String> {
    let public_key = checked_xonly_pubkey(oracle_pubkey_hex, "oracle")?;
    let signature_bytes =
        hex::decode(signature_hex).map_err(|error| format!("Bad oracle signature hex: {error}"))?;
    if signature_bytes.len() != 64 {
        return Err(format!(
            "Oracle signature must be 64 bytes, got {}",
            signature_bytes.len()
        ));
    }
    let commitment_bytes = hex::decode(commitment_hex)
        .map_err(|error| format!("Bad message commitment hex: {error}"))?;
    if commitment_bytes.len() != 32 {
        return Err(format!(
            "Message commitment must be 32 bytes, got {}",
            commitment_bytes.len()
        ));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&signature_bytes);
    let mut commitment = [0u8; 32];
    commitment.copy_from_slice(&commitment_bytes);
    Ok((public_key, signature, commitment))
}
