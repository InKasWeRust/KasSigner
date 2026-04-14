// KasSee Web — KSPT binary format
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// kspt.rs — KSPT serialization for unsigned TX creation.
// Format: "KSPT" + version(1) + flags(1) + global + inputs + outputs
// Supports single and compound (multi-recipient) transactions.

use crate::bip32::WalletData;
use crate::rpc::UtxoEntry;

const STORAGE_MASS_C: u64 = 1_000_000_000_000;
const MAX_STANDARD_MASS: u64 = 100_000;
const DUST_THRESHOLD: u64 = 20_000_000;

/// Check if an amount is dust (would exceed standard mass)
fn is_dust(amount: u64) -> bool {
    if amount == 0 { return true; }
    if amount >= DUST_THRESHOLD { return false; }
    let mass = STORAGE_MASS_C / amount;
    mass > MAX_STANDARD_MASS
}

/// Create unsigned KSPT: fetch UTXOs, select coins, build binary, return hex
pub async fn create_send_kspt(
    wallet: &WalletData,
    dest_address: &str,
    amount_kas: f64,
    fee: u64,
    ws_url: &str,
) -> Result<String, String> {
    let dest_script = crate::address::address_to_script_pubkey(dest_address)?;
    let amount_sompi = (amount_kas * 100_000_000.0) as u64;

    let mut all_utxos = crate::rpc::fetch_all_utxos(ws_url, wallet).await?;
    all_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

    let total_needed = amount_sompi + fee;
    let mut selected = Vec::new();
    let mut selected_total: u64 = 0;

    for utxo in all_utxos {
        selected_total += utxo.amount;
        selected.push(utxo);
        if selected_total >= total_needed { break; }
    }

    if selected_total < total_needed {
        return Err(format!(
            "Insufficient funds: have {} sompi ({:.8} KAS), need {} sompi",
            selected_total,
            selected_total as f64 / 1e8,
            total_needed,
        ));
    }

    let change_amount = selected_total - amount_sompi - fee;

    if amount_sompi > 0 && is_dust(amount_sompi) {
        return Err(format!(
            "Amount too small: {:.8} KAS. Minimum ~0.1 KAS.",
            amount_sompi as f64 / 1e8
        ));
    }

    // Absorb dust change into fee
    let final_change = if change_amount > 0 && is_dust(change_amount) { 0u64 } else { change_amount };

    let change_script = if final_change > 0 {
        let chg_idx = wallet.next_change_index;
        if chg_idx >= wallet.change_addresses.len() {
            return Err("No more change addresses. Re-import kpub.".into());
        }
        Some(crate::address::address_to_script_pubkey(
            &wallet.change_addresses[chg_idx],
        )?)
    } else {
        None
    };

    // Build outputs
    let mut outputs = vec![(amount_sompi, dest_script)];
    if let Some(chg_script) = change_script {
        outputs.push((final_change, chg_script));
    }

    let kspt_hex = serialize_kspt_multi(&selected, &outputs)?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] TX: {} inputs, send {}, change {}, {} bytes",
            selected.len(),
            amount_sompi,
            final_change,
            kspt_hex.len() / 2
        )
        .into(),
    );

    Ok(kspt_hex)
}

/// Consolidate all UTXOs into one, sending to first receive address
pub async fn create_consolidate_kspt(
    wallet: &WalletData,
    fee: u64,
    ws_url: &str,
) -> Result<String, String> {
    let mut all_utxos = crate::rpc::fetch_all_utxos(ws_url, wallet).await?;

    if all_utxos.is_empty() {
        return Err("No UTXOs to consolidate".into());
    }
    if all_utxos.len() == 1 {
        return Err("Only 1 UTXO — nothing to consolidate".into());
    }

    // Sort largest first, cap at 5 inputs to stay within 1024-byte signed TX limit
    all_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));
    let selected: Vec<_> = all_utxos.into_iter().take(5).collect();

    let total: u64 = selected.iter().map(|u| u.amount).sum();
    if total <= fee {
        return Err("Balance too low to cover fee".into());
    }

    let dest_addr = &wallet.receive_addresses[0];
    let dest_script = crate::address::address_to_script_pubkey(dest_addr)?;
    let send_amount = total - fee;

    let outputs = vec![(send_amount, dest_script)];
    let kspt_hex = serialize_kspt_multi(&selected, &outputs)?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] Consolidate: {} inputs → {} sompi, fee {}, {} bytes",
            selected.len(), send_amount, fee, kspt_hex.len() / 2
        ).into(),
    );

    Ok(kspt_hex)
}

/// Create unsigned KSPT with specific UTXO indices
pub async fn create_send_kspt_selected(
    wallet: &WalletData,
    dest_address: &str,
    amount_kas: f64,
    fee: u64,
    utxo_indices: &[usize],
    ws_url: &str,
) -> Result<String, String> {
    let dest_script = crate::address::address_to_script_pubkey(dest_address)?;
    let amount_sompi = (amount_kas * 100_000_000.0) as u64;

    let all_utxos = crate::rpc::fetch_all_utxos(ws_url, wallet).await?;

    let mut selected = Vec::new();
    for &idx in utxo_indices {
        if idx >= all_utxos.len() {
            return Err(format!("UTXO index {} out of range (have {})", idx, all_utxos.len()));
        }
        selected.push(all_utxos[idx].clone());
    }

    let selected_total: u64 = selected.iter().map(|u| u.amount).sum();
    let total_needed = amount_sompi + fee;

    if selected_total < total_needed {
        return Err(format!(
            "Selected UTXOs: {} sompi, need {} sompi",
            selected_total, total_needed,
        ));
    }

    let change_amount = selected_total - amount_sompi - fee;
    let final_change = if change_amount > 0 && is_dust(change_amount) { 0u64 } else { change_amount };

    let change_script = if final_change > 0 {
        let chg_idx = wallet.next_change_index;
        if chg_idx >= wallet.change_addresses.len() {
            return Err("No more change addresses".into());
        }
        Some(crate::address::address_to_script_pubkey(&wallet.change_addresses[chg_idx])?)
    } else {
        None
    };

    let mut outputs = vec![(amount_sompi, dest_script)];
    if let Some(chg_script) = change_script {
        outputs.push((final_change, chg_script));
    }

    serialize_kspt_multi(&selected, &outputs)
}

/// Create compound unsigned KSPT: multiple recipients in one transaction
pub async fn create_compound_kspt(
    wallet: &WalletData,
    recipients_json: &str,
    fee: u64,
    ws_url: &str,
) -> Result<String, String> {
    // Parse recipients: [{"address":"kaspa:...","amount_kas":1.5}, ...]
    let recipients: Vec<serde_json::Value> = serde_json::from_str(recipients_json)
        .map_err(|e| format!("Invalid recipients JSON: {}", e))?;

    if recipients.is_empty() {
        return Err("No recipients".into());
    }
    if recipients.len() > 10 {
        return Err("Maximum 10 recipients per transaction".into());
    }

    // Build output list
    let mut outputs: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut total_send: u64 = 0;

    for (i, r) in recipients.iter().enumerate() {
        let addr = r["address"].as_str()
            .ok_or_else(|| format!("Recipient {}: missing address", i + 1))?;
        let amount_kas = r["amount_kas"].as_f64()
            .ok_or_else(|| format!("Recipient {}: missing amount_kas", i + 1))?;
        let amount_sompi = (amount_kas * 100_000_000.0) as u64;

        if amount_sompi == 0 {
            return Err(format!("Recipient {}: amount must be > 0", i + 1));
        }
        if is_dust(amount_sompi) {
            return Err(format!("Recipient {}: amount too small ({:.8} KAS)", i + 1, amount_kas));
        }

        let script = crate::address::address_to_script_pubkey(addr)?;
        outputs.push((amount_sompi, script));
        total_send += amount_sompi;
    }

    // Fetch and select UTXOs
    let mut all_utxos = crate::rpc::fetch_all_utxos(ws_url, wallet).await?;
    all_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

    let total_needed = total_send + fee;
    let mut selected = Vec::new();
    let mut selected_total: u64 = 0;

    for utxo in all_utxos {
        selected_total += utxo.amount;
        selected.push(utxo);
        if selected_total >= total_needed { break; }
    }
















    if selected_total < total_needed {
        return Err(format!(
            "Insufficient funds: have {} sompi ({:.8} KAS), need {} sompi",
            selected_total, selected_total as f64 / 1e8, total_needed,
        ));
    }

    // Change
    let change_amount = selected_total - total_send - fee;
    let final_change = if change_amount > 0 && is_dust(change_amount) { 0u64 } else { change_amount };

    if final_change > 0 {
        let chg_idx = wallet.next_change_index;
        if chg_idx >= wallet.change_addresses.len() {
            return Err("No more change addresses".into());
        }
        let chg_script = crate::address::address_to_script_pubkey(&wallet.change_addresses[chg_idx])?;
        outputs.push((final_change, chg_script));
    }

    let kspt_hex = serialize_kspt_multi(&selected, &outputs)?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] Compound TX: {} inputs, {} recipients, total send {}, change {}, {} bytes",
            selected.len(), recipients.len(), total_send, final_change, kspt_hex.len() / 2
        ).into(),
    );

    Ok(kspt_hex)
}

/// Serialize unsigned KSPT binary with multiple outputs → hex string
fn serialize_kspt_multi(
    inputs: &[UtxoEntry],
    outputs: &[(u64, Vec<u8>)],
) -> Result<String, String> {
    let mut buf = Vec::with_capacity(512);

    // Header
    buf.extend_from_slice(b"KSPT");
    buf.push(0x01); // version
    buf.push(0x00); // flags (unsigned)

    // Global
    buf.extend_from_slice(&0u16.to_le_bytes()); // tx_version
    buf.push(inputs.len() as u8); // num_inputs
    buf.push(outputs.len() as u8); // num_outputs
    buf.extend_from_slice(&0u64.to_le_bytes()); // locktime
    buf.extend_from_slice(&[0u8; 20]); // subnetwork_id
    buf.extend_from_slice(&0u64.to_le_bytes()); // gas
    buf.extend_from_slice(&0u16.to_le_bytes()); // payload_len

    // Per input
    for utxo in inputs {
        let tx_id_bytes = hex::decode(&utxo.tx_id)
            .map_err(|e| format!("Bad tx_id: {}", e))?;
        if tx_id_bytes.len() != 32 {
            return Err(format!("tx_id wrong length: {}", tx_id_bytes.len()));
        }
        buf.extend_from_slice(&tx_id_bytes); // prev_tx_id: 32
        buf.extend_from_slice(&utxo.index.to_le_bytes()); // prev_index: 4
        buf.extend_from_slice(&utxo.amount.to_le_bytes()); // amount: 8
        buf.extend_from_slice(&0u64.to_le_bytes()); // sequence: 8
        buf.push(1u8); // sig_op_count

        buf.extend_from_slice(&0u16.to_le_bytes()); // spk version
        buf.push(utxo.script_public_key.len() as u8); // spk len
        buf.extend_from_slice(&utxo.script_public_key); // spk
    }

    // Outputs
    for (amount, script) in outputs {
        buf.extend_from_slice(&amount.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // spk version
        buf.push(script.len() as u8);
        buf.extend_from_slice(script);
    }

    Ok(hex::encode(&buf))
}

// ═══════════════════════════════════════════════════════════════════
// Multisig P2SH spend — create unsigned KSPT with redeem scripts
// ═══════════════════════════════════════════════════════════════════

/// Parse descriptor "multi(M,pk1hex,pk2hex,...)" → (M, Vec<[u8;32]>)
fn parse_descriptor(desc: &str) -> Result<(u8, Vec<[u8; 32]>), String> {
    let desc = desc.trim();
    if !desc.starts_with("multi(") || !desc.ends_with(')') {
        return Err("Descriptor must be multi(M,pk1,pk2,...)".into());
    }
    let inner = &desc[6..desc.len() - 1]; // strip "multi(" and ")"
    let parts: Vec<&str> = inner.split(',').collect();
    if parts.len() < 3 {
        return Err("Need at least M and 2 pubkeys".into());
    }

    let m: u8 = parts[0].trim().parse()
        .map_err(|_| "Invalid M value in descriptor".to_string())?;

    let mut pubkeys = Vec::new();
    for pk_hex in &parts[1..] {
        let pk_hex = pk_hex.trim();
        if pk_hex.len() != 64 {
            return Err(format!("Pubkey must be 64 hex chars, got {}", pk_hex.len()));
        }
        let pk_bytes = hex::decode(pk_hex)
            .map_err(|e| format!("Invalid pubkey hex: {}", e))?;
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&pk_bytes);
        pubkeys.push(pk);
    }

    if m == 0 || m as usize > pubkeys.len() {
        return Err(format!("Invalid M={} for N={}", m, pubkeys.len()));
    }

    // Sort pubkeys lexicographically so both devices produce the same address
    pubkeys.sort();

    Ok((m, pubkeys))
}

/// Build redeem script: OP_M OP_DATA_32 <pk1> ... OP_N OP_CHECKMULTISIG
fn build_redeem_script(m: u8, pubkeys: &[[u8; 32]]) -> Vec<u8> {
    let n = pubkeys.len() as u8;
    let mut script = Vec::with_capacity(1 + (n as usize) * 33 + 1 + 1);

    script.push(0x50 + m); // OP_M (OP_1=0x51, OP_2=0x52, etc.)
    for pk in pubkeys {
        script.push(0x20); // OP_DATA_32
        script.extend_from_slice(pk);
    }
    script.push(0x50 + n); // OP_N
    script.push(0xAE);     // OP_CHECKMULTISIG

    script
}

/// Create unsigned multisig KSPT: fetch UTXOs for P2SH address, build TX with redeem scripts
pub async fn create_multisig_kspt(
    descriptor: &str,
    source_address: &str,
    dest_address: &str,
    amount_kas: f64,
    fee: u64,
    change_address: &str,
    ws_url: &str,
) -> Result<String, String> {
    let (m, pubkeys) = parse_descriptor(descriptor)?;
    let redeem_script = build_redeem_script(m, &pubkeys);

    let dest_script = crate::address::address_to_script_pubkey(dest_address)?;
    let amount_sompi = (amount_kas * 100_000_000.0) as u64;

    // Fetch UTXOs for the P2SH address
    let mut utxos = crate::rpc::fetch_utxos_for_address(ws_url, source_address).await?;
    if utxos.is_empty() {
        return Err("No UTXOs found for multisig address".into());
    }

    utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

    let total_needed = amount_sompi + fee;
    let mut selected = Vec::new();
    let mut selected_total: u64 = 0;

    for utxo in utxos {
        selected_total += utxo.amount;
        selected.push(utxo);
        if selected_total >= total_needed { break; }
    }












    if selected_total < total_needed {
        return Err(format!(
            "Insufficient funds in multisig: have {} sompi, need {}",
            selected_total, total_needed
        ));
    }

    let change_amount = selected_total - amount_sompi - fee;
    let final_change = if change_amount > 0 && is_dust(change_amount) { 0u64 } else { change_amount };

    // Build outputs
    let mut outputs: Vec<(u64, Vec<u8>)> = vec![(amount_sompi, dest_script)];
    if final_change > 0 {
        // Change goes back to the same multisig address
        let change_script = crate::address::address_to_script_pubkey(change_address)?;
        outputs.push((final_change, change_script));
    }

    // Serialize KSPT with redeem scripts (flag 0x02)
    let kspt_hex = serialize_kspt_multisig(&selected, &outputs, &redeem_script, m)?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] Multisig TX: {} inputs, {}-of-{}, send {}, change {}, {} bytes",
            selected.len(), m, pubkeys.len(), amount_sompi, final_change, kspt_hex.len() / 2
        ).into(),
    );

    Ok(kspt_hex)
}

/// Serialize unsigned KSPT with redeem scripts for P2SH multisig inputs
fn serialize_kspt_multisig(
    inputs: &[crate::rpc::UtxoEntry],
    outputs: &[(u64, Vec<u8>)],
    redeem_script: &[u8],
    sig_op_count: u8,
) -> Result<String, String> {
    let mut buf = Vec::with_capacity(512);

    // Header
    buf.extend_from_slice(b"KSPT");
    buf.push(0x01); // version
    buf.push(0x02); // flags: bit 1 = has redeem scripts

    // Global
    buf.extend_from_slice(&0u16.to_le_bytes()); // tx_version
    buf.push(inputs.len() as u8);
    buf.push(outputs.len() as u8);
    buf.extend_from_slice(&0u64.to_le_bytes()); // locktime
    buf.extend_from_slice(&[0u8; 20]); // subnetwork_id
    buf.extend_from_slice(&0u64.to_le_bytes()); // gas
    buf.extend_from_slice(&0u16.to_le_bytes()); // payload_len

    // Per input
    for utxo in inputs {
        let tx_id_bytes = hex::decode(&utxo.tx_id)
            .map_err(|e| format!("Bad tx_id: {}", e))?;
        if tx_id_bytes.len() != 32 {
            return Err(format!("tx_id wrong length: {}", tx_id_bytes.len()));
        }
        buf.extend_from_slice(&tx_id_bytes);
        buf.extend_from_slice(&utxo.index.to_le_bytes());
        buf.extend_from_slice(&utxo.amount.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes()); // sequence
        buf.push(sig_op_count); // sig_op_count = M (threshold)

        buf.extend_from_slice(&0u16.to_le_bytes()); // spk version
        buf.push(utxo.script_public_key.len() as u8);
        buf.extend_from_slice(&utxo.script_public_key);

        // Redeem script for this input
        buf.push(redeem_script.len() as u8);
        buf.extend_from_slice(redeem_script);
    }

    // Outputs
    for (amount, script) in outputs {
        buf.extend_from_slice(&amount.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(script.len() as u8);
        buf.extend_from_slice(script);
    }

    Ok(hex::encode(&buf))
}
