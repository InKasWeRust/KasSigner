// KasSee Web — KSPT binary format
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// kspt.rs — KSPT serialization for unsigned TX creation.
// Format: "KSPT" + version(1) + flags(1) + global + inputs + outputs
// Supports single and compound (multi-recipient) transactions.

use crate::bip32::WalletData;
use crate::rpc::UtxoEntry;
use k256::elliptic_curve::sec1::ToEncodedPoint;

/// Blake2b-256 hash — unkeyed (matches firmware sighash::blake2b_hash for P2SH)
fn blake2b_hash(data: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

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

    let mut all_utxos = crate::rpc::fetch_all_utxos(ws_url, wallet).await?;
    // Sort to match the JS-side order (cachedUtxos.sort by amount desc,
    // then tx_id asc + index asc as tiebreakers for determinism).
    all_utxos.sort_by(|a, b| b.amount.cmp(&a.amount)
        .then_with(|| a.tx_id.cmp(&b.tx_id))
        .then_with(|| a.index.cmp(&b.index)));

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

/// Parse descriptor — supports both legacy and HD formats:
///
/// Legacy: "multi(M,pk1hex64,pk2hex64,...)" → x-only pubkeys directly
/// HD:     "multi_hd(M,pk1hex130,pk2hex130,...)" → compressed pubkey(33B) + chain_code(32B)
///         per cosigner, requiring derive_child at /0/addr_index to get x-only children.
///
/// Returns (M, Vec<[u8;32]>) — the lex-sorted x-only pubkeys for the redeem script.
fn parse_descriptor(desc: &str, addr_index: u32) -> Result<(u8, Vec<[u8; 32]>), String> {
    let desc = desc.trim();

    if desc.starts_with("multi_hd(") && desc.ends_with(')') {
        // ── HD format: multi_hd(M,<130hex>,<130hex>,...) ──
        let inner = &desc[9..desc.len() - 1]; // strip "multi_hd(" and ")"
        let parts: Vec<&str> = inner.split(',').collect();
        if parts.len() < 3 {
            return Err("Need at least M and 2 cosigner xpubs".into());
        }
        let m: u8 = parts[0].trim().parse()
            .map_err(|_| "Invalid M value in descriptor".to_string())?;

        let mut pubkeys = Vec::new();
        for xpub_hex in &parts[1..] {
            let xpub_hex = xpub_hex.trim();
            if xpub_hex.len() != 130 {
                return Err(format!("Cosigner xpub must be 130 hex chars (33B pubkey + 32B chain code), got {}", xpub_hex.len()));
            }
            let xpub_bytes = hex::decode(xpub_hex)
                .map_err(|e| format!("Invalid xpub hex: {}", e))?;
            // First 33 bytes = compressed pubkey, next 32 = chain code
            let pubkey = k256::PublicKey::from_sec1_bytes(&xpub_bytes[..33])
                .map_err(|e| format!("Invalid compressed pubkey: {}", e))?;
            let mut chain_code = [0u8; 32];
            chain_code.copy_from_slice(&xpub_bytes[33..65]);

            // Derive child at /0/addr_index (matches KasSigner firmware path)
            let parent = crate::bip32::ExtPubKey {
                key: pubkey,
                chain_code,
                depth: 3, // account level
            };
            let receive_chain = parent.derive_child(0)?;
            let addr_child = receive_chain.derive_child(addr_index)?;

            // Extract x-only (32 bytes, strip 0x02/0x03 prefix)
            let compressed = addr_child.key.to_encoded_point(true);
            let compressed_bytes = compressed.as_bytes(); // 33 bytes
            let mut xonly = [0u8; 32];
            xonly.copy_from_slice(&compressed_bytes[1..33]);
            pubkeys.push(xonly);
        }

        if m == 0 || m as usize > pubkeys.len() {
            return Err(format!("Invalid M={} for N={}", m, pubkeys.len()));
        }
        pubkeys.sort();
        Ok((m, pubkeys))

    } else if desc.starts_with("multi(") && desc.ends_with(')') {
        // ── Legacy format: multi(M,pk1hex64,pk2hex64,...) ──
        let inner = &desc[6..desc.len() - 1];
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
        pubkeys.sort();
        Ok((m, pubkeys))

    } else {
        Err("Descriptor must be multi(M,...) or multi_hd(M,...)".into())
    }
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
    addr_index: u32,
) -> Result<String, String> {
    // For HD descriptors, auto-discover the addr_index by trying indices
    // 0..99 and matching the derived P2SH address against source_address.
    // This saves the user from manually entering an index number.
    // For legacy multi(...) descriptors, addr_index is ignored (always 0).
    let final_index = if descriptor.trim().starts_with("multi_hd(") {
        let mut found: Option<u32> = None;
        for try_idx in 0..100u32 {
            let (m, pks) = parse_descriptor(descriptor, try_idx)?;
            let script = build_redeem_script(m, &pks);
            let script_hash = blake2b_hash(&script);
            let derived_addr = crate::address::encode_p2sh_address(&script_hash, "kaspa");
            if derived_addr == source_address {
                found = Some(try_idx);
                break;
            }
        }
        match found {
            Some(idx) => idx,
            None => return Err(format!(
                "Could not find address index (tried 0..99) that matches source address {}",
                source_address
            )),
        }
    } else {
        addr_index // legacy: use as-is (typically 0)
    };

    let (m, pubkeys) = parse_descriptor(descriptor, final_index)?;
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

    if selected.len() > 2 {
        return Err(format!(
            "Multisig P2SH limited to 2 inputs (selected {}). Redeem script mass exceeds standard limit. Consolidate UTXOs in batches of 2.",
            selected.len()
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
    // sig_op_count = N (total pubkeys), not M (threshold) — Kaspa's
    // OP_CHECKMULTISIG checks all N pubkeys against the M signatures.
    let kspt_hex = serialize_kspt_multisig(&selected, &outputs, &redeem_script, pubkeys.len() as u8)?;

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

// ═══════════════════════════════════════════════════════════════════
// Single-sig PSKB creation — standard PSKT wire format for P2PK
// ═══════════════════════════════════════════════════════════════════
//
// Same input/output semantics as the KSPT single-sig constructors
// (create_send_kspt, create_consolidate_kspt, etc.) but emits an
// UNSIGNED PSKB (Kaspa-standard partially-signed bundle).
//
// Wire envelope: `PSKB` magic + hex-ASCII of a UTF-8 JSON array
// wrapping one PSKT object. KasSigner's `std_pskt::parse_pskt`
// already consumes this (camera_loop.rs routes PSKB magic to the
// PSKT parser, signing.rs handles P2PK inputs via the existing
// PSKT path). No firmware changes needed.
//
// The UI routes PSKB output through the existing PSKT review screen
// — same flow as multisig PSKB: Review → Relay (standard PSKB for
// any wallet, or compact KSPT v2 for KasSigner) → Finalize.
//
// Why siblings and not parameters on the KSPT functions: the KSPT
// path is mainnet-verified. Duplication is cheap; silent KSPT
// breakage loses funds.

/// Create unsigned single-sig PSKB: fetch UTXOs, select coins,
/// build PSKB JSON, return wire hex.
pub async fn create_send_pskb(
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
            selected_total, selected_total as f64 / 1e8, total_needed,
        ));
    }

    let change_amount = selected_total - amount_sompi - fee;

    if amount_sompi > 0 && is_dust(amount_sompi) {
        return Err(format!(
            "Amount too small: {:.8} KAS. Minimum ~0.1 KAS.",
            amount_sompi as f64 / 1e8
        ));
    }

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

    let mut outputs = vec![(amount_sompi, dest_script)];
    if let Some(chg_script) = change_script {
        outputs.push((final_change, chg_script));
    }

    let pskb_hex = serialize_pskb_single_sig(&selected, &outputs)?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] PSKB TX: {} inputs, send {}, change {}, wire hex {} chars",
            selected.len(), amount_sompi, final_change, pskb_hex.len()
        ).into(),
    );

    Ok(pskb_hex)
}

/// Consolidate all UTXOs into one via PSKB format.
pub async fn create_consolidate_pskb(
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
    let pskb_hex = serialize_pskb_single_sig(&selected, &outputs)?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] Consolidate PSKB: {} inputs -> {} sompi, fee {}, wire hex {} chars",
            selected.len(), send_amount, fee, pskb_hex.len()
        ).into(),
    );

    Ok(pskb_hex)
}

/// Create unsigned PSKB with specific UTXO indices.
pub async fn create_send_pskb_selected(
    wallet: &WalletData,
    dest_address: &str,
    amount_kas: f64,
    fee: u64,
    utxo_indices: &[usize],
    ws_url: &str,
) -> Result<String, String> {
    let dest_script = crate::address::address_to_script_pubkey(dest_address)?;
    let amount_sompi = (amount_kas * 100_000_000.0) as u64;

    let mut all_utxos = crate::rpc::fetch_all_utxos(ws_url, wallet).await?;
    // Sort to match the JS-side order (cachedUtxos.sort by amount desc,
    // then tx_id asc + index asc as tiebreakers for determinism).
    all_utxos.sort_by(|a, b| b.amount.cmp(&a.amount)
        .then_with(|| a.tx_id.cmp(&b.tx_id))
        .then_with(|| a.index.cmp(&b.index)));

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

    serialize_pskb_single_sig(&selected, &outputs)
}

/// Create compound unsigned PSKB: multiple recipients in one transaction.
pub async fn create_compound_pskb(
    wallet: &WalletData,
    recipients_json: &str,
    fee: u64,
    ws_url: &str,
) -> Result<String, String> {
    let recipients: Vec<serde_json::Value> = serde_json::from_str(recipients_json)
        .map_err(|e| format!("Invalid recipients JSON: {}", e))?;

    if recipients.is_empty() {
        return Err("No recipients".into());
    }
    if recipients.len() > 10 {
        return Err("Maximum 10 recipients per transaction".into());
    }

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

    let pskb_hex = serialize_pskb_single_sig(&selected, &outputs)?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] Compound PSKB: {} inputs, {} recipients, send {}, change {}, wire hex {} chars",
            selected.len(), recipients.len(), total_send, final_change, pskb_hex.len()
        ).into(),
    );

    Ok(pskb_hex)
}

/// Serialize an unsigned single-sig PSKB wire payload.
///
/// Builds the same JSON shape as `create_multisig_pskb` but for P2PK
/// inputs: `redeemScript: null`, `sigOpCount: 1`, empty `partialSigs`.
///
/// JSON field order matches `kaspa-wallet-pskt`'s BTreeMap emission
/// and the existing `create_multisig_pskb` — verified on the device's
/// strict-shape parser in `std_pskt.rs`.
fn serialize_pskb_single_sig(
    inputs: &[crate::rpc::UtxoEntry],
    outputs: &[(u64, Vec<u8>)],
) -> Result<String, String> {
    let tx_version: u16 = 0;
    let num_in = inputs.len() as u16;
    let num_out = outputs.len() as u16;

    let mut inputs_json = Vec::<serde_json::Value>::with_capacity(inputs.len());
    for utxo in inputs {
        let spk_hex = format!("0000{}", hex::encode(&utxo.script_public_key));

        let utxo_entry = serde_json::json!({
            "amount": utxo.amount,
            "scriptPublicKey": spk_hex,
            "blockDaaScore": utxo.block_daa_score,
            "isCoinbase": false
        });

        let outpoint = serde_json::json!({
            "transactionId": utxo.tx_id,
            "index": utxo.index
        });

        let input = serde_json::json!({
            "utxoEntry": utxo_entry,
            "previousOutpoint": outpoint,
            "sequence": 0u64,
            "minTime": serde_json::Value::Null,
            "partialSigs": {},
            "sighashType": 1u8,
            "redeemScript": serde_json::Value::Null,
            "sigOpCount": 1u8,
            "bip32Derivations": {},
            "finalScriptSig": serde_json::Value::Null,
            "proprietaries": {}
        });
        inputs_json.push(input);
    }

    let mut outputs_json = Vec::<serde_json::Value>::with_capacity(outputs.len());
    for (amount, script) in outputs {
        let spk_hex = format!("0000{}", hex::encode(script));
        let output = serde_json::json!({
            "amount": amount,
            "scriptPublicKey": spk_hex,
            "redeemScript": serde_json::Value::Null,
            "bip32Derivations": {},
            "proprietaries": {}
        });
        outputs_json.push(output);
    }

    let global = serde_json::json!({
        "version": 0u8,
        "txVersion": tx_version,
        "fallbackLockTime": serde_json::Value::Null,
        "inputsModifiable": false,
        "outputsModifiable": false,
        "inputCount": num_in,
        "outputCount": num_out,
        "xpubs": {},
        "id": serde_json::Value::Null,
        "proprietaries": {}
    });

    let pskt = serde_json::json!({
        "global": global,
        "inputs": inputs_json,
        "outputs": outputs_json
    });

    let pskb_body = serde_json::Value::Array(vec![pskt]);
    let json_bytes = serde_json::to_vec(&pskb_body)
        .map_err(|e| format!("serialize PSKB JSON: {}", e))?;

    let mut wire: Vec<u8> = Vec::with_capacity(4 + json_bytes.len() * 2);
    wire.extend_from_slice(b"PSKB");
    wire.extend_from_slice(hex::encode(&json_bytes).as_bytes());
    let wire_hex = hex::encode(&wire);

    Ok(wire_hex)
}

// ═══════════════════════════════════════════════════════════════════
// Multisig PSKB creation (Path 2 — sibling of create_multisig_kspt)
// ═══════════════════════════════════════════════════════════════════
//
// Same input/output semantics as create_multisig_kspt (descriptor,
// source, dest, amount, fee, change, UTXO selection) but emits an
// UNSIGNED PSKB (Kaspa-standard partially-signed bundle) instead of
// KSPT v1 binary.
//
// Wire envelope: `50534b42` (ASCII "PSKB") + hex-ASCII of a UTF-8
// JSON array wrapping one PSKT object. Matches the format that
// `finalize_to_kspt_hex`, `relay_pskb_as_kspt_v2_hex`, and
// `merge_signed_kspt_v2_into_pskb` all already consume.
//
// Why a sibling and not a mode parameter: the mainnet-verified KSPT
// construction path produced the ceremonies that fund the multisig
// address we're about to spend from. Same risk asymmetry as the
// relay sibling — duplication is fixable later; silent KSPT
// breakage loses funds.
//
// The "unsigned" PSKB has `partialSigs: {}` on every input. Device
// receives it, signs, returns a PSKB with partialSigs populated (or
// a KSPT v2 via the compact relay path, which gets merged back).

pub async fn create_multisig_pskb(
    descriptor: &str,
    source_address: &str,
    dest_address: &str,
    amount_kas: f64,
    fee: u64,
    change_address: &str,
    ws_url: &str,
    addr_index: u32,
) -> Result<String, String> {
    // ── HD address-index auto-discovery (identical to create_multisig_kspt) ──
    let final_index = if descriptor.trim().starts_with("multi_hd(") {
        let mut found: Option<u32> = None;
        for try_idx in 0..100u32 {
            let (m, pks) = parse_descriptor(descriptor, try_idx)?;
            let script = build_redeem_script(m, &pks);
            let script_hash = blake2b_hash(&script);
            let derived_addr = crate::address::encode_p2sh_address(&script_hash, "kaspa");
            if derived_addr == source_address {
                found = Some(try_idx);
                break;
            }
        }
        match found {
            Some(idx) => idx,
            None => return Err(format!(
                "Could not find address index (tried 0..99) that matches source address {}",
                source_address
            )),
        }
    } else {
        addr_index
    };

    let (m, pubkeys) = parse_descriptor(descriptor, final_index)?;
    let redeem_script = build_redeem_script(m, &pubkeys);
    let redeem_script_hex = hex::encode(&redeem_script);

    let dest_script = crate::address::address_to_script_pubkey(dest_address)?;
    let amount_sompi = (amount_kas * 100_000_000.0) as u64;

    // ── UTXO selection (identical to create_multisig_kspt) ──
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

    if selected.len() > 2 {
        return Err(format!(
            "Multisig P2SH limited to 2 inputs (selected {}). Redeem script mass exceeds standard limit. Consolidate UTXOs in batches of 2.",
            selected.len()
        ));
    }

    let change_amount = selected_total - amount_sompi - fee;
    let final_change = if change_amount > 0 && is_dust(change_amount) { 0u64 } else { change_amount };

    // ── Build outputs ──
    let mut outputs: Vec<(u64, Vec<u8>)> = vec![(amount_sompi, dest_script)];
    if final_change > 0 {
        let change_script = crate::address::address_to_script_pubkey(change_address)?;
        outputs.push((final_change, change_script));
    }

    // ── Build the PSKT JSON structure ──
    //
    // Field order matches the wire-format documentation at the top of
    // pskt.rs lines 32-82. Using serde_json::Value with explicit
    // insertion order (serde_json preserves insertion order by default
    // when the `preserve_order` feature is enabled — this crate's
    // Cargo.toml should already carry that since byte-compatibility
    // was verified on 20 Apr 2026).
    //
    // tx_version = 0 (matches the KSPT path and Kaspa consensus default).
    // sigOpCount = M per KIP §5 (corrected from N after PR #39 feedback).
    // sighashType = 1 (SIGHASH_ALL, Kaspa's only supported mode).

    let tx_version: u16 = 0;
    let num_in = selected.len() as u16;
    let num_out = outputs.len() as u16;

    // Inputs JSON
    let mut inputs_json = Vec::<serde_json::Value>::with_capacity(selected.len());
    for utxo in &selected {
        // scriptPublicKey: "<4 hex BE version><script hex>". For P2SH the
        // script_public_key bytes are just the script; version is 0 for
        // all standard outputs on mainnet today.
        let spk_hex = format!("0000{}", hex::encode(&utxo.script_public_key));

        let utxo_entry = serde_json::json!({
            "amount": utxo.amount,
            "scriptPublicKey": spk_hex,
            "blockDaaScore": utxo.block_daa_score,
            "isCoinbase": false
        });

        let outpoint = serde_json::json!({
            "transactionId": utxo.tx_id,
            "index": utxo.index
        });

        let input = serde_json::json!({
            "utxoEntry": utxo_entry,
            "previousOutpoint": outpoint,
            "sequence": 0u64,
            "minTime": serde_json::Value::Null,
            "partialSigs": {},
            "sighashType": 1u8,
            "redeemScript": redeem_script_hex,
            // sigOpCount = N (total pubkeys), not M (threshold).
            // Under the KIP, M ≤ sigOpCount ≤ N is the valid range; M
            // is the tight value under the KIP's lex-sort + ordered-
            // emission conventions and N is a safe upper bound.
            // Consensus today still evaluates P2SH-multisig sigops at
            // N — Michael Sutton noted on X 21 Apr 2026 that exact-M
            // only becomes possible with upcoming Silverscript. Until
            // then, emitting M here causes "sig op count exceeds
            // passed limit" rejections because the node counts N and
            // our PSKB declared M.
            //
            // The existing KSPT path (kspt::create_multisig_kspt
            // line 565) already emits N for the same reason. Keeping
            // the two emitters consistent prevents an asymmetric
            // mainnet failure mode.
            "sigOpCount": pubkeys.len() as u8,
            "bip32Derivations": {},
            "finalScriptSig": serde_json::Value::Null,
            "proprietaries": {}
        });
        inputs_json.push(input);
    }

    // Outputs JSON
    let mut outputs_json = Vec::<serde_json::Value>::with_capacity(outputs.len());
    for (amount, script) in &outputs {
        let spk_hex = format!("0000{}", hex::encode(script));
        let output = serde_json::json!({
            "amount": amount,
            "scriptPublicKey": spk_hex,
            "redeemScript": serde_json::Value::Null,
            "bip32Derivations": {},
            "proprietaries": {}
        });
        outputs_json.push(output);
    }

    // Global
    let global = serde_json::json!({
        "version": 0u8,
        "txVersion": tx_version,
        "fallbackLockTime": serde_json::Value::Null,
        "inputsModifiable": false,
        "outputsModifiable": false,
        "inputCount": num_in,
        "outputCount": num_out,
        "xpubs": {},
        "id": serde_json::Value::Null,
        "proprietaries": {}
    });

    // Full PSKT object
    let pskt = serde_json::json!({
        "global": global,
        "inputs": inputs_json,
        "outputs": outputs_json
    });

    // PSKB = single-element array wrapping the PSKT object
    let pskb_body = serde_json::Value::Array(vec![pskt]);
    let json_bytes = serde_json::to_vec(&pskb_body)
        .map_err(|e| format!("serialize PSKB JSON: {}", e))?;

    // Wire envelope: raw magic bytes "PSKB" + hex-ASCII of JSON,
    // whole thing then hex-encoded. Matches relay_pskb_as_kspt_v2_hex
    // inverse path at pskt.rs ~line 585 where it does
    // `hex::decode(&wire[4..])` to get back at the JSON.
    let mut wire: Vec<u8> = Vec::with_capacity(4 + json_bytes.len() * 2);
    wire.extend_from_slice(b"PSKB");
    wire.extend_from_slice(hex::encode(&json_bytes).as_bytes());
    let wire_hex = hex::encode(&wire);

    web_sys::console::log_1(
        &format!(
            "[KasSee] Multisig PSKB: {} inputs, {}-of-{}, send {}, change {}, wire hex {} chars",
            selected.len(), m, pubkeys.len(), amount_sompi, final_change, wire_hex.len()
        ).into(),
    );

    Ok(wire_hex)
}

/// Create unsigned multisig PSKB with specific UTXO indices.
/// Same as `create_multisig_pskb` but uses explicit UTXO indices
/// instead of greedy auto-selection.
pub async fn create_multisig_pskb_selected(
    descriptor: &str,
    source_address: &str,
    dest_address: &str,
    amount_kas: f64,
    fee: u64,
    change_address: &str,
    ws_url: &str,
    addr_index: u32,
    utxo_indices: &[usize],
) -> Result<String, String> {
    let final_index = if descriptor.trim().starts_with("multi_hd(") {
        let mut found: Option<u32> = None;
        for try_idx in 0..100u32 {
            let (m, pks) = parse_descriptor(descriptor, try_idx)?;
            let script = build_redeem_script(m, &pks);
            let script_hash = blake2b_hash(&script);
            let derived_addr = crate::address::encode_p2sh_address(&script_hash, "kaspa");
            if derived_addr == source_address {
                found = Some(try_idx);
                break;
            }
        }
        match found {
            Some(idx) => idx,
            None => return Err(format!(
                "Could not find address index (tried 0..99) that matches source address {}",
                source_address
            )),
        }
    } else {
        addr_index
    };

    let (m, pubkeys) = parse_descriptor(descriptor, final_index)?;
    let redeem_script = build_redeem_script(m, &pubkeys);
    let redeem_script_hex = hex::encode(&redeem_script);

    let dest_script = crate::address::address_to_script_pubkey(dest_address)?;
    let amount_sompi = (amount_kas * 100_000_000.0) as u64;

    let mut utxos = crate::rpc::fetch_utxos_for_address(ws_url, source_address).await?;
    if utxos.is_empty() {
        return Err("No UTXOs found for multisig address".into());
    }
    utxos.sort_by(|a, b| b.amount.cmp(&a.amount)
        .then_with(|| a.tx_id.cmp(&b.tx_id))
        .then_with(|| a.index.cmp(&b.index)));

    let mut selected = Vec::new();
    for &idx in utxo_indices {
        if idx >= utxos.len() {
            return Err(format!("UTXO index {} out of range (have {})", idx, utxos.len()));
        }
        selected.push(utxos[idx].clone());
    }

    let selected_total: u64 = selected.iter().map(|u| u.amount).sum();
    let total_needed = amount_sompi + fee;
    if selected_total < total_needed {
        return Err(format!(
            "Selected UTXOs: {} sompi, need {} sompi",
            selected_total, total_needed
        ));
    }

    if selected.len() > 2 {
        return Err(format!(
            "Multisig P2SH limited to 2 inputs (selected {}). Redeem script mass exceeds standard limit. Consolidate UTXOs in batches of 2.",
            selected.len()
        ));
    }

    let change_amount = selected_total - amount_sompi - fee;
    let final_change = if change_amount > 0 && is_dust(change_amount) { 0u64 } else { change_amount };

    let mut outputs: Vec<(u64, Vec<u8>)> = vec![(amount_sompi, dest_script)];
    if final_change > 0 {
        let change_script = crate::address::address_to_script_pubkey(change_address)?;
        outputs.push((final_change, change_script));
    }

    let tx_version: u16 = 0;
    let num_in = selected.len() as u16;
    let num_out = outputs.len() as u16;

    let mut inputs_json = Vec::<serde_json::Value>::with_capacity(selected.len());
    for utxo in &selected {
        let spk_hex = format!("0000{}", hex::encode(&utxo.script_public_key));
        let input = serde_json::json!({
            "utxoEntry": {
                "amount": utxo.amount,
                "scriptPublicKey": spk_hex,
                "blockDaaScore": utxo.block_daa_score,
                "isCoinbase": false
            },
            "previousOutpoint": {
                "transactionId": utxo.tx_id,
                "index": utxo.index
            },
            "sequence": 0u64,
            "minTime": serde_json::Value::Null,
            "partialSigs": {},
            "sighashType": 1u8,
            "redeemScript": redeem_script_hex,
            "sigOpCount": pubkeys.len() as u8,
            "bip32Derivations": {},
            "finalScriptSig": serde_json::Value::Null,
            "proprietaries": {}
        });
        inputs_json.push(input);
    }

    let mut outputs_json = Vec::<serde_json::Value>::with_capacity(outputs.len());
    for (amount, script) in &outputs {
        let spk_hex = format!("0000{}", hex::encode(script));
        outputs_json.push(serde_json::json!({
            "amount": amount,
            "scriptPublicKey": spk_hex,
            "redeemScript": serde_json::Value::Null,
            "bip32Derivations": {},
            "proprietaries": {}
        }));
    }

    let pskt = serde_json::json!({
        "global": {
            "version": 0u8,
            "txVersion": tx_version,
            "fallbackLockTime": serde_json::Value::Null,
            "inputsModifiable": false,
            "outputsModifiable": false,
            "inputCount": num_in,
            "outputCount": num_out,
            "xpubs": {},
            "id": serde_json::Value::Null,
            "proprietaries": {}
        },
        "inputs": inputs_json,
        "outputs": outputs_json
    });

    let pskb_body = serde_json::Value::Array(vec![pskt]);
    let json_bytes = serde_json::to_vec(&pskb_body)
        .map_err(|e| format!("serialize PSKB JSON: {}", e))?;

    let mut wire: Vec<u8> = Vec::with_capacity(4 + json_bytes.len() * 2);
    wire.extend_from_slice(b"PSKB");
    wire.extend_from_slice(hex::encode(&json_bytes).as_bytes());
    let wire_hex = hex::encode(&wire);

    web_sys::console::log_1(
        &format!(
            "[KasSee] Multisig PSKB (selected): {} inputs, {}-of-{}, send {}, change {}, wire hex {} chars",
            selected.len(), m, pubkeys.len(), amount_sompi, final_change, wire_hex.len()
        ).into(),
    );

    Ok(wire_hex)
}
