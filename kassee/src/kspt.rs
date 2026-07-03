// KasSee Web — KSPT binary format
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0
//
// kspt.rs — KSPT serialization for unsigned TX creation.
// Format: "KSPT" + version(1) + flags(1) + global + inputs + outputs
// Supports single and compound (multi-recipient) transactions.

//! Core KSPT/PSKB transaction construction plus the shared script-building
//! primitives (opcode table `covenant_ops`, push helpers, address conversion)
//! used by every covenant builder. The covenant redeem-script builders live in
//! the `kspt_*` submodules and are re-exported here as `kspt::build_*`.

use crate::bip32::WalletData;
use crate::rpc::UtxoEntry;
use k256::elliptic_curve::sec1::ToEncodedPoint;

/// Blake2b-256 hash — unkeyed (matches firmware sighash::blake2b_hash for P2SH)
pub fn blake2b_hash(data: &[u8]) -> [u8; 32] {
    let h = blake2b_simd::Params::new().hash_length(32).hash(data);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    out
}

const STORAGE_MASS_C: u64 = 1_000_000_000_000;
const MAX_STANDARD_MASS: u64 = 100_000;
const DUST_THRESHOLD: u64 = 20_000_000;

/// Check if an amount is dust (would exceed standard mass)
fn is_dust(amount: u64) -> bool {
    if amount == 0 {
        return true;
    }
    if amount >= DUST_THRESHOLD {
        return false;
    }
    let mass = STORAGE_MASS_C / amount;
    mass > MAX_STANDARD_MASS
}

/// Consensus-mirroring storage mass (KIP-9 with v2.0.1 plurality).
///
/// Each element is (amount_sompi, plurality). Plurality is 1 for every
/// standard P2PK/P2SH UTXO and 2 for a covenant_id-tagged UTXO (the
/// 32-byte covenant hash pushes the entry past one 100-byte storage
/// unit). Integer math identical to rusty-kaspa v2.0.1
/// consensus/core/src/mass/mod.rs calc_storage_mass, with saturation
/// where consensus returns None (mass "too high" either way):
///
///   harmonic term per element:  C * p^2 / amount
///   relaxed path (|O|=1, |I|=1, or |O|=|I|=2, in plurality terms):
///       max(0, harmonic_outs - harmonic_ins)
///   otherwise:
///       max(0, harmonic_outs - |I| * (C / (sum_ins / |I|)))
///
/// The previous f64 version applied the harmonic formula to inputs
/// unconditionally; on the arithmetic path consensus subtracts LESS
/// (AM >= HM), so that version underestimated storage mass exactly in
/// the multi-input-plus-change case.
pub(crate) fn storage_mass_estimate(ins: &[(u64, u64)], outs: &[(u64, u64)]) -> u64 {
    const C: u64 = STORAGE_MASS_C;

    let mut outs_plurality: u64 = 0;
    let mut harmonic_outs: u64 = 0;
    for &(amount, p) in outs {
        outs_plurality += p;
        harmonic_outs =
            harmonic_outs.saturating_add(C.saturating_mul(p).saturating_mul(p) / amount.max(1));
    }

    let ins_plurality: u64 = ins.iter().map(|&(_, p)| p).sum();
    let relaxed =
        outs_plurality == 1 || ins_plurality == 1 || (outs_plurality == 2 && ins_plurality == 2);

    if relaxed {
        let harmonic_ins = ins.iter().fold(0u64, |acc, &(amount, p)| {
            acc.saturating_add(C.saturating_mul(p).saturating_mul(p) / amount.max(1))
        });
        return harmonic_outs.saturating_sub(harmonic_ins);
    }

    let sum_ins: u64 = ins.iter().fold(0u64, |acc, &(a, _)| acc.saturating_add(a));
    let mean_ins = (sum_ins / ins_plurality.max(1)).max(1);
    let arithmetic_ins = ins_plurality.saturating_mul(C / mean_ins);
    harmonic_outs.saturating_sub(arithmetic_ins)
}

/// Create unsigned KSPT: fetch UTXOs, select coins, build binary, return hex
pub async fn create_send_kspt(
    wallet: &WalletData,
    dest_address: &str,
    amount_sompi: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, String> {
    let dest_script = crate::address::address_to_script_pubkey(dest_address)?;

    let mut all_utxos = crate::rpc::fetch_all_utxos(ws_url, wallet).await?;
    all_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

    let total_needed = amount_sompi + fee;
    let mut selected = Vec::new();
    let mut selected_total: u64 = 0;

    for utxo in all_utxos {
        selected_total += utxo.amount;
        selected.push(utxo);
        if selected_total >= total_needed {
            break;
        }
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
    let final_change = if change_amount > 0 && is_dust(change_amount) {
        0u64
    } else {
        change_amount
    };

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

/// Send to a raw script_public_key (arbitrary bytes). Used for KasFreeze test.
/// Same as create_send_kspt but takes raw SPK bytes instead of an address.
// Kept: send-to-raw-script-pubkey helper, reusable primitive.
#[allow(dead_code)]
pub async fn create_send_to_raw_spk(
    wallet: &WalletData,
    spk_hex: &str,
    amount_sompi: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, String> {
    let dest_script = hex::decode(spk_hex).map_err(|e| format!("Bad SPK hex: {}", e))?;

    let mut all_utxos = crate::rpc::fetch_all_utxos(ws_url, wallet).await?;
    all_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

    let total_needed = amount_sompi + fee;
    let mut selected = Vec::new();
    let mut selected_total: u64 = 0;

    for utxo in all_utxos {
        selected_total += utxo.amount;
        selected.push(utxo);
        if selected_total >= total_needed {
            break;
        }
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
    let final_change = if change_amount > 0 && is_dust(change_amount) {
        0u64
    } else {
        change_amount
    };

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

    let kspt_hex = serialize_kspt_multi(&selected, &outputs)?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] KasFreeze TX: {} inputs, {} sompi to {} byte SPK, change {}, {} bytes",
            selected.len(),
            amount_sompi,
            spk_hex.len() / 2,
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
            selected.len(),
            send_amount,
            fee,
            kspt_hex.len() / 2
        )
        .into(),
    );

    Ok(kspt_hex)
}

/// Create unsigned KSPT with specific UTXO indices
pub async fn create_send_kspt_selected(
    wallet: &WalletData,
    dest_address: &str,
    amount_sompi: u64,
    fee: u64,
    utxo_indices: &[usize],
    ws_url: &str,
) -> Result<String, String> {
    let dest_script = crate::address::address_to_script_pubkey(dest_address)?;

    let mut all_utxos = crate::rpc::fetch_all_utxos(ws_url, wallet).await?;
    // Sort to match the JS-side order (cachedUtxos.sort by amount desc,
    // then tx_id asc + index asc as tiebreakers for determinism).
    all_utxos.sort_by(|a, b| {
        b.amount
            .cmp(&a.amount)
            .then_with(|| a.tx_id.cmp(&b.tx_id))
            .then_with(|| a.index.cmp(&b.index))
    });

    let mut selected = Vec::new();
    for &idx in utxo_indices {
        if idx >= all_utxos.len() {
            return Err(format!(
                "UTXO index {} out of range (have {})",
                idx,
                all_utxos.len()
            ));
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
    let final_change = if change_amount > 0 && is_dust(change_amount) {
        0u64
    } else {
        change_amount
    };

    let change_script = if final_change > 0 {
        let chg_idx = wallet.next_change_index;
        if chg_idx >= wallet.change_addresses.len() {
            return Err("No more change addresses".into());
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

    serialize_kspt_multi(&selected, &outputs)
}

/// Create compound unsigned KSPT: multiple recipients in one transaction
pub async fn create_compound_kspt(
    wallet: &WalletData,
    recipients_json: &str,
    fee: u64,
    ws_url: &str,
) -> Result<String, String> {
    // Parse recipients: [{"address":"kaspa:...","amount_sompi":"150000000"}, ...]
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
        let addr = r["address"]
            .as_str()
            .ok_or_else(|| format!("Recipient {}: missing address", i + 1))?;
        let amount_sompi = r["amount_sompi"]
            .as_str()
            .ok_or_else(|| format!("Recipient {}: missing amount_sompi", i + 1))?
            .parse::<u64>()
            .map_err(|_| format!("Recipient {}: invalid amount_sompi", i + 1))?;

        if amount_sompi == 0 {
            return Err(format!("Recipient {}: amount must be > 0", i + 1));
        }
        if is_dust(amount_sompi) {
            return Err(format!(
                "Recipient {}: amount too small ({} sompi)",
                i + 1,
                amount_sompi
            ));
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
        if selected_total >= total_needed {
            break;
        }
    }

    if selected_total < total_needed {
        return Err(format!(
            "Insufficient funds: have {} sompi ({:.8} KAS), need {} sompi",
            selected_total,
            selected_total as f64 / 1e8,
            total_needed,
        ));
    }

    // Change
    let change_amount = selected_total - total_send - fee;
    let final_change = if change_amount > 0 && is_dust(change_amount) {
        0u64
    } else {
        change_amount
    };

    if final_change > 0 {
        let chg_idx = wallet.next_change_index;
        if chg_idx >= wallet.change_addresses.len() {
            return Err("No more change addresses".into());
        }
        let chg_script =
            crate::address::address_to_script_pubkey(&wallet.change_addresses[chg_idx])?;
        outputs.push((final_change, chg_script));
    }

    let kspt_hex = serialize_kspt_multi(&selected, &outputs)?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] Compound TX: {} inputs, {} recipients, total send {}, change {}, {} bytes",
            selected.len(),
            recipients.len(),
            total_send,
            final_change,
            kspt_hex.len() / 2
        )
        .into(),
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
        let tx_id_bytes = hex::decode(&utxo.tx_id).map_err(|e| format!("Bad tx_id: {}", e))?;
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
        let m: u8 = parts[0]
            .trim()
            .parse()
            .map_err(|_| "Invalid M value in descriptor".to_string())?;

        let mut pubkeys = Vec::new();
        for xpub_hex in &parts[1..] {
            let xpub_hex = xpub_hex.trim();
            if xpub_hex.len() != 130 {
                return Err(format!(
                    "Cosigner xpub must be 130 hex chars (33B pubkey + 32B chain code), got {}",
                    xpub_hex.len()
                ));
            }
            let xpub_bytes =
                hex::decode(xpub_hex).map_err(|e| format!("Invalid xpub hex: {}", e))?;
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
        let m: u8 = parts[0]
            .trim()
            .parse()
            .map_err(|_| "Invalid M value in descriptor".to_string())?;

        let mut pubkeys = Vec::new();
        for pk_hex in &parts[1..] {
            let pk_hex = pk_hex.trim();
            if pk_hex.len() != 64 {
                return Err(format!("Pubkey must be 64 hex chars, got {}", pk_hex.len()));
            }
            let pk_bytes = hex::decode(pk_hex).map_err(|e| format!("Invalid pubkey hex: {}", e))?;
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
    script.push(0xAE); // OP_CHECKMULTISIG

    script
}

/// Create unsigned multisig KSPT: fetch UTXOs for P2SH address, build TX with redeem scripts
#[allow(clippy::too_many_arguments)]
pub async fn create_multisig_kspt(
    descriptor: &str,
    source_address: &str,
    dest_address: &str,
    amount_sompi: u64,
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
            None => {
                return Err(format!(
                    "Could not find address index (tried 0..99) that matches source address {}",
                    source_address
                ))
            }
        }
    } else {
        addr_index // legacy: use as-is (typically 0)
    };

    let (m, pubkeys) = parse_descriptor(descriptor, final_index)?;
    let redeem_script = build_redeem_script(m, &pubkeys);

    let dest_script = crate::address::address_to_script_pubkey(dest_address)?;

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
        if selected_total >= total_needed {
            break;
        }
    }

    if selected_total < total_needed {
        return Err(format!(
            "Insufficient funds in multisig: have {} sompi, need {}",
            selected_total, total_needed
        ));
    }

    if selected.len() > 3 {
        return Err(format!(
            "Multisig P2SH limited to 3 inputs (selected {}). Node rejects 4+ inputs. Consolidate UTXOs in batches of 3.",
            selected.len()
        ));
    }

    let change_amount = selected_total - amount_sompi - fee;
    let final_change = if change_amount > 0 && is_dust(change_amount) {
        0u64
    } else {
        change_amount
    };

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
    let kspt_hex =
        serialize_kspt_multisig(&selected, &outputs, &redeem_script, pubkeys.len() as u8)?;

    web_sys::console::log_1(
        &format!(
            "[KasSee] Multisig TX: {} inputs, {}-of-{}, send {}, change {}, {} bytes",
            selected.len(),
            m,
            pubkeys.len(),
            amount_sompi,
            final_change,
            kspt_hex.len() / 2
        )
        .into(),
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
        let tx_id_bytes = hex::decode(&utxo.tx_id).map_err(|e| format!("Bad tx_id: {}", e))?;
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
    amount_sompi: u64,
    fee: u64,
    ws_url: &str,
) -> Result<String, String> {
    let dest_script = crate::address::address_to_script_pubkey(dest_address)?;

    let mut all_utxos = crate::rpc::fetch_all_utxos(ws_url, wallet).await?;
    all_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));

    let total_needed = amount_sompi + fee;
    let mut selected = Vec::new();
    let mut selected_total: u64 = 0;

    for utxo in all_utxos {
        selected_total += utxo.amount;
        selected.push(utxo);
        if selected_total >= total_needed {
            break;
        }
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

    let final_change = if change_amount > 0 && is_dust(change_amount) {
        0u64
    } else {
        change_amount
    };

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
            selected.len(),
            amount_sompi,
            final_change,
            pskb_hex.len()
        )
        .into(),
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
            selected.len(),
            send_amount,
            fee,
            pskb_hex.len()
        )
        .into(),
    );

    Ok(pskb_hex)
}

/// Create unsigned PSKB with specific UTXO indices.
pub async fn create_send_pskb_selected(
    wallet: &WalletData,
    dest_address: &str,
    amount_sompi: u64,
    fee: u64,
    utxo_indices: &[usize],
    ws_url: &str,
) -> Result<String, String> {
    let dest_script = crate::address::address_to_script_pubkey(dest_address)?;

    let mut all_utxos = crate::rpc::fetch_all_utxos(ws_url, wallet).await?;
    // Sort to match the JS-side order (cachedUtxos.sort by amount desc,
    // then tx_id asc + index asc as tiebreakers for determinism).
    all_utxos.sort_by(|a, b| {
        b.amount
            .cmp(&a.amount)
            .then_with(|| a.tx_id.cmp(&b.tx_id))
            .then_with(|| a.index.cmp(&b.index))
    });

    let mut selected = Vec::new();
    for &idx in utxo_indices {
        if idx >= all_utxos.len() {
            return Err(format!(
                "UTXO index {} out of range (have {})",
                idx,
                all_utxos.len()
            ));
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
    let final_change = if change_amount > 0 && is_dust(change_amount) {
        0u64
    } else {
        change_amount
    };

    let change_script = if final_change > 0 {
        let chg_idx = wallet.next_change_index;
        if chg_idx >= wallet.change_addresses.len() {
            return Err("No more change addresses".into());
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

    serialize_pskb_single_sig(&selected, &outputs)
}

/// Create unsigned PSKB with explicit UTXO data (no re-fetch needed).
/// Used when JS has cached UTXOs that may not match a fresh node query.
/// Fee is auto-adjusted upward if storage mass requires a higher fee.
pub async fn create_send_pskb_with_utxos(
    wallet: &WalletData,
    dest_address: &str,
    amount_sompi: u64,
    fee: u64,
    selected: Vec<crate::rpc::UtxoEntry>,
    _ws_url: &str,
) -> Result<String, String> {
    let dest_script = crate::address::address_to_script_pubkey(dest_address)?;

    if selected.is_empty() {
        return Err("No UTXOs provided".into());
    }

    let selected_total: u64 = selected.iter().map(|u| u.amount).sum();

    // Auto-compute fee from storage mass with a 3-pass iteration to resolve
    // the circular dependency: fee depends on change, change depends on fee.
    // Storage mass via storage_mass_estimate (integer, consensus-mirroring,
    // correct arithmetic-vs-relaxed input path). Plain sends: plurality 1
    // on every input and output.
    let min_fee_floor = 300_000u64;
    let compute_mass = 800u64 * selected.len() as u64 + 2000;
    let ins: Vec<(u64, u64)> = selected.iter().map(|u| (u.amount, 1u64)).collect();

    let mut actual_fee = min_fee_floor;
    for _pass in 0..3 {
        let change_est = if selected_total > amount_sompi + actual_fee {
            selected_total - amount_sompi - actual_fee
        } else {
            0
        };
        let outs: Vec<(u64, u64)> = if change_est > 0 && !is_dust(change_est) {
            vec![(amount_sompi, 1u64), (change_est, 1u64)]
        } else {
            vec![(amount_sompi, 1u64)]
        };
        let storage_mass = storage_mass_estimate(&ins, &outs);
        let total_mass = storage_mass.max(compute_mass);
        // 110% safety margin on mass fee
        let mass_fee = total_mass.saturating_mul(110);
        actual_fee = mass_fee.max(min_fee_floor);
    }
    // Use JS fee if higher (user explicitly chose Priority)
    if fee > actual_fee {
        actual_fee = fee;
    }

    let total_needed = amount_sompi + actual_fee;
    if selected_total < total_needed {
        return Err(format!(
            "Selected UTXOs: {} sompi, need {} sompi (fee auto-adjusted to {} for storage mass)",
            selected_total, total_needed, actual_fee,
        ));
    }

    let change_amount = selected_total - amount_sompi - actual_fee;
    let final_change = if change_amount > 0 && is_dust(change_amount) {
        0u64
    } else {
        change_amount
    };

    let change_script = if final_change > 0 {
        let chg_idx = wallet.next_change_index;
        if chg_idx >= wallet.change_addresses.len() {
            return Err("No more change addresses".into());
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
        let addr = r["address"]
            .as_str()
            .ok_or_else(|| format!("Recipient {}: missing address", i + 1))?;
        let amount_sompi = r["amount_sompi"]
            .as_str()
            .ok_or_else(|| format!("Recipient {}: missing amount_sompi", i + 1))?
            .parse::<u64>()
            .map_err(|_| format!("Recipient {}: invalid amount_sompi", i + 1))?;

        if amount_sompi == 0 {
            return Err(format!("Recipient {}: amount must be > 0", i + 1));
        }
        if is_dust(amount_sompi) {
            return Err(format!(
                "Recipient {}: amount too small ({} sompi)",
                i + 1,
                amount_sompi
            ));
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
        if selected_total >= total_needed {
            break;
        }
    }

    if selected_total < total_needed {
        return Err(format!(
            "Insufficient funds: have {} sompi ({:.8} KAS), need {} sompi",
            selected_total,
            selected_total as f64 / 1e8,
            total_needed,
        ));
    }

    let change_amount = selected_total - total_send - fee;
    let final_change = if change_amount > 0 && is_dust(change_amount) {
        0u64
    } else {
        change_amount
    };

    if final_change > 0 {
        let chg_idx = wallet.next_change_index;
        if chg_idx >= wallet.change_addresses.len() {
            return Err("No more change addresses".into());
        }
        let chg_script =
            crate::address::address_to_script_pubkey(&wallet.change_addresses[chg_idx])?;
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
    let json_bytes =
        serde_json::to_vec(&pskb_body).map_err(|e| format!("serialize PSKB JSON: {}", e))?;

    let mut wire: Vec<u8> = Vec::with_capacity(4 + json_bytes.len() * 2);
    wire.extend_from_slice(b"PSKB");
    wire.extend_from_slice(hex::encode(&json_bytes).as_bytes());
    let wire_hex = hex::encode(&wire);

    Ok(wire_hex)
}

/// Output descriptor for PSKB with optional covenant binding.
pub struct PskbOutput {
    pub amount: u64,
    pub script: Vec<u8>,
    pub covenant: Option<(u16, [u8; 32])>, // (authorizing_input, covenant_id)
}

/// Serialize a single-sig PSKB with covenant binding support (KIP-20).
///
/// Same as serialize_pskb_single_sig but outputs carry covenant data.
/// TX version is set to 1 (required for covenant sighash coverage).
pub fn serialize_pskb_with_covenants(
    inputs: &[crate::rpc::UtxoEntry],
    outputs: &[PskbOutput],
) -> Result<String, String> {
    let tx_version: u16 = 1; // Covenant binding on outputs requires version >= 1
    let num_in = inputs.len() as u16;
    let num_out = outputs.len() as u16;

    let mut inputs_json = Vec::<serde_json::Value>::with_capacity(inputs.len());
    for utxo in inputs {
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
            "redeemScript": serde_json::Value::Null,
            "sigOpCount": 1u8,
            "bip32Derivations": {},
            "finalScriptSig": serde_json::Value::Null,
            "proprietaries": {}
        });
        inputs_json.push(input);
    }

    let mut outputs_json = Vec::<serde_json::Value>::with_capacity(outputs.len());
    for out in outputs {
        let spk_hex = format!("0000{}", hex::encode(&out.script));
        let cov_binding = match &out.covenant {
            None => serde_json::Value::Null,
            Some((auth_input, cov_id)) => serde_json::json!({
                "authorizingInput": *auth_input,
                "covenantId": hex::encode(cov_id)
            }),
        };
        let output = serde_json::json!({
            "amount": out.amount,
            "scriptPublicKey": spk_hex,
            "covenantBinding": cov_binding,
            "redeemScript": serde_json::Value::Null,
            "bip32Derivations": {},
            "proprietaries": {}
        });
        outputs_json.push(output);
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
    let json_bytes =
        serde_json::to_vec(&pskb_body).map_err(|e| format!("serialize covenant PSKB: {}", e))?;

    let mut wire: Vec<u8> = Vec::with_capacity(4 + json_bytes.len() * 2);
    wire.extend_from_slice(b"PSKB");
    wire.extend_from_slice(hex::encode(&json_bytes).as_bytes());
    Ok(hex::encode(&wire))
}

/// Same as `serialize_pskb_with_covenants` but includes a TX payload in the PSKB global.
pub fn serialize_pskb_with_covenants_and_payload(
    inputs: &[crate::rpc::UtxoEntry],
    outputs: &[PskbOutput],
    payload: &[u8],
) -> Result<String, String> {
    // tx_version must be 1 when any output carries a covenant binding (the node
    // requires version >= 1 for covenant outputs and covers the binding in the
    // sighash); otherwise 0 for a plain payload TX.
    let tx_version: u16 = if outputs.iter().any(|o| o.covenant.is_some()) {
        1
    } else {
        0
    };
    let num_in = inputs.len() as u16;
    let num_out = outputs.len() as u16;

    let mut inputs_json = Vec::<serde_json::Value>::with_capacity(inputs.len());
    for utxo in inputs {
        let spk_hex = format!("0000{}", hex::encode(&utxo.script_public_key));
        inputs_json.push(serde_json::json!({
            "utxoEntry": { "amount": utxo.amount, "scriptPublicKey": spk_hex, "blockDaaScore": utxo.block_daa_score, "isCoinbase": false },
            "previousOutpoint": { "transactionId": utxo.tx_id, "index": utxo.index },
            "sequence": 0u64, "minTime": serde_json::Value::Null, "partialSigs": {}, "sighashType": 1u8,
            "redeemScript": serde_json::Value::Null, "sigOpCount": 1u8, "bip32Derivations": {},
            "finalScriptSig": serde_json::Value::Null, "proprietaries": {}
        }));
    }

    let mut outputs_json = Vec::<serde_json::Value>::with_capacity(outputs.len());
    for out in outputs {
        let spk_hex = format!("0000{}", hex::encode(&out.script));
        let cov_binding = match &out.covenant {
            None => serde_json::Value::Null,
            Some((auth_input, cov_id)) => {
                serde_json::json!({ "authorizingInput": *auth_input, "covenantId": hex::encode(cov_id) })
            }
        };
        outputs_json.push(serde_json::json!({
            "amount": out.amount, "scriptPublicKey": spk_hex, "covenantBinding": cov_binding,
            "redeemScript": serde_json::Value::Null, "bip32Derivations": {}, "proprietaries": {}
        }));
    }

    let pskt = serde_json::json!({
        "global": {
            "version": 0u8, "txVersion": tx_version, "txPayload": hex::encode(payload),
            "fallbackLockTime": serde_json::Value::Null, "inputsModifiable": false, "outputsModifiable": false,
            "inputCount": num_in, "outputCount": num_out, "xpubs": {}, "id": serde_json::Value::Null, "proprietaries": {}
        },
        "inputs": inputs_json,
        "outputs": outputs_json
    });

    let pskb_body = serde_json::Value::Array(vec![pskt]);
    let json_bytes = serde_json::to_vec(&pskb_body)
        .map_err(|e| format!("serialize covenant PSKB w/payload: {}", e))?;

    let mut wire: Vec<u8> = Vec::with_capacity(4 + json_bytes.len() * 2);
    wire.extend_from_slice(b"PSKB");
    wire.extend_from_slice(hex::encode(&json_bytes).as_bytes());
    Ok(hex::encode(&wire))
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

#[allow(clippy::too_many_arguments)]
pub async fn create_multisig_pskb(
    descriptor: &str,
    source_address: &str,
    dest_address: &str,
    amount_sompi: u64,
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
            None => {
                return Err(format!(
                    "Could not find address index (tried 0..99) that matches source address {}",
                    source_address
                ))
            }
        }
    } else {
        addr_index
    };

    let (m, pubkeys) = parse_descriptor(descriptor, final_index)?;
    let redeem_script = build_redeem_script(m, &pubkeys);
    let redeem_script_hex = hex::encode(&redeem_script);

    let dest_script = crate::address::address_to_script_pubkey(dest_address)?;

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
        if selected_total >= total_needed {
            break;
        }
    }
    if selected_total < total_needed {
        return Err(format!(
            "Insufficient funds in multisig: have {} sompi, need {}",
            selected_total, total_needed
        ));
    }

    if selected.len() > 3 {
        return Err(format!(
            "Multisig P2SH limited to 3 inputs (selected {}). Node rejects 4+ inputs. Consolidate UTXOs in batches of 3.",
            selected.len()
        ));
    }

    let change_amount = selected_total - amount_sompi - fee;
    let final_change = if change_amount > 0 && is_dust(change_amount) {
        0u64
    } else {
        change_amount
    };

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
    let json_bytes =
        serde_json::to_vec(&pskb_body).map_err(|e| format!("serialize PSKB JSON: {}", e))?;

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
            selected.len(),
            m,
            pubkeys.len(),
            amount_sompi,
            final_change,
            wire_hex.len()
        )
        .into(),
    );

    Ok(wire_hex)
}

/// Create unsigned multisig PSKB with specific UTXO indices.
/// Same as `create_multisig_pskb` but uses explicit UTXO indices
/// instead of greedy auto-selection.
#[allow(clippy::too_many_arguments)]
pub async fn create_multisig_pskb_selected(
    descriptor: &str,
    source_address: &str,
    dest_address: &str,
    amount_sompi: u64,
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
            None => {
                return Err(format!(
                    "Could not find address index (tried 0..99) that matches source address {}",
                    source_address
                ))
            }
        }
    } else {
        addr_index
    };

    let (m, pubkeys) = parse_descriptor(descriptor, final_index)?;
    let redeem_script = build_redeem_script(m, &pubkeys);
    let redeem_script_hex = hex::encode(&redeem_script);

    let dest_script = crate::address::address_to_script_pubkey(dest_address)?;

    let mut utxos = crate::rpc::fetch_utxos_for_address(ws_url, source_address).await?;
    if utxos.is_empty() {
        return Err("No UTXOs found for multisig address".into());
    }
    utxos.sort_by(|a, b| {
        b.amount
            .cmp(&a.amount)
            .then_with(|| a.tx_id.cmp(&b.tx_id))
            .then_with(|| a.index.cmp(&b.index))
    });

    let mut selected = Vec::new();
    for &idx in utxo_indices {
        if idx >= utxos.len() {
            return Err(format!(
                "UTXO index {} out of range (have {})",
                idx,
                utxos.len()
            ));
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

    if selected.len() > 3 {
        return Err(format!(
            "Multisig P2SH limited to 3 inputs (selected {}). Node rejects 4+ inputs. Consolidate UTXOs in batches of 3.",
            selected.len()
        ));
    }

    let change_amount = selected_total - amount_sompi - fee;
    let final_change = if change_amount > 0 && is_dust(change_amount) {
        0u64
    } else {
        change_amount
    };

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
    let json_bytes =
        serde_json::to_vec(&pskb_body).map_err(|e| format!("serialize PSKB JSON: {}", e))?;

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

// ═══════════════════════════════════════════════════════════════════════
// Covenant script builders (KIP-10 introspection opcodes)
// ═══════════════════════════════════════════════════════════════════════

// Kept: retained for future use; not currently wired.
#[allow(dead_code)]
mod covenant_ops {
    pub const OP_0: u8 = 0x00;
    pub const OP_IF: u8 = 0x63;
    pub const OP_ELSE: u8 = 0x67;
    pub const OP_ENDIF: u8 = 0x68;
    pub const OP_VERIFY: u8 = 0x69;
    pub const OP_DROP: u8 = 0x75;
    pub const OP_EQUAL: u8 = 0x87;
    pub const OP_EQUALVERIFY: u8 = 0x88;
    pub const OP_SUB: u8 = 0x94;
    pub const OP_MUL: u8 = 0x95;
    pub const OP_DIV: u8 = 0x96;
    pub const OP_LESSTHANOREQUAL: u8 = 0xa1;
    pub const OP_GREATERTHANOREQUAL: u8 = 0xa2;
    pub const OP_CHECKSIG: u8 = 0xac;
    pub const OP_CHECKSIGVERIFY: u8 = 0xad;
    pub const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb0;
    pub const OP_CHECKSEQUENCEVERIFY: u8 = 0xb1;
    pub const OP_TX_INPUT_COUNT: u8 = 0xb3;
    pub const OP_TX_OUTPUT_COUNT: u8 = 0xb4;
    pub const OP_TX_LOCKTIME: u8 = 0xb5;
    pub const OP_TX_INPUT_INDEX: u8 = 0xb9;
    pub const OP_TX_INPUT_AMOUNT: u8 = 0xbe;
    pub const OP_TX_INPUT_SPK: u8 = 0xbf;
    pub const OP_TX_OUTPUT_AMOUNT: u8 = 0xc2;
    pub const OP_TX_OUTPUT_SPK: u8 = 0xc3;

    // Stack-reorder + substr opcodes used by the rollup-state covenant.
    // PICK/ROLL copy/move a depth-N item to the top; the *_SUBSTR ops slice a
    // byte range out of the tx payload / an input's full (version-prefixed) SPK.
    pub const OP_PICK: u8 = 0x79; // pop loc -> copy dstack[depth-loc] to top
    pub const OP_ROLL: u8 = 0x7a; // pop loc -> move dstack[depth-loc] to top
    pub const OP_TX_PAYLOAD_SUBSTR: u8 = 0xb8; // pop [start,end] -> push payload[start..end]
    pub const OP_TX_INPUT_SPK_SUBSTR: u8 = 0xc6; // pop [idx,start,end] -> push utxo[idx].spk[start..end]
    pub const OP_BLAKE2B: u8 = 0xaa;
    pub const OP_SHA256: u8 = 0xa8;
    pub const OP_CHECKSIGFROMSTACK: u8 = 0xd7;
    pub const OP_DUP: u8 = 0x76;
    pub const OP_SWAP: u8 = 0x7c;
    pub const OP_NOT: u8 = 0x91;
    pub const OP_1: u8 = 0x51;

    // String/bitwise opcodes (unlocked with covenants_enabled)
    pub const OP_CAT: u8 = 0x7e; // pop x2, pop x1, push x1||x2
    pub const OP_SUBSTR: u8 = 0x7f; // pop len, pop offset, pop str → push substr
    pub const OP_SIZE: u8 = 0x82; // push size of top item (without removing)
    pub const OP_AND: u8 = 0x84; // bitwise AND
    pub const OP_OR_BITWISE: u8 = 0x85; // bitwise OR
    pub const OP_XOR: u8 = 0x86; // bitwise XOR
    pub const OP_MOD: u8 = 0x97; // modulo
    pub const OP_ADD: u8 = 0x93; // addition
    pub const OP_NUMEQUAL: u8 = 0x9c; // numeric equality (a b -> a==b)
    pub const OP_NUMEQUALVERIFY: u8 = 0x9d; // numeric equality + VERIFY (a b -> fail unless a==b)

    // KIP-20 covenant identity opcodes (Toccata)
    pub const OP_AUTH_OUTPUT_COUNT: u8 = 0xcb; // pop input_idx → push #outputs it authorizes
    pub const OP_AUTH_OUTPUT_IDX: u8 = 0xcc; // pop (input_idx, k) → push k-th authorized output index
    pub const OP_INPUT_COVENANT_ID: u8 = 0xcf; // pop input_idx → push that input's covenant_id
    pub const OP_COV_INPUT_COUNT: u8 = 0xd0; // pop covenant_id → push count of inputs with that id
    pub const OP_COV_OUTPUT_COUNT: u8 = 0xd2; // pop covenant_id → push count of outputs with that id
    pub const OP_COV_OUTPUT_IDX: u8 = 0xd3; // pop (covenant_id, k) → push k-th output index with that id
    pub const OP_OUTPUT_COVENANT_ID: u8 = 0xd5; // pop output_idx → push that output's covenant_id
    pub const OP_OUTPUT_AUTHORIZING_INPUT: u8 = 0xd6; // pop output_idx → push which input authorizes it

    // ZK precompile (Toccata)
    pub const OP_ZK_PRECOMPILE: u8 = 0xa6; // Groth16/R0Succinct verifier
}

fn push_int(script: &mut Vec<u8>, value: u64) {
    if value == 0 {
        script.push(covenant_ops::OP_0);
    } else if value <= 16 {
        script.push(0x50 + value as u8);
    } else {
        let mut v = value;
        let mut bytes = Vec::new();
        while v > 0 {
            bytes.push((v & 0xff) as u8);
            v >>= 8;
        }
        if bytes.last().is_some_and(|b| b & 0x80 != 0) {
            bytes.push(0x00);
        }
        script.push(bytes.len() as u8);
        script.extend_from_slice(&bytes);
    }
}

fn push_pubkey(script: &mut Vec<u8>, pubkey: &[u8; 32]) {
    script.push(0x20);
    script.extend_from_slice(pubkey);
}

/// Extract the CLTV (OP_CHECKLOCKTIMEVERIFY) locktime value from a
/// redeem script, if present. Scans for 0xB0 and reads the preceding push.
/// Returns 0 if no CLTV found.
pub fn extract_cltv_locktime(redeem: &[u8]) -> u64 {
    let mut i = 0;
    let mut last_push_val: u64 = 0;
    while i < redeem.len() {
        let op = redeem[i];
        if op == 0xB0 {
            return last_push_val;
        }
        if op == 0x00 {
            last_push_val = 0;
            i += 1;
        } else if (0x51..=0x60).contains(&op) {
            last_push_val = (op - 0x50) as u64;
            i += 1;
        } else if (0x01..=0x4b).contains(&op) {
            let len = op as usize;
            if i + 1 + len <= redeem.len() {
                last_push_val = read_script_int(&redeem[i + 1..i + 1 + len]);
            }
            i += 1 + len;
        } else if op == 0x4c {
            if i + 1 < redeem.len() {
                let len = redeem[i + 1] as usize;
                if i + 2 + len <= redeem.len() {
                    last_push_val = read_script_int(&redeem[i + 2..i + 2 + len]);
                }
                i += 2 + len;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    0
}

/// Extract the CSV (OP_CHECKSEQUENCEVERIFY) minimum sequence value from a
/// redeem script, if present. Scans for 0xB1 and reads the preceding push.
/// Returns 0 if no CSV found.
pub fn extract_csv_sequence(redeem: &[u8]) -> u64 {
    // Find OP_CHECKSEQUENCEVERIFY (0xB1) and read the preceding push
    let mut i = 0;
    let mut last_push_val: u64 = 0;
    while i < redeem.len() {
        let op = redeem[i];
        if op == 0xB1 {
            // Found CSV — last_push_val has the sequence
            return last_push_val;
        }
        // Track push values
        if op == 0x00 {
            // OP_0
            last_push_val = 0;
            i += 1;
        } else if (0x51..=0x60).contains(&op) {
            // OP_1 through OP_16 (small integer opcodes)
            last_push_val = (op - 0x50) as u64;
            i += 1;
        } else if (0x01..=0x4b).contains(&op) {
            // Direct push: op bytes follow
            let len = op as usize;
            if i + 1 + len <= redeem.len() {
                let data = &redeem[i + 1..i + 1 + len];
                last_push_val = read_script_int(data);
            }
            i += 1 + len;
        } else if op == 0x4c {
            // OP_PUSHDATA1
            if i + 1 < redeem.len() {
                let len = redeem[i + 1] as usize;
                if i + 2 + len <= redeem.len() {
                    last_push_val = read_script_int(&redeem[i + 2..i + 2 + len]);
                }
                i += 2 + len;
            } else {
                i += 1;
            }
        } else {
            // Non-push op — don't reset, CSV might follow immediately
            i += 1;
        }
    }
    0
}

/// Read a little-endian script integer (unsigned, up to 8 bytes).
fn read_script_int(data: &[u8]) -> u64 {
    let mut val: u64 = 0;
    for (idx, &b) in data.iter().enumerate().take(8) {
        val |= (b as u64) << (idx * 8);
    }
    val
}

/// Push variable-length data onto the script (for SPK bytes etc).
fn push_data(script: &mut Vec<u8>, data: &[u8]) {
    if data.len() <= 75 {
        script.push(data.len() as u8);
    } else if data.len() <= 255 {
        script.push(0x4c); // OP_PUSHDATA1
        script.push(data.len() as u8);
    } else if data.len() <= 65535 {
        script.push(0x4d); // OP_PUSHDATA2
        script.push((data.len() & 0xff) as u8);
        script.push((data.len() >> 8) as u8);
    } else {
        script.push(0x4e); // OP_PUSHDATA4 (seals > 65535 bytes, e.g. RISC0 ~222KB)
        script.push((data.len() & 0xff) as u8);
        script.push(((data.len() >> 8) & 0xff) as u8);
        script.push(((data.len() >> 16) & 0xff) as u8);
        script.push(((data.len() >> 24) & 0xff) as u8);
    }
    script.extend_from_slice(data);
}

#[path = "kspt_covenant.rs"]
mod covenant_builders;
pub use covenant_builders::*;

pub fn covenant_script_to_address(redeem_script: &[u8], prefix: &str) -> Result<String, String> {
    let script_hash = blake2b_hash(redeem_script);
    Ok(crate::address::encode_p2sh_address(&script_hash, prefix))
}

// ═══════════════════════════════════════════════════════════════════
// State Machine Covenant (Supply Chain / Traceability)
// ═══════════════════════════════════════════════════════════════════

#[path = "kspt_state_machine.rs"]
mod state_machine;
pub use state_machine::*;

// ═══════════════════════════════════════════════════════════════════
// Commit-Reveal Covenant (MEV Resistance / Fair Protocols)
// ═══════════════════════════════════════════════════════════════════

#[path = "kspt_commit_reveal.rs"]
mod commit_reveal;
pub use commit_reveal::*;

// ═══════════════════════════════════════════════════════════════════
// ZK Proof Covenant (Groth16 via OP_ZK_PRECOMPILE 0xa6)
// ═══════════════════════════════════════════════════════════════════

/// Compute the required sigOpCount for a ZK covenant spend.
///
/// Groth16 verification costs Gram(1000 * 140) = 14_000_000 script units.
/// Budget formula: budget = sigOpCount × 100_000 + 9_999
/// Required: budget >= groth16_cost + checksigverify_cost
///
/// CHECKSIGVERIFY costs 1 sigop via standard sigop counting.
/// OpZkPrecompile costs via consume_script_units (not sigop).
///
/// So sigOpCount must cover both:
///   sigOpCount × 100_000 + 9_999 >= 14_000_000
///   sigOpCount >= ceil((14_000_000 - 9_999) / 100_000) = 140
///
/// But we also consume 1 sigop for CHECKSIGVERIFY, which is part of
/// the sigop budget. Actually, sigOpCount is the declared count in the
/// UTXO entry — it's a field the transaction creator sets. The node
/// validates that the actual sigop consumption doesn't exceed
/// sigOpCount × SCRIPT_UNITS_PER_SIGOP_COUNT_UNIT.
///
/// Keeping it simple: 145 covers Groth16 (14M) + CHECKSIGVERIFY (~100K)
/// + BLAKE2B VK hash verification (~100K for 296 bytes) + margin.
/// Required sigOpCount for a Groth16-gated covenant spend on toc5/1.3.0.
///
/// Runtime cost is metered against budget = sigOpCount * 100_000 + 9_999:
///   - flat Groth16 tag cost:        Gram(140_000) = 14_000_000 script units
///   - per-VK-element (toc5):        (n_public_inputs + 1) * 250_000
///   - one CHECKSIG-family op:       100_000
///   - OP_BLAKE2B over the VK:       2 * vk_len  (~592 for a 296-byte VK)
///   - pushed bytes (1:1):           VK, proof, inputs, sig, redeem, vk_hash, tag
/// n_public_inputs must equal the circuit public-input count (VK gamma_abc len
/// is n+1). Includes a fixed safety margin, rounds up, capped at 255.
/// Script-unit budget for a Groth16-gated covenant spend with `n_public_inputs`
/// public inputs. Single source of truth shared by sigOpCount sizing and the
/// min-fee derivation below, so the two can never drift.
///
/// Costs mirror rusty-kaspa v2.0.0:
///   TAG        = Gram(140_000) base for the Groth16 OpZkPrecompile tag (tags.rs)
///   VK_ELEMENT = GROTH16_GAMMA_ABC_G1_ELEMENT_SCRIPT_UNITS (groth16/mod.rs), (n+1) elements
///   CHECKSIG   = one CHECKSIG-family op
///   BLAKE2B_VK = OP_BLAKE2B over the VK
///   PUSH_BYTES = pushed bytes (VK, proof, inputs, sig, redeem, vk_hash, tag), 1:1
///   SAFETY     = fixed margin
#[allow(clippy::doc_lazy_continuation)]
pub const fn zk_groth16_script_units(n_public_inputs: u64) -> u64 {
    const TAG: u64 = 14_000_000;
    const VK_ELEMENT: u64 = 250_000;
    const CHECKSIG: u64 = 100_000;
    const BLAKE2B_VK: u64 = 640;
    const PUSH_BYTES: u64 = 2_000;
    const SAFETY: u64 = 50_000;
    TAG + (n_public_inputs + 1) * VK_ELEMENT + CHECKSIG + BLAKE2B_VK + PUSH_BYTES + SAFETY
}

pub const fn zk_groth16_sig_op_count(n_public_inputs: u64) -> u8 {
    const FREE: u64 = 9_999;
    let needed = zk_groth16_script_units(n_public_inputs);
    let sigops = (needed - FREE).div_ceil(100_000);
    if sigops > 255 {
        255
    } else {
        sigops as u8
    }
}

/// Minimum relay fee (sompi) for a Groth16-gated covenant spend with
/// `n_public_inputs` public inputs, under the Toccata fee model in
/// rusty-kaspa v2.0.0.
///
/// fee_floor = compute_mass_grams * minimum_feerate, where
///   compute_mass_grams = script_units / SCRIPT_UNITS_PER_GRAM(=100) + size/spk margin
///   minimum_feerate    = DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE(100_000 sompi/kg) / 1000
///                      = 100 sompi/gram
///
/// SIZE_MARGIN_GRAMS covers the size-based (size * mass_per_tx_byte) and
/// script_public_key compute-mass terms that are added on top of the script
/// cost by `calc_non_contextual_masses`, plus integer rounding. The ZK script
/// term dominates by ~100x, so a fixed grams margin is a safe overestimate.
// Kept: Groth16 minimum-fee helper, ZK infrastructure.
#[allow(dead_code)]
pub const fn zk_groth16_min_fee_sompi(n_public_inputs: u64) -> u64 {
    const SCRIPT_UNITS_PER_GRAM: u64 = 100; // v2.0.0 consensus/core mass/units.rs
    const MIN_FEERATE_SOMPI_PER_GRAM: u64 = 100; // DEFAULT_MINIMUM_RELAY_TRANSACTION_FEE / 1000
    const SIZE_MARGIN_GRAMS: u64 = 20_000;
    let script_grams = zk_groth16_script_units(n_public_inputs) / SCRIPT_UNITS_PER_GRAM;
    (script_grams + SIZE_MARGIN_GRAMS) * MIN_FEERATE_SOMPI_PER_GRAM
}

/// 1 public input (the product / sum / commitment). 147 on toc5.
pub const ZK_GROTH16_SIG_OP_COUNT: u8 = zk_groth16_sig_op_count(1);

// ═══════════════════════════════════════════════════════════════════
// Crowdfunding Covenant (ZK-gated sweep)
// ═══════════════════════════════════════════════════════════════════

#[path = "kspt_crowdfund.rs"]
mod crowdfund;
pub use crowdfund::*;

// ═══════════════════════════════════════════════════════════════════
// RISC0 Succinct Covenant (OP_ZK_PRECOMPILE 0xa6, tag 0x21)
// ═══════════════════════════════════════════════════════════════════

/// RISC0 tag byte.
pub const ZK_TAG_RISC0: u8 = 0x21;

/// RISC0 Succinct costs Gram(1000 * 250) = 25_000_000 script units.
/// sigOpCount >= ceil((25_000_000 - 9_999) / 100_000) = 250.
/// Add margin for CHECKSIGVERIFY + overhead = 255.
/// Note: u8 max is 255.
pub const ZK_RISC0_SIG_OP_COUNT: u8 = 255;

// ═══════════════════════════════════════════════════════════════════
// Merkle Whitelist Vault (OP_CAT + OP_BLAKE2B)
// ═══════════════════════════════════════════════════════════════════

#[path = "kspt_merkle.rs"]
mod merkle;
pub use merkle::*;

/// Build a P2PK script_public_key from a 32-byte "pubkey" (real or synthetic).
/// Format: OP_DATA_32 <32 bytes> OP_CHECKSIG = 34 bytes.
// Kept: general P2PK script-pubkey builder, reusable primitive.
#[allow(dead_code)]
pub fn p2pk_spk(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut spk = Vec::with_capacity(34);
    spk.push(0x20); // OP_DATA_32
    spk.extend_from_slice(pubkey);
    spk.push(0xAC); // OP_CHECKSIG
    spk
}
// ================================================================
// Tagged Vault: covenant-ID-aware vault (KIP-20 PoC)
// ================================================================

#[path = "kspt_vault.rs"]
mod vault;
pub use vault::*;
#[path = "kspt_oracle.rs"]
mod oracle_mb;
pub use oracle_mb::*;
