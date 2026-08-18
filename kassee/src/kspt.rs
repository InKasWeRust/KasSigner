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

    // Sort largest first, take up to MAX_INPUTS (16) inputs. Was 5, with a
    // comment citing a 1024-byte signed-TX limit that was itself stale — the
    // firmware's signed buffer is 4096 bytes and MAX_INPUTS is now 16.
    all_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));
    let selected: Vec<_> = all_utxos.into_iter().take(32).collect();

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
    parse_descriptor_at(desc, addr_index, 0, 0)
}

/// As `parse_descriptor`, with an explicit cosigner index for the 45' scheme.
///
/// `cosigner_index` is IGNORED by the 44' and legacy branches: they have no such
/// level. It selects the address family for `multi_hd45(`.
fn parse_descriptor_at(
    desc: &str,
    addr_index: u32,
    cosigner_index: u32,
    chain: u32,
) -> Result<(u8, Vec<[u8; 32]>), String> {
    let desc = strip_header(desc);

    if desc.starts_with("multi_hd45(") && desc.ends_with(')') {
        // ── 45' standard: multi_hd45(M,<kpub>,<kpub>,...) ──
        //
        // Entries are base58check kpub strings, account keys at
        // m/45'/111111'/account'. Two things differ from the 44' branch below
        // and both change the address:
        //
        //   1. SORT THE PARENT STRINGS, not the derived children. rusty-kaspa
        //      sorts `xpub_key.to_string(...)` (wallet/core/src/wallet/mod.rs),
        //      so descriptors arrive unordered - its own cross-implementation
        //      vector lists five keys in an order that sorts to the permutation
        //      [3, 0, 2, 1, 4]. Sorting on load is what makes an external
        //      descriptor work at all; trusting the written order silently
        //      yields a different redeem script.
        //
        //   2. Derive at /cosigner_index/0/addr_index, with the SAME cosigner
        //      index applied to every key. That extra level is what gives each
        //      participant their own address family.
        //
        // The sort is a plain byte comparison, not case-insensitive: base58
        // spans digits, uppercase and lowercase, so 'Z' sorts before 't'.
        let inner = &desc[11..desc.len() - 1];
        let parts: Vec<&str> = inner.split(',').collect();
        if parts.len() < 3 {
            return Err("Need at least M and 2 cosigner kpubs".into());
        }
        let m: u8 = parts[0]
            .trim()
            .parse()
            .map_err(|_| "Invalid M value in descriptor".to_string())?;

        let mut entries: Vec<&str> = parts[1..].iter().map(|e| e.trim()).collect();
        entries.sort_unstable();
        for w in entries.windows(2) {
            if w[0] == w[1] {
                return Err("Duplicate cosigner kpub in descriptor".into());
            }
        }

        let mut pubkeys = Vec::new();
        for kpub_str in &entries {
            let parent = crate::bip32::ExtPubKey::from_kpub(kpub_str)
                .map_err(|e| format!("Invalid cosigner kpub: {}", e))?;
            if parent.depth != 3 {
                return Err(format!(
                    "Cosigner kpub must be an account key at depth 3, got depth {}",
                    parent.depth
                ));
            }
            // /cosigner/chain/index. The chain was hardcoded 0 while change
            // returned to the source address; it is a real dimension now.
            let family = parent.derive_child(cosigner_index)?;
            let chain_node = family.derive_child(chain)?;
            let addr_child = chain_node.derive_child(addr_index)?;

            let compressed = addr_child.key.to_encoded_point(true);
            let mut xonly = [0u8; 32];
            xonly.copy_from_slice(&compressed.as_bytes()[1..33]);
            pubkeys.push(xonly);
        }

        if m == 0 || m as usize > pubkeys.len() {
            return Err(format!("Invalid M={} for N={}", m, pubkeys.len()));
        }
        // NO sort here: the order was fixed above by sorting the parents, and
        // the redeem script must follow it. Sorting the children as 44' does
        // would produce an address no other implementation computes.
        Ok((m, pubkeys))
    } else if desc.starts_with("multi_hd(") && desc.ends_with(')') {
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

/// Build the `bip32Derivations` map for a 45' multisig input.
///
/// One entry per cosigner: compressed pubkey -> { keyFingerprint, derivationPath }.
///
/// **This is what lets the device sign without holding the descriptor.** The
/// path belongs to the ADDRESS being spent, so every cosigner derives at the
/// same `m/45'/111111'/account'/cosigner/chain/index`; the entries differ only
/// by pubkey and fingerprint. Without it the device cannot know which cosigner
/// slot the address uses and refuses, because searching costs
/// `n + 2n + 2n*100` derivations per input per seed slot.
///
/// Keys are COMPRESSED (33 bytes), not the x-only form used in the redeem
/// script: the field is keyed by pubkey and the parity byte is part of it.
///
/// `keyFingerprint` is the cosigner kpub's own parent fingerprint, read
/// straight from the serialized key rather than recomputed. It is a hint for
/// fast skipping, never an authority - the device verifies the derived pubkey
/// against the redeem script before signing.
///
/// Returns an empty map for 44' descriptors: they have no cosigner level, and
/// the device matches those keys through its 44' address table instead.
fn build_bip32_derivations(
    descriptor: &str,
    addr_index: u32,
    cosigner_index: u32,
    chain: u32,
) -> Result<serde_json::Value, String> {
    let desc = strip_header(descriptor);
    if !desc.starts_with("multi_hd45(") {
        return Ok(serde_json::json!({}));
    }
    let inner = &desc[11..desc.len() - 1];
    let parts: Vec<&str> = inner.split(',').collect();
    let mut entries: Vec<&str> = parts[1..].iter().map(|e| e.trim()).collect();
    entries.sort_unstable();

    let path = format!(
        "m/45'/111111'/0'/{}/{}/{}",
        cosigner_index, chain, addr_index
    );
    let mut map = serde_json::Map::new();
    for kpub_str in &entries {
        let parent = crate::bip32::ExtPubKey::from_kpub(kpub_str)
            .map_err(|e| format!("Invalid cosigner kpub: {}", e))?;
        // Parent fingerprint, bytes 5..9 of the serialized payload.
        let decoded = bs58::decode(kpub_str)
            .with_check(None)
            .into_vec()
            .map_err(|e| format!("Base58 decode failed: {}", e))?;
        let fingerprint = hex::encode(&decoded[5..9]);

        let family = parent.derive_child(cosigner_index)?;
        let chain_node = family.derive_child(chain)?;
        let child = chain_node.derive_child(addr_index)?;
        let compressed = child.key.to_encoded_point(true);
        map.insert(
            hex::encode(compressed.as_bytes()),
            serde_json::json!({
                "keyFingerprint": fingerprint,
                "derivationPath": path,
            }),
        );
    }
    Ok(serde_json::Value::Object(map))
}

/// How deep to scan a branch. 40 receive + 40 change is ONE rpc call.
pub const CHANGE_SCAN_DEPTH: u32 = 40;

/// One multisig address at an exact `(cosigner, chain, index)`. No network.
pub fn multisig_address_at(
    descriptor: &str,
    addr_index: u32,
    cosigner_index: u32,
    chain: u32,
) -> Result<String, String> {
    let (m, pks) = parse_descriptor_at(descriptor, addr_index, cosigner_index, chain)?;
    let script = build_redeem_script(m, &pks);
    let hash = blake2b_hash(&script);
    Ok(crate::address::encode_p2sh_address(&hash, "kaspa"))
}

/// Scan ONE cosigner branch and report what is on it.
///
/// Returns JSON: `{ balance_sompi, utxo_count, funded: [{chain,index,address,
/// amount}], next_change_index, next_receive_index, cosigner_index, depth }`.
///
/// **One branch, deliberately.** A descriptor describes N branches, one per
/// participant, but only yours is any of this node's business. Querying all of
/// them would name other participants' addresses to whichever node you happen
/// to be using - their exposure, not yours to spend.
///
/// **`next_change_index` is the working purpose.** Change used the INPUT's
/// address index, so spending one address repeatedly sent every change output
/// back to the same chain-1 address, which is the reuse a change chain exists
/// to prevent.
///
/// **A UTXO scan cannot see a fully spent address.** An index used and then
/// emptied looks free, so change may land somewhere that already has history.
/// A privacy regression, not a loss of funds, and closing it needs per-address
/// history from the rate-limited REST path.
pub async fn scan_multisig_branch(
    descriptor: &str,
    cosigner_index: u32,
    depth: u32,
    ws_url: &str,
) -> Result<String, String> {
    let mut addrs = Vec::with_capacity((depth as usize) * 2);
    for chain in 0..2u32 {
        for idx in 0..depth {
            addrs.push((
                chain,
                idx,
                multisig_address_at(descriptor, idx, cosigner_index, chain)?,
            ));
        }
    }
    let list: Vec<String> = addrs.iter().map(|(_, _, a)| a.clone()).collect();
    let utxos = crate::rpc::fetch_utxos_for_addresses(ws_url, &list).await?;

    let mut by_script: std::collections::HashMap<Vec<u8>, u64> = std::collections::HashMap::new();
    for u in &utxos {
        *by_script.entry(u.script_public_key.clone()).or_insert(0) += u.amount;
    }

    let mut funded = Vec::new();
    let mut balance: u64 = 0;
    let mut chain0_used = vec![false; depth as usize];
    let mut chain1_used = vec![false; depth as usize];
    // Script -> which (chain, index, address) it belongs to, so the raw UTXOs
    // below can be labelled without a second derivation pass.
    let mut owner: std::collections::HashMap<Vec<u8>, (u32, u32, String)> =
        std::collections::HashMap::new();
    for (chain, idx, addr) in &addrs {
        let spk = match crate::address::address_to_script_pubkey(addr) {
            Ok(s) => s,
            Err(_) => continue,
        };
        owner.insert(spk.clone(), (*chain, *idx, addr.clone()));
        if let Some(amount) = by_script.get(&spk) {
            balance += *amount;
            if *chain == 0 {
                chain0_used[*idx as usize] = true;
            } else {
                chain1_used[*idx as usize] = true;
            }
            funded.push(serde_json::json!({
                "chain": chain, "index": idx, "address": addr, "amount": amount,
            }));
        }
    }

    // Individual OUTPOINTS, not just per-address totals.
    //
    // `funded` aggregates by address, which is right for a balance view but
    // useless for building a transaction: an input needs `tx_id` and `index`.
    // A multi-address spend selects outpoints, so they have to come out of here.
    let mut utxo_list = Vec::with_capacity(utxos.len());
    for u in &utxos {
        if let Some((chain, idx, addr)) = owner.get(&u.script_public_key) {
            utxo_list.push(serde_json::json!({
                "chain": chain,
                "index": idx,
                "address": addr,
                "tx_id": u.tx_id,
                "outpoint_index": u.index,
                "amount": u.amount,
            }));
        }
    }
    let first_free =
        |used: &[bool]| -> u32 { used.iter().position(|u| !*u).unwrap_or(used.len()) as u32 };
    let result = serde_json::json!({
        "balance_sompi": balance,
        "utxo_count": utxos.len(),
        "funded": funded,
        "utxos": utxo_list,
        "next_change_index": first_free(&chain1_used),
        "next_receive_index": first_free(&chain0_used),
        "cosigner_index": cosigner_index,
        "depth": depth,
    });
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

/// Build a 45' multisig PSKB spending from MANY addresses of one branch.
///
/// `sources` is `[{address, tx_id, index}]` - each entry names one UTXO to
/// spend, so the caller chooses both the addresses and which of their outputs
/// are used.
///
/// **Why this exists.** The single-address builders cannot combine UTXOs, and
/// change rotation creates a new change address on every spend. Without this,
/// every spend leaves a UTXO that can only ever be spent alone: a wallet used
/// fifty times holds fifty UTXOs that can never be merged, and the smallest
/// eventually cost more in fee than they hold. Dust with no exit, not a privacy
/// trade.
///
/// **What differs from one address.** Each input carries its OWN
/// `redeemScript` and its OWN `bip32Derivations` at its own
/// `(cosigner, chain, index)`. The single-address builders derive one of each
/// and reuse it for every input, which is correct only while every input shares
/// an address.
///
/// **The cost the caller is accepting.** Spending several addresses together
/// links them permanently: every address in the transaction becomes provably
/// one wallet. That is why this is explicit rather than automatic.
// Eight scalars because the wasm export below passes them straight through
// from JS; a parameter struct would not cross the wasm-bindgen boundary.
#[allow(clippy::too_many_arguments)]
pub async fn create_multisig_pskb_multi(
    descriptor: &str,
    sources_json: &str,
    dest_address: &str,
    amount_sompi: u64,
    fee_sompi: u64,
    cosigner_index: u32,
    change_index_hint: u32,
    ws_url: &str,
) -> Result<String, String> {
    #[derive(serde::Deserialize)]
    struct Src {
        address: String,
        tx_id: String,
        index: u32,
    }
    let sources: Vec<Src> =
        serde_json::from_str(sources_json).map_err(|e| format!("sources_json: {}", e))?;
    if sources.is_empty() {
        return Err("No inputs selected".into());
    }

    let desc = strip_header(descriptor);
    if !desc.starts_with("multi_hd45(") {
        return Err("Multi-address spend requires a 45' descriptor".into());
    }

    // Resolve every distinct address ONCE: which (chain, index) produces it, and
    // the redeem script and derivation map that go with it. Addresses repeat
    // when several UTXOs share one, so caching avoids re-deriving per input.
    let mut resolved: std::collections::HashMap<String, (String, serde_json::Value, usize)> =
        std::collections::HashMap::new();
    for s in &sources {
        if resolved.contains_key(&s.address) {
            continue;
        }
        let mut found: Option<(u32, u32)> = None;
        'outer: for chain in 0..2u32 {
            for idx in 0..CHANGE_SCAN_DEPTH {
                if multisig_address_at(desc, idx, cosigner_index, chain)? == s.address {
                    found = Some((chain, idx));
                    break 'outer;
                }
            }
        }
        let (chain, idx) = found.ok_or_else(|| {
            format!(
                "{} is not in branch {} (checked both chains, indices 0..{})",
                s.address, cosigner_index, CHANGE_SCAN_DEPTH
            )
        })?;
        let (m, pks) = parse_descriptor_at(desc, idx, cosigner_index, chain)?;
        let script = build_redeem_script(m, &pks);
        let derivs = build_bip32_derivations(desc, idx, cosigner_index, chain)?;
        resolved.insert(s.address.clone(), (hex::encode(&script), derivs, pks.len()));
    }

    // Fetch every address's UTXOs in ONE rpc call, then pick the named outpoints.
    let addr_list: Vec<String> = {
        let mut v: Vec<String> = sources.iter().map(|s| s.address.clone()).collect();
        v.sort();
        v.dedup();
        v
    };
    let utxos = crate::rpc::fetch_utxos_for_addresses(ws_url, &addr_list).await?;

    let mut selected = Vec::new();
    for s in &sources {
        let hit = utxos
            .iter()
            .find(|u| u.tx_id == s.tx_id && u.index == s.index)
            .ok_or_else(|| format!("UTXO {}:{} not found (already spent?)", s.tx_id, s.index))?;
        selected.push((s.address.clone(), hit.clone()));
    }

    let selected_total: u64 = selected.iter().map(|(_, u)| u.amount).sum();
    let total_needed = amount_sompi.saturating_add(fee_sompi);
    if selected_total < total_needed {
        return Err(format!(
            "Selected {} sompi but need {} (amount {} + fee {})",
            selected_total, total_needed, amount_sompi, fee_sompi
        ));
    }

    // ── Outputs: destination, then change if any is left ──
    let mut outputs: Vec<(u64, Vec<u8>)> = Vec::new();
    outputs.push((
        amount_sompi,
        crate::address::address_to_script_pubkey(dest_address)?,
    ));

    let change_amount = selected_total - total_needed;
    let mut change_index: Option<usize> = None;
    let mut change_derivations = serde_json::json!({});
    // Dust change is dropped into the fee rather than creating an unspendable
    // output - the same rule the single-address builders apply.
    let final_change = if change_amount > 0 && is_dust(change_amount) {
        0
    } else {
        change_amount
    };
    if final_change > 0 {
        let chg_idx = if change_index_hint != u32::MAX {
            change_index_hint
        } else {
            match scan_multisig_branch(desc, cosigner_index, CHANGE_SCAN_DEPTH, ws_url).await {
                Ok(j) => serde_json::from_str::<serde_json::Value>(&j)
                    .ok()
                    .and_then(|v| v["next_change_index"].as_u64())
                    .map(|n| n as u32)
                    .unwrap_or(0),
                Err(_) => 0,
            }
        };
        let (cm, cpks) = parse_descriptor_at(desc, chg_idx, cosigner_index, 1)?;
        let cscript = build_redeem_script(cm, &cpks);
        let chash = blake2b_hash(&cscript);
        let caddr = crate::address::encode_p2sh_address(&chash, "kaspa");
        change_derivations = build_bip32_derivations(desc, chg_idx, cosigner_index, 1)?;
        change_index = Some(outputs.len());
        outputs.push((
            final_change,
            crate::address::address_to_script_pubkey(&caddr)?,
        ));
    }

    // ── Inputs: each with ITS OWN redeem script and derivation map ──
    let mut inputs_json = Vec::<serde_json::Value>::with_capacity(selected.len());
    for (addr, utxo) in &selected {
        let (redeem_hex, derivs, n_keys) = resolved
            .get(addr)
            .ok_or_else(|| format!("unresolved address {}", addr))?;
        let spk_hex = format!("0000{}", hex::encode(&utxo.script_public_key));
        inputs_json.push(serde_json::json!({
            "utxoEntry": {
                "amount": utxo.amount,
                "scriptPublicKey": spk_hex,
                "blockDaaScore": utxo.block_daa_score,
                "isCoinbase": false,
                "covenantId": utxo.covenant_id
            },
            "previousOutpoint": { "transactionId": utxo.tx_id, "index": utxo.index },
            "sequence": 0u64,
            "minTime": serde_json::Value::Null,
            "partialSigs": {},
            "sighashType": 1u8,
            "redeemScript": redeem_hex,
            "sigOpCount": *n_keys as u8,
            "bip32Derivations": derivs,
            "finalScriptSig": serde_json::Value::Null,
            "proprietaries": {}
        }));
    }

    let mut outputs_json = Vec::<serde_json::Value>::with_capacity(outputs.len());
    for (oi, (amount, script)) in outputs.iter().enumerate() {
        let spk_hex = format!("0000{}", hex::encode(script));
        let od = if Some(oi) == change_index {
            change_derivations.clone()
        } else {
            serde_json::json!({})
        };
        outputs_json.push(serde_json::json!({
            "amount": amount,
            "scriptPublicKey": spk_hex,
            "redeemScript": serde_json::Value::Null,
            "bip32Derivations": od,
            "proprietaries": {}
        }));
    }

    let num_in = inputs_json.len() as u64;
    let num_out = outputs_json.len() as u64;
    let pskt = serde_json::json!({
        "global": {
            "version": 0u8,
            "txVersion": 0u16,
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

    web_sys::console::log_1(&format!(
        "[KasSee] Multisig PSKB (multi): {} inputs across {} address(es), send {}, change {}, wire hex {} chars",
        num_in, addr_list.len(), amount_sompi, final_change, wire_hex.len()
    ).into());

    Ok(wire_hex)
}

/// Find the address index, and for 45' the cosigner index, that reproduce
/// `source_address`. Returns `(addr_index, cosigner_index)`.
///
/// 44' has ONE address family, so only the address index is searched, 0..99, as
/// before. 45' has N families - one per cosigner - because the cosigner level
/// sits between the account key and the chain, and which family an address
/// belongs to is not recoverable from the address itself. So both dimensions
/// are searched.
///
/// The cosigner loop is bounded by N rather than by a constant: a descriptor
/// with N cosigners has exactly N families, and an index at or above N is not a
/// family any participant hands out.
///
/// Legacy `multi(` descriptors have no HD levels and take the caller's index
/// unchanged.
fn discover_indices(
    descriptor: &str,
    source_address: &str,
    addr_index: u32,
) -> Result<(u32, u32, u32), String> {
    let desc = strip_header(descriptor);

    if desc.starts_with("multi_hd45(") {
        // Entry count bounds the family loop. The parser validates the entries
        // properly; this only needs an upper bound.
        let n_cosigners = desc.matches(',').count().max(1) as u32;
        // THREE dimensions now: cosigner family, chain, address index.
        //
        // Chain 1 is where multisig change lives once it stops returning to the
        // source address, so an address handed to us can be on either chain and
        // there is nothing in the address itself that says which. Receive first,
        // since that is the common case.
        for cos in 0..n_cosigners {
            for chain in 0..2u32 {
                for try_idx in 0..100u32 {
                    let (m, pks) = parse_descriptor_at(desc, try_idx, cos, chain)?;
                    let script = build_redeem_script(m, &pks);
                    let script_hash = blake2b_hash(&script);
                    let derived = crate::address::encode_p2sh_address(&script_hash, "kaspa");
                    if derived == source_address {
                        return Ok((try_idx, cos, chain));
                    }
                }
            }
        }
        return Err(format!(
            "Could not find a cosigner/chain/index triple (0..{} x 0..1 x 0..99) matching {}",
            n_cosigners.saturating_sub(1),
            source_address
        ));
    }

    if desc.starts_with("multi_hd(") {
        for try_idx in 0..100u32 {
            let (m, pks) = parse_descriptor(desc, try_idx)?;
            let script = build_redeem_script(m, &pks);
            let script_hash = blake2b_hash(&script);
            let derived = crate::address::encode_p2sh_address(&script_hash, "kaspa");
            if derived == source_address {
                return Ok((try_idx, 0, 0));
            }
        }
        return Err(format!(
            "Could not find address index (tried 0..99) that matches source address {}",
            source_address
        ));
    }

    Ok((addr_index, 0, 0))
}

/// Strip an optional `#` header line and surrounding whitespace.
///
/// A 45' descriptor may be written with a comment line above it, e.g.
/// `# KasSigner multisig, 45' coordinated, 2-of-3`. It is DECORATIVE: the
/// `multi_hd45(` prefix is the sole authority for the scheme, and a header that
/// contradicts it is ignored rather than treated as an error. It must never
/// reach the entry list, because the sort is a byte comparison and a label
/// inside an entry would change every address.
fn strip_header(desc: &str) -> &str {
    let mut s = desc.trim();
    while s.starts_with('#') {
        s = match s.find('\n') {
            Some(i) => s[i + 1..].trim_start(),
            None => "",
        };
    }
    s.trim()
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
    let (final_index, final_cosigner, final_chain) =
        discover_indices(descriptor, source_address, addr_index)?;

    let (m, pubkeys) = parse_descriptor_at(descriptor, final_index, final_cosigner, final_chain)?;
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
        // Change goes back to the same multisig address.
        //
        // ENFORCED, not merely intended. This comment previously stated the
        // invariant while the next line converted whatever string the caller
        // passed, so correctness depended on every caller doing the right
        // thing. The web UI does (`app.js:8417`, `changeAddr = sourceAddr`),
        // but the function is a WASM export and any caller could redirect the
        // entire change amount to an address of its choosing.
        //
        // The device is not a reliable backstop for this: output labelling
        // recognises only P2PK as owned change, so a redirected P2SH multisig
        // change output renders on the review screen as an ordinary
        // destination, and multisig change legitimately returns to the address
        // being spent from, which is exactly the intuition that fails.
        //
        // Change goes to the CHANGE CHAIN for 45', /cosigner/1/index.
        //
        // It used to be required to return to the source address, because the
        // parser derived on chain 0 only and there was no other address to send
        // to. Reusing the spent address every time is poor hygiene and makes the
        // wallet's history trivially linkable, and the chain level exists in the
        // standard path precisely for this.
        //
        // 44' keeps the old rule: it has no cosigner level and no separate
        // change chain, so the source address is still the only correct answer.
        let desc_is_45 = strip_header(descriptor).starts_with("multi_hd45(");
        let change_script = if desc_is_45 {
            let (cm, cpks) = parse_descriptor_at(descriptor, final_index, final_cosigner, 1)?;
            let cscript = build_redeem_script(cm, &cpks);
            let chash = blake2b_hash(&cscript);
            let caddr = crate::address::encode_p2sh_address(&chash, "kaspa");
            crate::address::address_to_script_pubkey(&caddr)?
        } else {
            if change_address != source_address {
                return Err(format!(
                    "Multisig change must return to the source address ({}), got {}",
                    source_address, change_address
                ));
            }
            crate::address::address_to_script_pubkey(change_address)?
        };
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
    // Take up to MAX_INPUTS (16) largest UTXOs. Was 5, from when the firmware
    // ceiling was lower; the KasSigner now signs 16 (transaction.rs
    // MAX_INPUTS) and the signed response fits its 4096-byte buffer. The
    // caller (handleConsolidate) sizes the fee to this same count via
    // consolidateFee(Math.min(16, ...)) — the two MUST stay in sync or the
    // fee is wrong.
    let selected: Vec<_> = all_utxos.into_iter().take(32).collect();

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
            "isCoinbase": false,
            // The UTXO's on-chain covenant id, so the signer can tell a
            // continuation from a genesis: the node rejects a continuation
            // whose binding id differs from the authorizing input's. Absent
            // when the UTXO carries no covenant.
            "covenantId": utxo.covenant_id
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
                "isCoinbase": false,
                // The UTXO's on-chain covenant id; see the note above.
                "covenantId": utxo.covenant_id
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
            "utxoEntry": { "amount": utxo.amount, "scriptPublicKey": spk_hex, "blockDaaScore": utxo.block_daa_score, "isCoinbase": false, "covenantId": utxo.covenant_id },
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
    // First unused change index, or u32::MAX to derive it here.
    change_index_hint: u32,
    addr_index: u32,
) -> Result<String, String> {
    // ── HD address-index auto-discovery (identical to create_multisig_kspt) ──
    let (final_index, final_cosigner, final_chain) =
        discover_indices(descriptor, source_address, addr_index)?;

    let (m, pubkeys) = parse_descriptor_at(descriptor, final_index, final_cosigner, final_chain)?;
    let redeem_script = build_redeem_script(m, &pubkeys);
    let redeem_script_hex = hex::encode(&redeem_script);
    // The derivation hint. Empty for 44', which needs none.
    let derivations =
        build_bip32_derivations(descriptor, final_index, final_cosigner, final_chain)?;

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
    // Which output is change, and its derivation map. Set only when a 45'
    // change output is created; a payment to someone else carries no path.
    let mut change_index: Option<usize> = None;
    let mut change_derivations = serde_json::json!({});
    let final_change = if change_amount > 0 && is_dust(change_amount) {
        0u64
    } else {
        change_amount
    };

    // ── Build outputs ──
    let mut outputs: Vec<(u64, Vec<u8>)> = vec![(amount_sompi, dest_script)];
    if final_change > 0 {
        // Same invariant as `create_multisig_kspt`; see the note there.
        // 45' change goes to /cosigner/1/index, the change chain. It carries
        // its own derivation map so the DEVICE can verify it: rebuilding a
        // multisig address needs every cosigner key, so a signer holding one
        // seed cannot check it without the path plus the descriptor. Omit the
        // map and every device shows this output as an unverified claim.
        //
        // 44' has no change chain and still returns to the source address.
        let desc_is_45 = strip_header(descriptor).starts_with("multi_hd45(");
        let change_script = if desc_is_45 {
            // ROTATE: the first chain-1 index with nothing on it.
            //
            // Change used `final_index`, the index of the address being spent,
            // so spending one address repeatedly sent every change output to
            // the same chain-1 address.
            //
            // Falls back to `final_index` if the scan fails: a transaction to a
            // reused address beats no transaction.
            // The CALLER's index wins when it supplies one.
            //
            // A UTXO scan cannot see a spent-empty address, so computing the
            // index here would hand back an index that was used and emptied -
            // and rotation would stop rotating after one round. The caller can
            // see transaction history and passes the answer in; `u32::MAX`
            // means "no hint, work it out", which is the old behaviour.
            let chg_idx = if change_index_hint != u32::MAX {
                change_index_hint
            } else {
                match scan_multisig_branch(descriptor, final_cosigner, CHANGE_SCAN_DEPTH, ws_url)
                    .await
                {
                    Ok(j) => serde_json::from_str::<serde_json::Value>(&j)
                        .ok()
                        .and_then(|v| v["next_change_index"].as_u64())
                        .map(|n| n as u32)
                        .unwrap_or(final_index),
                    Err(_) => final_index,
                }
            };
            let (cm, cpks) = parse_descriptor_at(descriptor, chg_idx, final_cosigner, 1)?;
            let cscript = build_redeem_script(cm, &cpks);
            let chash = blake2b_hash(&cscript);
            let caddr = crate::address::encode_p2sh_address(&chash, "kaspa");
            change_derivations = build_bip32_derivations(descriptor, chg_idx, final_cosigner, 1)?;
            crate::address::address_to_script_pubkey(&caddr)?
        } else {
            if change_address != source_address {
                return Err(format!(
                    "Multisig change must return to the source address ({}), got {}",
                    source_address, change_address
                ));
            }
            crate::address::address_to_script_pubkey(change_address)?
        };
        change_index = Some(outputs.len());
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
            "isCoinbase": false,
            // The UTXO's on-chain covenant id, so the signer can tell a
            // continuation from a genesis: the node rejects a continuation
            // whose binding id differs from the authorizing input's. Absent
            // when the UTXO carries no covenant.
            "covenantId": utxo.covenant_id
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
            "bip32Derivations": derivations,
            "finalScriptSig": serde_json::Value::Null,
            "proprietaries": {}
        });
        inputs_json.push(input);
    }

    // Outputs JSON
    let mut outputs_json = Vec::<serde_json::Value>::with_capacity(outputs.len());
    for (oi, (amount, script)) in outputs.iter().enumerate() {
        let spk_hex = format!("0000{}", hex::encode(script));
        // Only the CHANGE output carries a map. A payment to someone else has
        // no path of ours, and claiming one would be a lie the device is now
        // built to catch.
        let od = if Some(oi) == change_index {
            change_derivations.clone()
        } else {
            serde_json::json!({})
        };
        let output = serde_json::json!({
            "amount": amount,
            "scriptPublicKey": spk_hex,
            "redeemScript": serde_json::Value::Null,
            "bip32Derivations": od,
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
    // First unused change index, or u32::MAX to derive it here.
    change_index_hint: u32,
    addr_index: u32,
    utxo_indices: &[usize],
) -> Result<String, String> {
    let (final_index, final_cosigner, final_chain) =
        discover_indices(descriptor, source_address, addr_index)?;

    let (m, pubkeys) = parse_descriptor_at(descriptor, final_index, final_cosigner, final_chain)?;
    let redeem_script = build_redeem_script(m, &pubkeys);
    let redeem_script_hex = hex::encode(&redeem_script);
    // The derivation hint. Empty for 44', which needs none.
    let derivations =
        build_bip32_derivations(descriptor, final_index, final_cosigner, final_chain)?;

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
    // Which output is change, and its derivation map. Set only when a 45'
    // change output is created; a payment to someone else carries no path.
    let mut change_index: Option<usize> = None;
    let mut change_derivations = serde_json::json!({});
    let final_change = if change_amount > 0 && is_dust(change_amount) {
        0u64
    } else {
        change_amount
    };

    let mut outputs: Vec<(u64, Vec<u8>)> = vec![(amount_sompi, dest_script)];
    if final_change > 0 {
        // Same invariant as `create_multisig_kspt`; see the note there.
        // 45' change goes to /cosigner/1/index, the change chain. It carries
        // its own derivation map so the DEVICE can verify it: rebuilding a
        // multisig address needs every cosigner key, so a signer holding one
        // seed cannot check it without the path plus the descriptor. Omit the
        // map and every device shows this output as an unverified claim.
        //
        // 44' has no change chain and still returns to the source address.
        let desc_is_45 = strip_header(descriptor).starts_with("multi_hd45(");
        let change_script = if desc_is_45 {
            // ROTATE: the first chain-1 index with nothing on it.
            //
            // Change used `final_index`, the index of the address being spent,
            // so spending one address repeatedly sent every change output to
            // the same chain-1 address.
            //
            // Falls back to `final_index` if the scan fails: a transaction to a
            // reused address beats no transaction.
            // The CALLER's index wins when it supplies one.
            //
            // A UTXO scan cannot see a spent-empty address, so computing the
            // index here would hand back an index that was used and emptied -
            // and rotation would stop rotating after one round. The caller can
            // see transaction history and passes the answer in; `u32::MAX`
            // means "no hint, work it out", which is the old behaviour.
            let chg_idx = if change_index_hint != u32::MAX {
                change_index_hint
            } else {
                match scan_multisig_branch(descriptor, final_cosigner, CHANGE_SCAN_DEPTH, ws_url)
                    .await
                {
                    Ok(j) => serde_json::from_str::<serde_json::Value>(&j)
                        .ok()
                        .and_then(|v| v["next_change_index"].as_u64())
                        .map(|n| n as u32)
                        .unwrap_or(final_index),
                    Err(_) => final_index,
                }
            };
            let (cm, cpks) = parse_descriptor_at(descriptor, chg_idx, final_cosigner, 1)?;
            let cscript = build_redeem_script(cm, &cpks);
            let chash = blake2b_hash(&cscript);
            let caddr = crate::address::encode_p2sh_address(&chash, "kaspa");
            change_derivations = build_bip32_derivations(descriptor, chg_idx, final_cosigner, 1)?;
            crate::address::address_to_script_pubkey(&caddr)?
        } else {
            if change_address != source_address {
                return Err(format!(
                    "Multisig change must return to the source address ({}), got {}",
                    source_address, change_address
                ));
            }
            crate::address::address_to_script_pubkey(change_address)?
        };
        change_index = Some(outputs.len());
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
                "isCoinbase": false,
                // The UTXO's on-chain covenant id; see the note above.
                "covenantId": utxo.covenant_id
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
            "bip32Derivations": derivations,
            "finalScriptSig": serde_json::Value::Null,
            "proprietaries": {}
        });
        inputs_json.push(input);
    }

    let mut outputs_json = Vec::<serde_json::Value>::with_capacity(outputs.len());
    for (oi, (amount, script)) in outputs.iter().enumerate() {
        let spk_hex = format!("0000{}", hex::encode(script));
        // Only the CHANGE output carries a map; see `create_multisig_pskb`.
        let od = if Some(oi) == change_index {
            change_derivations.clone()
        } else {
            serde_json::json!({})
        };
        outputs_json.push(serde_json::json!({
            "amount": amount,
            "scriptPublicKey": spk_hex,
            "redeemScript": serde_json::Value::Null,
            "bip32Derivations": od,
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
