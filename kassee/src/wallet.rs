// KasSee — Watch-only companion wallet for air-gapped KasSigner
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// kassee/wallet.rs — Watch-only wallet operations
//
// Handles kpub import, address derivation, UTXO tracking, KSPT creation,
// multisig P2SH funding/spending, and transaction broadcast.

use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use kaspa_bip32::{secp256k1, ExtendedPublicKey, ChildNumber};
use kaspa_addresses::{Address, Prefix, Version};

// ─── Data types ───

#[derive(Serialize, Deserialize)]
pub struct WalletData {
    pub kpub: String,
    pub receive_addresses: Vec<String>,
    pub change_addresses: Vec<String>,
    #[serde(default)]
    pub next_receive_index: usize,
    #[serde(default)]
    pub next_change_index: usize,
}

pub struct ImportInfo {
    pub first_address: String,
    pub address_count: usize,
    pub wallet_file: String,
}

pub struct BalanceInfo {
    pub total_sompi: u64,
    pub utxo_count: usize,
    pub funded_addresses: usize,
}

impl BalanceInfo {
    pub fn total_kas(&self) -> f64 {
        self.total_sompi as f64 / 100_000_000.0
    }
}

// ─── Wallet file path ───

fn wallet_path() -> PathBuf {
    let mut p = if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home)
    } else {
        PathBuf::from(".")
    };
    p.push("kassee.json");
    p
}

fn save_wallet(data: &WalletData) -> Result<(), String> {
    let path = wallet_path();
    let json = serde_json::to_string_pretty(data).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| format!("Failed to write {}: {}", path.display(), e))
}

fn load_wallet() -> Result<WalletData, String> {
    let path = wallet_path();
    let json = std::fs::read_to_string(&path)
        .map_err(|_| "No wallet found. Run 'kassee import <kpub>' first.".to_string())?;
    serde_json::from_str(&json).map_err(|e| format!("Corrupt wallet file: {}", e))
}

// ─── Convert compressed pubkey (33 bytes) to kaspa address ───

fn compressed_pubkey_to_address(pubkey: &secp256k1::PublicKey) -> String {
    let compressed = pubkey.serialize(); // 33 bytes SEC1
    // Kaspa uses x-only (Schnorr) key: drop the 0x02/0x03 prefix byte
    let x_only = &compressed[1..]; // 32 bytes
    let addr = Address::new(Prefix::Mainnet, Version::PubKey, x_only);
    addr.to_string()
}

// ─── kpub import ───

pub async fn import_kpub(kpub_str: &str) -> Result<ImportInfo, String> {
    if !kpub_str.starts_with("kpub") {
        return Err("Invalid kpub: must start with 'kpub'".into());
    }

    // Parse kpub string directly using FromStr
    let xpub: ExtendedPublicKey<secp256k1::PublicKey> = kpub_str.parse()
        .map_err(|e: kaspa_bip32::Error| format!("Failed to parse kpub: {}", e))?;

    println!("  Parsed kpub at depth {}", xpub.attrs().depth);

    // Derive receive chain: /0
    let receive_chain = xpub.derive_child(ChildNumber::new(0, false)
        .map_err(|e| format!("derive /0: {}", e))?)
        .map_err(|e| format!("derive receive chain: {}", e))?;

    // Derive 20 receive addresses: /0/0 .. /0/19
    let mut receive_addresses = Vec::new();
    for i in 0..20u32 {
        let child = receive_chain.derive_child(ChildNumber::new(i, false)
            .map_err(|e| format!("child {}: {}", i, e))?)
            .map_err(|e| format!("derive receive/{}: {}", i, e))?;
        let addr = compressed_pubkey_to_address(child.public_key());
        receive_addresses.push(addr);
    }

    // Derive change chain: /1
    let change_chain = xpub.derive_child(ChildNumber::new(1, false)
        .map_err(|e| format!("derive /1: {}", e))?)
        .map_err(|e| format!("derive change chain: {}", e))?;

    // Derive 5 change addresses: /1/0 .. /1/4
    let mut change_addresses = Vec::new();
    for i in 0..5u32 {
        let child = change_chain.derive_child(ChildNumber::new(i, false)
            .map_err(|e| format!("child {}: {}", i, e))?)
            .map_err(|e| format!("derive change/{}: {}", i, e))?;
        let addr = compressed_pubkey_to_address(child.public_key());
        change_addresses.push(addr);
    }

    let first_addr = receive_addresses[0].clone();
    let total = receive_addresses.len() + change_addresses.len();

    let data = WalletData {
        kpub: kpub_str.to_string(),
        receive_addresses,
        change_addresses,
        next_receive_index: 0,
        next_change_index: 0,
    };

    save_wallet(&data)?;

    Ok(ImportInfo {
        first_address: first_addr,
        address_count: total,
        wallet_file: wallet_path().display().to_string(),
    })
}

// ─── Balance ───

pub async fn show_balance(node_url: Option<&str>) -> Result<BalanceInfo, String> {
    let data = load_wallet()?;
    let all_addresses: Vec<&str> = data.receive_addresses.iter()
        .chain(data.change_addresses.iter())
        .map(|s| s.as_str())
        .collect();

    let client = connect_to_node(node_url).await?;

    let mut total_sompi: u64 = 0;
    let mut utxo_count: usize = 0;
    let mut funded: usize = 0;

    for addr_str in &all_addresses {
        let utxos = fetch_utxos(&client, addr_str).await?;
        if !utxos.is_empty() {
            funded += 1;
            for utxo in &utxos {
                total_sompi += utxo.amount;
                utxo_count += 1;
            }
        }
    }

    Ok(BalanceInfo { total_sompi, utxo_count, funded_addresses: funded })
}

// ─── Addresses ───

/// Show receive or change addresses.
pub async fn show_addresses_with_type(count: u32, change: bool) -> Result<Vec<String>, String> {
    let data = load_wallet()?;
    let addrs = if change { &data.change_addresses } else { &data.receive_addresses };
    let n = (count as usize).min(addrs.len());
    Ok(addrs[..n].to_vec())
}

// ─── Send (create unsigned KSPT) ───

pub async fn create_pskb(dest_address: &str, amount_kas: f64, fee: u64, node_url: Option<&str>) -> Result<String, String> {
    let mut data = load_wallet()?;
    let amount_sompi = (amount_kas * 100_000_000.0) as u64;

    let _dest = Address::try_from(dest_address)
        .map_err(|e| format!("Invalid destination address: {}", e))?;

    let client = connect_to_node(node_url).await?;
    {
        use kaspa_rpc_core::api::rpc::RpcApi;
        match client.get_fee_estimate().await {
            Ok(estimate) => {
                let priority_rate = estimate.priority_bucket.feerate;
                let normal_rate = estimate.normal_buckets.first()
                    .map(|b| b.feerate).unwrap_or(1.0);
                println!("  Fee estimate: priority={:.4} sompi/gram, normal={:.4} sompi/gram",
                    priority_rate, normal_rate);
                // Typical 1-in 2-out P2PK tx: ~2300 grams compute mass
                let suggested = (normal_rate * 2300.0).max(1000.0) as u64;
                if fee < suggested {
                    println!("  NOTE: --fee {} may be too low. Suggested minimum: {} sompi", fee, suggested);
                }
            }
            Err(e) => {
                println!("  (Fee estimate unavailable: {})", e);
            }
        }
    }

    // Check destination address for existing UTXOs (address reuse warning)
    {
        let dest_utxos = fetch_utxos(&client, dest_address).await?;
        if !dest_utxos.is_empty() {
            let dest_sompi: u64 = dest_utxos.iter().map(|u| u.amount).sum();
            println!("\n  ⚠ WARNING: Destination already has {} UTXOs ({:.8} KAS) — address reuse.",
                dest_utxos.len(), dest_sompi as f64 / 1e8);
            println!("  Kaspa P2PK exposes the pubkey — reusing addresses weakens security.\n");
            std::thread::sleep(std::time::Duration::from_secs(3));
        }
    }

    // Check change address for existing UTXOs — skip to next unused one
    {
        let chg_idx = data.next_change_index;
        if chg_idx < data.change_addresses.len() {
            let chg_addr = &data.change_addresses[chg_idx];
            let chg_utxos = fetch_utxos(&client, chg_addr).await?;
            if !chg_utxos.is_empty() {
                let chg_sompi: u64 = chg_utxos.iter().map(|u| u.amount).sum();
                println!("  ⚠ WARNING: Change address #{} has {} UTXOs ({:.8} KAS) — skipping to next.",
                    chg_idx, chg_utxos.len(), chg_sompi as f64 / 1e8);
                data.next_change_index += 1;
                save_wallet(&data)?;
            }
        }
    }

    let all_addresses: Vec<&str> = data.receive_addresses.iter()
        .chain(data.change_addresses.iter())
        .map(|s| s.as_str())
        .collect();

    let mut all_utxos = Vec::new();
    for addr_str in &all_addresses {
        let utxos = fetch_utxos(&client, addr_str).await?;
        all_utxos.extend(utxos);
    }

    let total_needed = amount_sompi + fee;
    let mut selected = Vec::new();
    let mut selected_total: u64 = 0;

    all_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));
    for utxo in &all_utxos {
        selected.push(utxo.clone());
        selected_total += utxo.amount;
        if selected_total >= total_needed {
            break;
        }
    }

    if selected_total < total_needed {
        return Err(format!(
            "Insufficient funds: have {} sompi ({:.8} KAS), need {} sompi ({:.8} KAS)",
            selected_total, selected_total as f64 / 1e8,
            total_needed, total_needed as f64 / 1e8,
        ));
    }

    let change_amount = selected_total - amount_sompi - fee;

    // KIP-9 storage mass check: warn if any output is too small
    // C = 10_000 * SOMPI_PER_KASPA = 1_000_000_000_000
    // storage_mass per output ≈ C / output_amount
    // Max standard mass = 100_000
    // Threshold: C / 100_000 = 10_000_000 sompi = 0.1 KAS (hard limit)
    // Warning at 0.2 KAS (20_000_000 sompi) to leave margin
    const STORAGE_MASS_WARN_THRESHOLD: u64 = 20_000_000; // 0.2 KAS
    const STORAGE_MASS_C: u64 = 1_000_000_000_000;
    const MAX_STANDARD_MASS: u64 = 100_000;

    if amount_sompi > 0 && amount_sompi < STORAGE_MASS_WARN_THRESHOLD {
        let mass_approx = STORAGE_MASS_C / amount_sompi;
        println!("  WARNING: Send amount {:.8} KAS is small — estimated storage mass {} (max {})",
            amount_sompi as f64 / 1e8, mass_approx, MAX_STANDARD_MASS);
        if mass_approx > MAX_STANDARD_MASS {
            return Err(format!(
                "Send amount too small: {:.8} KAS → storage mass {} exceeds max {}. Send at least 0.1 KAS.",
                amount_sompi as f64 / 1e8, mass_approx, MAX_STANDARD_MASS));
        }
    }

    if change_amount > 0 && change_amount < STORAGE_MASS_WARN_THRESHOLD {
        let mass_approx = STORAGE_MASS_C / change_amount;
        println!("  WARNING: Change amount {:.8} KAS is small — estimated storage mass {} (max {})",
            change_amount as f64 / 1e8, mass_approx, MAX_STANDARD_MASS);
        if mass_approx > MAX_STANDARD_MASS {
            // Absorb small change into the fee instead
            let new_fee = fee + change_amount;
            println!("  Auto-absorbing dust change into fee: {} + {} = {} sompi",
                fee, change_amount, new_fee);
            // Recurse with zero change by adjusting amounts
            // Actually, simpler: just set change_amount to 0 and increase fee
            let change_amount_final = 0u64;
            println!("  Selected {} UTXOs, total {} sompi", selected.len(), selected_total);
            println!("  Send: {} sompi to {}", amount_sompi, dest_address);
            println!("  Change: 0 (dust absorbed into fee)");
            println!("  Fee: {} sompi ({:.8} KAS)", new_fee, new_fee as f64 / 1e8);

            return build_and_serialize_kspt(
                &mut data, &client, &selected, amount_sompi, dest_address,
                change_amount_final, new_fee,
            ).await;
        }
    }

    println!("  Selected {} UTXOs, total {} sompi", selected.len(), selected_total);
    println!("  Send: {} sompi to {}", amount_sompi, dest_address);
    if change_amount > 0 {
        println!("  Change: {} sompi to {} (change #{})", change_amount,
            data.change_addresses[data.next_change_index], data.next_change_index);
    }
    println!("  Fee: {} sompi ({:.8} KAS)", fee, fee as f64 / 1e8);

    build_and_serialize_kspt(
        &mut data, &client, &selected, amount_sompi, dest_address,
        change_amount, fee,
    ).await
}

/// Internal: build KSPT from selected UTXOs and output parameters.
async fn build_and_serialize_kspt(
    data: &mut WalletData,
    _client: &kaspa_wrpc_client::KaspaRpcClient,
    selected: &[UtxoEntry],
    amount_sompi: u64,
    dest_address: &str,
    change_amount: u64,
    _fee: u64,
) -> Result<String, String> {

    // Build PSKB using kaspa-wallet-pskt
    use kaspa_wallet_pskt::pskt::{PSKT, Creator, InputBuilder, OutputBuilder};
    use kaspa_wallet_pskt::bundle::Bundle;
    use kaspa_consensus_core::tx::{
        TransactionOutpoint, ScriptPublicKey,
        UtxoEntry as ConsensusUtxoEntry,
    };
    use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
    use kaspa_hashes::Hash as KaspaHash;
    use kaspa_txscript::pay_to_address_script;

    // Build destination script
    let dest_addr = Address::try_from(dest_address)
        .map_err(|e| format!("Invalid destination: {}", e))?;
    let dest_script = pay_to_address_script(&dest_addr);

    // Build change script (first receive address)
    // Use next unused change address
    let chg_idx = data.next_change_index;
    if chg_idx >= data.change_addresses.len() {
        return Err(format!("No more change addresses (used {}/{}). Re-import kpub to derive more.",
            chg_idx, data.change_addresses.len()));
    }
    let change_addr = Address::try_from(data.change_addresses[chg_idx].as_str())
        .map_err(|e| format!("Invalid change address: {}", e))?;
    let change_script = pay_to_address_script(&change_addr);

    // Create PSKT: Creator → Constructor
    let pskt = PSKT::<Creator>::default().constructor();

    // Add inputs
    let mut pskt = pskt;
    for utxo in selected {
        let tx_id_bytes = hex::decode(&utxo.tx_id)
            .map_err(|e| format!("Bad tx_id hex: {}", e))?;

        let input = InputBuilder::default()
            .utxo_entry(ConsensusUtxoEntry::new(
                utxo.amount,
                ScriptPublicKey::from_vec(0, utxo.script_public_key.clone()),
                utxo.block_daa_score,
                false,
            ))
            .previous_outpoint(TransactionOutpoint::new(
                KaspaHash::from_slice(&tx_id_bytes),
                utxo.index,
            ))
            .sighash_type(SIG_HASH_ALL)
            .build()
            .map_err(|e| format!("Input build error: {}", e))?;

        pskt = pskt.input(input);
    }

    // Add destination output
    let dest_output = OutputBuilder::default()
        .amount(amount_sompi)
        .script_public_key(dest_script.clone())
        .build()
        .map_err(|e| format!("Output build error: {}", e))?;
    pskt = pskt.output(dest_output);

    // Add change output if needed
    if change_amount > 0 {
        let change_output = OutputBuilder::default()
            .amount(change_amount)
            .script_public_key(change_script.clone())
            .build()
            .map_err(|e| format!("Change output build error: {}", e))?;
        pskt = pskt.output(change_output);
    }

    let pskt = pskt.no_more_inputs().no_more_outputs();

    // Also store PSKB for future use / broadcast
    let mut bundle = Bundle::new();
    bundle.add_pskt(pskt);
    let _pskb_string = bundle.serialize()
        .map_err(|e| format!("PSKB serialize error: {}", e))?;

    // Serialize as KSPT binary for QR transport (compact, fits in 1-2 QR frames)
    let kspt = serialize_kspt(selected, amount_sompi, &dest_script, change_amount, &change_script)?;

    // Bump change address index so next TX uses a fresh one
    if change_amount > 0 {
        data.next_change_index += 1;
        save_wallet(&data)?;
    }

    Ok(kspt)
}

/// Serialize transaction data to KSPT binary format for QR transport.
/// Format: "KSPT" + version(1) + flags(1) + global + inputs + outputs
fn serialize_kspt(
    inputs: &[UtxoEntry],
    dest_amount: u64,
    dest_script: &kaspa_consensus_core::tx::ScriptPublicKey,
    change_amount: u64,
    change_script: &kaspa_consensus_core::tx::ScriptPublicKey,
) -> Result<String, String> {
    let mut buf = Vec::with_capacity(512);

    let num_outputs = if change_amount > 0 { 2u8 } else { 1u8 };

    // Header
    buf.extend_from_slice(b"KSPT");  // magic
    buf.push(0x01);                   // version
    buf.push(0x00);                   // flags

    // Global
    buf.extend_from_slice(&0u16.to_le_bytes());       // tx_version
    buf.push(inputs.len() as u8);                      // num_inputs
    buf.push(num_outputs);                             // num_outputs
    buf.extend_from_slice(&0u64.to_le_bytes());       // locktime
    buf.extend_from_slice(&[0u8; 20]);                // subnetwork_id (native)
    buf.extend_from_slice(&0u64.to_le_bytes());       // gas
    buf.extend_from_slice(&0u16.to_le_bytes());       // payload_len

    // Per input
    for utxo in inputs {
        // prev_tx_id: 32 bytes
        let tx_id_bytes = hex::decode(&utxo.tx_id)
            .map_err(|e| format!("Bad tx_id: {}", e))?;
        if tx_id_bytes.len() != 32 {
            return Err(format!("tx_id wrong length: {}", tx_id_bytes.len()));
        }
        buf.extend_from_slice(&tx_id_bytes);

        // prev_index: 4 bytes LE
        buf.extend_from_slice(&utxo.index.to_le_bytes());

        // amount: 8 bytes LE (UTXO amount being spent)
        buf.extend_from_slice(&utxo.amount.to_le_bytes());

        // sequence: 8 bytes LE
        buf.extend_from_slice(&0u64.to_le_bytes());

        // sig_op_count: 1 byte
        buf.push(1u8);

        // script_public_key: version(2 LE) + len(1) + script(len)
        let spk = &utxo.script_public_key;
        buf.extend_from_slice(&0u16.to_le_bytes());  // spk version
        buf.push(spk.len() as u8);                    // spk length
        buf.extend_from_slice(spk);                    // spk script bytes
    }

    // Output 1: destination
    buf.extend_from_slice(&dest_amount.to_le_bytes());       // value: 8 bytes LE
    let dest_s = dest_script.script();
    buf.extend_from_slice(&dest_script.version().to_le_bytes()); // spk version: 2 LE
    buf.push(dest_s.len() as u8);                                // spk len: 1
    buf.extend_from_slice(dest_s);                               // spk script

    // Output 2: change (if any)
    if change_amount > 0 {
        buf.extend_from_slice(&change_amount.to_le_bytes());
        let chg_s = change_script.script();
        buf.extend_from_slice(&change_script.version().to_le_bytes());
        buf.push(chg_s.len() as u8);
        buf.extend_from_slice(chg_s);
    }

    println!("  KSPT binary: {} bytes", buf.len());

    // Return as hex string for display (the QR will encode raw bytes via multi-frame)
    Ok(hex::encode(&buf))
}

// ─── Broadcast ───

pub async fn broadcast_pskb(signed_hex: &str, node_url: Option<&str>) -> Result<String, String> {
    let bytes = hex::decode(signed_hex)
        .map_err(|e| format!("Invalid hex: {}", e))?;

    // Parse signed KSPT binary
    if bytes.len() < 6 || &bytes[0..4] != b"KSPT" {
        return Err("Not a signed KSPT (missing KSPT header)".into());
    }
    let version = bytes[4];
    let flags = bytes[5];

    if version == 0x01 && flags != 0x01 {
        return Err(format!("Not a signed KSPT v1 (flags={:#x}, expected 0x01)", flags));
    }
    if version == 0x02 && flags == 0x00 {
        return Err("Partially signed KSPT — needs more signatures before broadcast".into());
    }

    println!("  Parsing signed KSPT v{}, flags={:#x}, {} bytes", version, flags, bytes.len());

    let mut pos: usize = 6;

    // Global
    let tx_version = u16::from_le_bytes([bytes[pos], bytes[pos+1]]); pos += 2;
    let num_inputs = bytes[pos] as usize; pos += 1;
    let num_outputs = bytes[pos] as usize; pos += 1;
    let _locktime = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()); pos += 8;
    let _subnetwork_id = &bytes[pos..pos+20]; pos += 20;
    let _gas = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()); pos += 8;
    let payload_len = u16::from_le_bytes([bytes[pos], bytes[pos+1]]) as usize; pos += 2;
    let _payload = &bytes[pos..pos+payload_len]; pos += payload_len;

    println!("  TX: v{}, {} inputs, {} outputs", tx_version, num_inputs, num_outputs);

    // Parse inputs with signatures
    use kaspa_consensus_core::tx::{
        TransactionInput, TransactionOutput, TransactionOutpoint, Transaction, ScriptPublicKey,
    };
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
    use kaspa_hashes::Hash as KaspaHash;

    let mut tx_inputs = Vec::new();
    let mut utxo_entries = Vec::new();

    for i in 0..num_inputs {
        let tx_id = &bytes[pos..pos+32]; pos += 32;
        let prev_index = u32::from_le_bytes(bytes[pos..pos+4].try_into().unwrap()); pos += 4;
        let amount = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()); pos += 8;
        let sequence = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()); pos += 8;
        let sig_op_count = bytes[pos]; pos += 1;
        let spk_version = u16::from_le_bytes([bytes[pos], bytes[pos+1]]); pos += 2;
        let spk_len = bytes[pos] as usize; pos += 1;
        let spk_script = &bytes[pos..pos+spk_len]; pos += spk_len;

        let mut sig_script = Vec::new();

        if version == 0x01 {
            // v1: sig_len(1) + sig(64) + sighash_type(1)
            let sig_len = bytes[pos] as usize; pos += 1;
            if sig_len > 0 {
                let sig_bytes = &bytes[pos..pos+sig_len]; pos += sig_len;
                let sighash_type = bytes[pos]; pos += 1;
                sig_script.push((sig_len + 1) as u8);
                sig_script.extend_from_slice(sig_bytes);
                sig_script.push(sighash_type);
                println!("  Input {}: P2PK signed ({} byte sig)", i, sig_len);
            } else {
                return Err(format!("Input {} has no signature", i));
            }
        } else {
            // v2: sig_count(1) + [pubkey_pos(1) + sighash_type(1) + sig(64)]×sig_count
            let sig_count = bytes[pos] as usize; pos += 1;
            if sig_count == 0 {
                return Err(format!("Input {} has no signatures", i));
            }

            // Detect script type to build correct sig_script
            let is_p2sh = spk_len == 35
                && spk_script[0] == 0xAA  // OP_BLAKE2B
                && spk_script[1] == 0x20  // OP_DATA_32
                && spk_script[34] == 0x87; // OP_EQUAL
            let is_multisig = !is_p2sh && spk_len >= 37
                && spk_script[spk_len - 1] == 0xAE  // OP_CHECKMULTISIG
                && spk_script[0] >= 0x51 && spk_script[0] <= 0x55;

            if is_multisig || is_p2sh {
                // Multisig/P2SH sig_script: [<65> <sig+sighash>]×M
                // Signatures must be in pubkey order
                let mut sigs: Vec<(u8, Vec<u8>)> = Vec::new(); // (pubkey_pos, sig+sighash)
                for _s in 0..sig_count {
                    let pubkey_pos = bytes[pos]; pos += 1;
                    let sighash_type = bytes[pos]; pos += 1;
                    let sig_bytes = &bytes[pos..pos+64]; pos += 64;
                    let mut sig_data = Vec::with_capacity(65);
                    sig_data.extend_from_slice(sig_bytes);
                    sig_data.push(sighash_type);
                    sigs.push((pubkey_pos, sig_data));
                }
                // Sort by pubkey position (required by Kaspa consensus)
                sigs.sort_by_key(|s| s.0);
                for (_pk_pos, sig_data) in &sigs {
                    sig_script.push(sig_data.len() as u8); // push opcode
                    sig_script.extend_from_slice(sig_data);
                }

                // Read redeem script (always present in v2 after sigs)
                let rs_len = bytes[pos] as usize; pos += 1;
                if rs_len > 0 {
                    let redeem_script = &bytes[pos..pos+rs_len]; pos += rs_len;
                    if is_p2sh {
                        // P2SH: append redeem script as data push
                        if rs_len <= 75 {
                            sig_script.push(rs_len as u8); // OP_DATA_N
                        } else {
                            sig_script.push(0x4C); // OP_PUSHDATA1
                            sig_script.push(rs_len as u8);
                        }
                        sig_script.extend_from_slice(redeem_script);
                        println!("  Input {}: P2SH multisig {}/{} sigs, redeem {} bytes", i, sig_count, sig_op_count, rs_len);
                    } else {
                        println!("  Input {}: multisig {}/{} sigs", i, sig_count, sig_op_count);
                    }
                } else {
                    println!("  Input {}: multisig {}/{} sigs (no redeem script)", i, sig_count, sig_op_count);
                }
            } else {
                // P2PK with v2 format — use first sig
                let _pubkey_pos = bytes[pos]; pos += 1;
                let sighash_type = bytes[pos]; pos += 1;
                let sig_bytes = &bytes[pos..pos+64]; pos += 64;
                sig_script.push(65u8);
                sig_script.extend_from_slice(sig_bytes);
                sig_script.push(sighash_type);
                // Skip remaining sigs if any
                for _ in 1..sig_count {
                    pos += 1 + 1 + 64; // pubkey_pos + sighash + sig
                }
                // Skip redeem script
                let rs_len = bytes[pos] as usize; pos += 1;
                if rs_len > 0 { pos += rs_len; }
                println!("  Input {}: P2PK signed (v2 format)", i);
            }
        }

        let outpoint = TransactionOutpoint::new(
            KaspaHash::from_slice(tx_id),
            prev_index,
        );

        tx_inputs.push(TransactionInput::new(
            outpoint,
            sig_script,
            sequence,
            sig_op_count,
        ));

        utxo_entries.push(kaspa_consensus_core::tx::UtxoEntry::new(
            amount,
            ScriptPublicKey::from_vec(spk_version, spk_script.to_vec()),
            0,
            false,
        ));
    }

    // Parse outputs
    let mut tx_outputs = Vec::new();
    for _o in 0..num_outputs {
        let value = u64::from_le_bytes(bytes[pos..pos+8].try_into().unwrap()); pos += 8;
        let spk_version = u16::from_le_bytes([bytes[pos], bytes[pos+1]]); pos += 2;
        let spk_len = bytes[pos] as usize; pos += 1;
        let spk_script = &bytes[pos..pos+spk_len]; pos += spk_len;

        tx_outputs.push(TransactionOutput::new(
            value,
            ScriptPublicKey::from_vec(spk_version, spk_script.to_vec()),
        ));
    }

    // Build the transaction
    let tx = Transaction::new(
        tx_version,
        tx_inputs,
        tx_outputs,
        0,
        SUBNETWORK_ID_NATIVE,
        0,
        vec![],
    );

    let tx_id = tx.id();
    println!("  TX ID: {}", tx_id);
    println!("  Inputs: {}", num_inputs);
    for (i, inp) in tx.inputs.iter().enumerate() {
        println!("    Input {}: sig_script {} bytes", i, inp.signature_script.len());
    }
    println!("  Outputs: {}", num_outputs);

    // Connect and submit
    let client = connect_to_node(node_url).await?;

    use kaspa_rpc_core::api::rpc::RpcApi;
    use kaspa_rpc_core::model::tx::{RpcTransaction, RpcTransactionInput, RpcTransactionOutput, RpcTransactionOutpoint};

    let rpc_inputs: Vec<RpcTransactionInput> = tx.inputs.iter().map(|inp| {
        RpcTransactionInput {
            previous_outpoint: RpcTransactionOutpoint::from(inp.previous_outpoint),
            signature_script: inp.signature_script.clone(),
            sequence: inp.sequence,
            sig_op_count: inp.sig_op_count,
            verbose_data: None,
        }
    }).collect();

    let rpc_outputs: Vec<RpcTransactionOutput> = tx.outputs.iter().map(|out| {
        RpcTransactionOutput {
            value: out.value,
            script_public_key: out.script_public_key.clone(),
            verbose_data: None,
        }
    }).collect();

    let rpc_tx = RpcTransaction {
        version: tx.version,
        inputs: rpc_inputs,
        outputs: rpc_outputs,
        lock_time: tx.lock_time,
        subnetwork_id: tx.subnetwork_id.clone(),
        gas: tx.gas,
        payload: tx.payload.clone(),
        mass: 0,
        verbose_data: None,
    };

    let _resp = client.submit_transaction(rpc_tx, false).await
        .map_err(|e| format!("Broadcast failed: {}", e))?;

    Ok(tx_id.to_string())
}

// ─── Info ───

pub async fn show_info() -> Result<String, String> {
    let data = load_wallet()?;
    Ok(format!(
        "KasSigner Companion Wallet\n  kpub: {}...{}\n  Receive addresses: {}\n  Change addresses: {}",
        &data.kpub[..12],
        &data.kpub[data.kpub.len()-8..],
        data.receive_addresses.len(),
        data.change_addresses.len(),
    ))
}

// ─── Test KSPT generator ───

#[allow(clippy::needless_range_loop)]
pub fn generate_test_kspt(num_inputs: u8, num_outputs: u8) -> Result<String, String> {
    let ni = num_inputs.clamp(1, 8) as usize;
    let no = num_outputs.clamp(1, 4) as usize;

    let mut buf = Vec::with_capacity(1024);

    buf.extend_from_slice(b"KSPT");
    buf.push(0x01);
    buf.push(0x00);

    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(ni as u8);
    buf.push(no as u8);
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&[0u8; 20]);
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    for i in 0..ni {
        let mut tx_id = [0u8; 32];
        for b in 0..32 { tx_id[b] = ((i * 37 + b * 13 + 7) & 0xFF) as u8; }
        buf.extend_from_slice(&tx_id);
        buf.extend_from_slice(&(i as u32).to_le_bytes());
        buf.extend_from_slice(&500_000_000u64.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.push(1u8);
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(34u8);
        buf.push(0x20);
        let mut pk = [0u8; 32];
        for b in 0..32 { pk[b] = ((i * 41 + b * 17 + 3) & 0xFF) as u8; }
        buf.extend_from_slice(&pk);
        buf.push(0xac);
    }

    let total_in = ni as u64 * 500_000_000;
    let fee = 1000u64;
    let per_output = (total_in - fee) / no as u64;

    for o in 0..no {
        let amount = if o == no - 1 {
            total_in - fee - per_output * (no as u64 - 1)
        } else {
            per_output
        };
        buf.extend_from_slice(&amount.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(34u8);
        buf.push(0x20);
        let mut pk = [0u8; 32];
        for b in 0..32 { pk[b] = ((o * 53 + b * 19 + 11) & 0xFF) as u8; }
        buf.extend_from_slice(&pk);
        buf.push(0xac);
    }

    println!("  KSPT binary: {} bytes ({} inputs, {} outputs)", buf.len(), ni, no);
    Ok(hex::encode(&buf))
}

/// Generate a fake multisig KSPT for testing co-signing on the device.
///
/// Creates inputs with M-of-N multisig scripts using deterministic fake pubkeys.
/// The device will recognize these as multisig inputs and require M signatures
/// from different seeds to fully sign.
///
/// Kaspa multisig script format:
///   OP_M [OP_DATA_32 <pubkey>]×N OP_N OP_CHECKMULTISIG
///
/// Where OP_1=0x51..OP_5=0x55, OP_DATA_32=0x20, OP_CHECKMULTISIG=0xAE
#[allow(clippy::needless_range_loop)]
pub fn generate_test_multisig_kspt(m: u8, n: u8, num_inputs: u8) -> Result<String, String> {
    let m = m.clamp(1, 5);
    let n = n.max(m).min(5);
    let ni = num_inputs.clamp(1, 4) as usize;

    // Build M-of-N multisig script
    // OP_M + N*(OP_DATA_32 + 32-byte-pubkey) + OP_N + OP_CHECKMULTISIG
    let script_len = 1 + (n as usize) * 33 + 1 + 1;
    let mut ms_script = vec![0u8; script_len];
    ms_script[0] = 0x50 + m; // OP_M
    for k in 0..n as usize {
        ms_script[1 + k * 33] = 0x20; // OP_DATA_32
        // Deterministic fake pubkey per key position
        for b in 0..32 {
            ms_script[1 + k * 33 + 1 + b] = ((k * 47 + b * 23 + 5) & 0xFF) as u8;
        }
    }
    ms_script[script_len - 2] = 0x50 + n; // OP_N
    ms_script[script_len - 1] = 0xAE;     // OP_CHECKMULTISIG

    let mut buf = Vec::with_capacity(1024);

    // Header
    buf.extend_from_slice(b"KSPT");
    buf.push(0x01); // version
    buf.push(0x00); // flags

    // Global
    buf.extend_from_slice(&0u16.to_le_bytes());  // tx_version
    buf.push(ni as u8);                           // num_inputs
    buf.push(2u8);                                // num_outputs (dest + change)
    buf.extend_from_slice(&0u64.to_le_bytes());  // locktime
    buf.extend_from_slice(&[0u8; 20]);           // subnetwork_id
    buf.extend_from_slice(&0u64.to_le_bytes());  // gas
    buf.extend_from_slice(&0u16.to_le_bytes());  // payload_len

    // Inputs — each references the multisig script
    for i in 0..ni {
        // Fake tx_id
        let mut tx_id = [0u8; 32];
        for b in 0..32 { tx_id[b] = ((i * 37 + b * 13 + 7) & 0xFF) as u8; }
        buf.extend_from_slice(&tx_id);
        buf.extend_from_slice(&(i as u32).to_le_bytes());      // prev_index
        buf.extend_from_slice(&500_000_000u64.to_le_bytes());  // amount (5 KAS)
        buf.extend_from_slice(&0u64.to_le_bytes());            // sequence
        buf.push(n);                                            // sig_op_count = N
        buf.extend_from_slice(&0u16.to_le_bytes());            // spk version
        buf.push(script_len as u8);                             // spk len
        buf.extend_from_slice(&ms_script);                      // multisig script
    }

    // Outputs — standard P2PK scripts
    let total_in = ni as u64 * 500_000_000;
    let fee = 10_000u64;
    let dest_amount = total_in / 2;
    let change_amount = total_in - dest_amount - fee;

    // Output 1: destination (fake P2PK)
    buf.extend_from_slice(&dest_amount.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes()); // spk version
    buf.push(34u8);                              // P2PK script len
    buf.push(0x20);                              // OP_DATA_32
    let mut dest_pk = [0u8; 32];
    for b in 0..32 { dest_pk[b] = ((b * 53 + 11) & 0xFF) as u8; }
    buf.extend_from_slice(&dest_pk);
    buf.push(0xAC);                              // OP_CHECKSIG

    // Output 2: change (fake P2PK)
    buf.extend_from_slice(&change_amount.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(34u8);
    buf.push(0x20);
    let mut chg_pk = [0u8; 32];
    for b in 0..32 { chg_pk[b] = ((b * 59 + 17) & 0xFF) as u8; }
    buf.extend_from_slice(&chg_pk);
    buf.push(0xAC);

    println!("  Multisig KSPT: {} bytes ({}-of-{}, {} inputs, script {} bytes)",
        buf.len(), m, n, ni, script_len);
    println!("  Pubkeys in multisig script:");
    for k in 0..n as usize {
        let pk_start = 1 + k * 33 + 1;
        let pk = &ms_script[pk_start..pk_start + 32];
        print!("    Key {}: ", k);
        for b in pk { print!("{:02x}", b); }
        println!();
    }

    Ok(hex::encode(&buf))
}

/// Generate a multisig KSPT using real kpubs for end-to-end co-signing tests.
///
/// Derives address at `addr_index` from each kpub, builds an M-of-N multisig
/// script with those real pubkeys, and creates a KSPT the device can actually sign.
#[allow(clippy::needless_range_loop)]
pub fn generate_real_multisig_kspt(m: u8, kpubs: &[String], addr_index: u32) -> Result<String, String> {
    let n = kpubs.len();
    if !(2..=5).contains(&n) { return Err("Need 2-5 kpubs".into()); }
    let m = m.max(1).min(n as u8);

    // Derive x-only pubkey at addr_index for each kpub
    let mut pubkeys: Vec<[u8; 32]> = Vec::new();
    for (i, kpub_str) in kpubs.iter().enumerate() {
        let xpub: ExtendedPublicKey<secp256k1::PublicKey> = kpub_str.parse()
            .map_err(|e: kaspa_bip32::Error| format!("kpub #{} parse error: {}", i, e))?;
        // Derive /0/addr_index (receive chain)
        let receive_chain = xpub.derive_child(ChildNumber::new(0, false)
            .map_err(|e| format!("derive /0: {}", e))?)
            .map_err(|e| format!("derive receive chain: {}", e))?;
        let child = receive_chain.derive_child(ChildNumber::new(addr_index, false)
            .map_err(|e| format!("child {}: {}", addr_index, e))?)
            .map_err(|e| format!("derive receive/{}: {}", addr_index, e))?;
        let compressed = child.public_key().serialize();
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(&compressed[1..33]);
        println!("  Key #{} (addr {}): {}", i, addr_index, hex::encode(x_only));
        pubkeys.push(x_only);
    }

    // Build M-of-N multisig script
    let script_len = 1 + n * 33 + 1 + 1;
    let mut ms_script = vec![0u8; script_len];
    ms_script[0] = 0x50 + m;  // OP_M
    for k in 0..n {
        ms_script[1 + k * 33] = 0x20; // OP_DATA_32
        ms_script[1 + k * 33 + 1..1 + k * 33 + 33].copy_from_slice(&pubkeys[k]);
    }
    ms_script[script_len - 2] = 0x50 + n as u8; // OP_N
    ms_script[script_len - 1] = 0xAE;            // OP_CHECKMULTISIG

    let mut buf = Vec::with_capacity(512);

    // Header
    buf.extend_from_slice(b"KSPT");
    buf.push(0x01);
    buf.push(0x00);

    // Global: 1 input, 2 outputs
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(1u8);  // num_inputs
    buf.push(2u8);  // num_outputs
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&[0u8; 20]);
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    // Input: fake UTXO with 5 KAS, referencing multisig script
    let mut tx_id = [0u8; 32];
    for b in 0..32 { tx_id[b] = ((b * 37 + 7) & 0xFF) as u8; }
    buf.extend_from_slice(&tx_id);
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&500_000_000u64.to_le_bytes()); // 5 KAS
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.push(n as u8); // sig_op_count
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(script_len as u8);
    buf.extend_from_slice(&ms_script);

    // Output 1: destination (2.5 KAS to fake P2PK)
    let dest_amount = 250_000_000u64;
    buf.extend_from_slice(&dest_amount.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(34u8);
    buf.push(0x20);
    buf.extend_from_slice(&pubkeys[0]); // send to first signer's address
    buf.push(0xAC);

    // Output 2: change (remaining minus fee)
    let change_amount = 500_000_000 - dest_amount - 10_000;
    buf.extend_from_slice(&change_amount.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(34u8);
    buf.push(0x20);
    buf.extend_from_slice(&pubkeys[if n > 1 { 1 } else { 0 }]); // change to second signer
    buf.push(0xAC);

    println!("  Multisig KSPT: {} bytes ({}-of-{}, script {} bytes)", buf.len(), m, n, script_len);

    Ok(hex::encode(&buf))
}

// ─── Real Multisig Transactions ───

/// Helper: derive x-only pubkeys from kpubs and build M-of-N multisig script.
fn build_multisig_script(m: u8, kpubs: &[String], addr_index: u32) -> Result<(Vec<u8>, Vec<[u8; 32]>), String> {
    let n = kpubs.len();
    if !(2..=5).contains(&n) { return Err("Need 2-5 kpubs".into()); }
    let m = m.max(1).min(n as u8);

    let mut pubkeys: Vec<[u8; 32]> = Vec::new();
    for (i, kpub_str) in kpubs.iter().enumerate() {
        let xpub: ExtendedPublicKey<secp256k1::PublicKey> = kpub_str.parse()
            .map_err(|e: kaspa_bip32::Error| format!("kpub #{} parse error: {}", i, e))?;
        let receive_chain = xpub.derive_child(ChildNumber::new(0, false)
            .map_err(|e| format!("derive /0: {}", e))?)
            .map_err(|e| format!("derive receive chain: {}", e))?;
        let child = receive_chain.derive_child(ChildNumber::new(addr_index, false)
            .map_err(|e| format!("child {}: {}", addr_index, e))?)
            .map_err(|e| format!("derive receive/{}: {}", addr_index, e))?;
        let compressed = child.public_key().serialize();
        let mut x_only = [0u8; 32];
        x_only.copy_from_slice(&compressed[1..33]);
        pubkeys.push(x_only);
    }

    // Sort pubkeys lexicographically — ensures the same set of kpubs
    // always produces the same redeem script regardless of input order
    pubkeys.sort();

    let script_len = 1 + n * 33 + 1 + 1;
    let mut ms_script = vec![0u8; script_len];
    ms_script[0] = 0x50 + m;
    for k in 0..n {
        ms_script[1 + k * 33] = 0x20;
        ms_script[1 + k * 33 + 1..1 + k * 33 + 33].copy_from_slice(&pubkeys[k]);
    }
    ms_script[script_len - 2] = 0x50 + n as u8;
    ms_script[script_len - 1] = 0xAE;

    println!("  Multisig script: {}-of-{}, {} bytes", m, n, script_len);
    for (i, pk) in pubkeys.iter().enumerate() {
        println!("    Key #{}: {}", i, hex::encode(pk));
    }

    Ok((ms_script, pubkeys))
}

/// Send KAS from the imported wallet to a multisig output.
/// Creates a KSPT where the destination output uses the raw multisig script.
/// After signing + broadcast, note the TX ID to use with send-from-multisig.
pub async fn send_to_multisig(
    amount_kas: f64, m: u8, kpubs: &[String], addr_index: u32, fee: u64,
    node_url: Option<&str>,
) -> Result<String, String> {
    let mut data = load_wallet()?;
    let amount_sompi = (amount_kas * 100_000_000.0) as u64;

    let (ms_script, _pubkeys) = build_multisig_script(m, kpubs, addr_index)?;

    let client = connect_to_node(node_url).await?;

    // Gather UTXOs from our wallet
    let all_addresses: Vec<&str> = data.receive_addresses.iter()
        .chain(data.change_addresses.iter())
        .map(|s| s.as_str())
        .collect();

    let mut all_utxos = Vec::new();
    for addr_str in &all_addresses {
        let utxos = fetch_utxos(&client, addr_str).await?;
        all_utxos.extend(utxos);
    }

    let total_needed = amount_sompi + fee;
    let mut selected = Vec::new();
    let mut selected_total: u64 = 0;
    all_utxos.sort_by(|a, b| b.amount.cmp(&a.amount));
    for utxo in &all_utxos {
        selected.push(utxo.clone());
        selected_total += utxo.amount;
        if selected_total >= total_needed { break; }
    }
    if selected_total < total_needed {
        return Err(format!("Insufficient funds: have {} sompi, need {}", selected_total, total_needed));
    }

    let change_amount = selected_total - amount_sompi - fee;

    // Change address (P2PK, from our wallet)
    let chg_idx = data.next_change_index;
    if chg_idx >= data.change_addresses.len() {
        return Err("No more change addresses".into());
    }
    let change_addr = Address::try_from(data.change_addresses[chg_idx].as_str())
        .map_err(|e| format!("Invalid change address: {}", e))?;
    let change_script = kaspa_txscript::pay_to_address_script(&change_addr);

    println!("  Send {} KAS to {}-of-{} multisig (P2SH)", amount_kas, m, kpubs.len());

    // Compute P2SH script: blake2b_256(redeem_script) → OP_BLAKE2B OP_DATA_32 <hash> OP_EQUAL
    let script_hash = {
        let mut hasher = blake2b_simd::Params::new().hash_length(32).to_state();
        hasher.update(&ms_script);
        let h = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(h.as_bytes());
        hash
    };
    let mut p2sh_script = [0u8; 35];
    p2sh_script[0] = 0xAA;  // OP_BLAKE2B
    p2sh_script[1] = 0x20;  // OP_DATA_32
    p2sh_script[2..34].copy_from_slice(&script_hash);
    p2sh_script[34] = 0x87; // OP_EQUAL

    // Compute and display the P2SH address
    let p2sh_addr = Address::new(Prefix::Mainnet, Version::ScriptHash, &script_hash);
    println!("  P2SH address: {}", p2sh_addr);
    println!("  Redeem script: {} bytes ({})", ms_script.len(), hex::encode(&ms_script));
    println!("  Change: {:.8} KAS to {}", change_amount as f64 / 1e8, data.change_addresses[chg_idx]);
    println!("  Fee: {} sompi", fee);

    // Build KSPT with multisig output
    let mut buf = Vec::with_capacity(512);
    let num_outputs = if change_amount > 0 { 2u8 } else { 1u8 };

    // Header
    buf.extend_from_slice(b"KSPT");
    buf.push(0x01);
    buf.push(0x00);

    // Global
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(selected.len() as u8);
    buf.push(num_outputs);
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&[0u8; 20]);
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    // Inputs (P2PK from our wallet)
    for utxo in &selected {
        let tx_id_bytes = hex::decode(&utxo.tx_id)
            .map_err(|e| format!("Bad tx_id: {}", e))?;
        buf.extend_from_slice(&tx_id_bytes);
        buf.extend_from_slice(&utxo.index.to_le_bytes());
        buf.extend_from_slice(&utxo.amount.to_le_bytes());
        buf.extend_from_slice(&0u64.to_le_bytes());
        buf.push(1u8);
        buf.extend_from_slice(&0u16.to_le_bytes());
        buf.push(utxo.script_public_key.len() as u8);
        buf.extend_from_slice(&utxo.script_public_key);
    }

    // Output 1: P2SH multisig destination
    buf.extend_from_slice(&amount_sompi.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(35u8); // P2SH script is always 35 bytes
    buf.extend_from_slice(&p2sh_script);

    // Output 2: change (P2PK)
    if change_amount > 0 {
        buf.extend_from_slice(&change_amount.to_le_bytes());
        let chg_s = change_script.script();
        buf.extend_from_slice(&change_script.version().to_le_bytes());
        buf.push(chg_s.len() as u8);
        buf.extend_from_slice(chg_s);
    }

    // Bump change index
    if change_amount > 0 {
        data.next_change_index += 1;
        save_wallet(&data)?;
    }

    println!("  KSPT: {} bytes", buf.len());
    Ok(hex::encode(&buf))
}

/// Create a KSPT to spend from a multisig UTXO.
/// Requires the exact TX ID, output index, and amount of the multisig UTXO.
#[allow(clippy::too_many_arguments)]
pub fn send_from_multisig(
    dest_address: &str, txid: &str, vout: u32, utxo_amount: u64,
    m: u8, kpubs: &[String], addr_index: u32, fee: u64,
) -> Result<String, String> {
    let _dest = Address::try_from(dest_address)
        .map_err(|e| format!("Invalid destination: {}", e))?;
    let dest_script = kaspa_txscript::pay_to_address_script(&_dest);

    let (ms_script, _pubkeys) = build_multisig_script(m, kpubs, addr_index)?;

    let tx_id_bytes = hex::decode(txid)
        .map_err(|e| format!("Invalid txid hex: {}", e))?;
    if tx_id_bytes.len() != 32 {
        return Err(format!("txid must be 32 bytes, got {}", tx_id_bytes.len()));
    }

    // Compute the P2SH script (same as funding) for the UTXO's scriptPubKey
    let script_hash = {
        let mut hasher = blake2b_simd::Params::new().hash_length(32).to_state();
        hasher.update(&ms_script);
        let h = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(h.as_bytes());
        hash
    };
    let mut p2sh_script = [0u8; 35];
    p2sh_script[0] = 0xAA;  // OP_BLAKE2B
    p2sh_script[1] = 0x20;  // OP_DATA_32
    p2sh_script[2..34].copy_from_slice(&script_hash);
    p2sh_script[34] = 0x87; // OP_EQUAL

    let send_amount = utxo_amount - fee;
    println!("  Spend from P2SH multisig: {} sompi ({:.8} KAS)", utxo_amount, utxo_amount as f64 / 1e8);
    println!("  Send: {} sompi to {}", send_amount, dest_address);
    println!("  Fee: {} sompi", fee);
    println!("  Redeem script: {} bytes", ms_script.len());

    let mut buf = Vec::with_capacity(512);

    // Header — flags 0x02 = has redeem scripts
    buf.extend_from_slice(b"KSPT");
    buf.push(0x01); // version
    buf.push(0x02); // flags: bit 1 = has redeem scripts

    // Global: 1 input, 1 output
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(1u8);
    buf.push(1u8);
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&[0u8; 20]);
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&0u16.to_le_bytes());

    // Input: the P2SH UTXO
    buf.extend_from_slice(&tx_id_bytes);
    buf.extend_from_slice(&vout.to_le_bytes());
    buf.extend_from_slice(&utxo_amount.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.push(kpubs.len() as u8); // sig_op_count = N
    buf.extend_from_slice(&0u16.to_le_bytes());
    buf.push(35u8); // P2SH script is 35 bytes
    buf.extend_from_slice(&p2sh_script);

    // Redeem script for this input (flags 0x02 tells device to read this)
    buf.push(ms_script.len() as u8);
    buf.extend_from_slice(&ms_script);

    // Output: destination P2PK
    buf.extend_from_slice(&send_amount.to_le_bytes());
    let dest_s = dest_script.script();
    buf.extend_from_slice(&dest_script.version().to_le_bytes());
    buf.push(dest_s.len() as u8);
    buf.extend_from_slice(dest_s);

    println!("  KSPT: {} bytes", buf.len());
    Ok(hex::encode(&buf))
}

// ─── QR display ───

/// Maximum payload per QR frame.
/// Each frame: 3 bytes header + data. Must produce QR version ≤8 (192 byte binary capacity).
/// 120 bytes data + 3 byte header = 123 bytes → version 7 QR (154 capacity). Safe for all cameras.
const MAX_FRAME_DATA: usize = 78;

pub fn display_qr(hex_data: &str) {
    // Decode hex to raw bytes for binary QR
    let bytes = match hex::decode(hex_data) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("(Invalid hex data)");
            return;
        }
    };

    // Always use multi-frame for KSPT binary — ensures each frame fits version ≤8 QR
    display_multiframe_qr(&bytes);
}

#[allow(dead_code)]
fn display_single_qr(data: &[u8]) {
    use qrcode::QrCode;
    if let Ok(code) = QrCode::new(data) {
        let string = code.render::<char>()
            .quiet_zone(false)
            .module_dimensions(2, 1)
            .build();
        println!("{}", string);
    } else {
        eprintln!("(QR generation failed)");
    }
}

fn display_multiframe_qr(data: &[u8]) {
    let total_frames = data.len().div_ceil(MAX_FRAME_DATA);
    if total_frames > 16 {
        eprintln!("Error: data too large ({} bytes, {} frames needed, max 16)",
            data.len(), total_frames);
        return;
    }

    let total = total_frames as u8;
    // Compute balanced frame size: split evenly so all frames are similar size
    let balanced_frame_size = data.len().div_ceil(total_frames);
    println!("Multi-frame QR: {} frame(s) ({} bytes total)", total, data.len());

    // Build all QR frame images
    let scale: u32 = 10;
    let border: u32 = 4;
    let mut frame_images: Vec<Vec<u8>> = Vec::new();
    let mut frame_sizes: Vec<u32> = Vec::new();
    let mut img_size: u32 = 0;

    for frame_num in 0..total_frames {
        let start = frame_num * balanced_frame_size;
        let end = (start + balanced_frame_size).min(data.len());
        let frag = &data[start..end];
        let frag_len = frag.len() as u8;

        let mut frame_buf = Vec::with_capacity(3 + frag.len());
        frame_buf.push(frame_num as u8);
        frame_buf.push(total);
        frame_buf.push(frag_len);
        frame_buf.extend_from_slice(frag);

        println!("  Frame {}/{}: {} bytes", frame_num + 1, total, frag_len);

        use qrcode::QrCode;
        match QrCode::new(&frame_buf) {
            Ok(code) => {
                let modules = code.to_colors();
                let size = code.width() as u32;
                img_size = (size + border * 2) * scale;

                // Build raw pixel data (indexed: 0=white, 1=black)
                let mut pixels = vec![0u8; (img_size * img_size) as usize];
                for (i, color) in modules.iter().enumerate() {
                    if *color == qrcode::types::Color::Dark {
                        let mx = i as u32 % size;
                        let my = i as u32 / size;
                        let px = (mx + border) * scale;
                        let py = (my + border) * scale;
                        for dy in 0..scale {
                            for dx in 0..scale {
                                let idx = ((py + dy) * img_size + (px + dx)) as usize;
                                pixels[idx] = 1;
                            }
                        }
                    }
                }
                frame_images.push(pixels);
                frame_sizes.push(img_size);
            }
            Err(e) => {
                eprintln!("QR generation failed for frame {}: {:?}", frame_num + 1, e);
                return;
            }
        }
    }

    if frame_images.is_empty() || img_size == 0 {
        eprintln!("No frames generated");
        return;
    }

    // Save individual PNGs
    for (i, (pixels, fsize)) in frame_images.iter().zip(frame_sizes.iter()).enumerate() {
        let filename = format!("frame_{}.png", i + 1);
        let sz = *fsize;
        let mut img = image::GrayImage::new(sz, sz);
        for p in img.pixels_mut() { *p = image::Luma([255u8]); }
        for (j, &px) in pixels.iter().enumerate() {
            if px == 1 {
                let x = j as u32 % sz;
                let y = j as u32 / sz;
                if x < sz && y < sz {
                    img.put_pixel(x, y, image::Luma([0u8]));
                }
            }
        }
        let _ = img.save(&filename);
        println!("  Saved: {}", filename);
    }

    // Write animated GIF — all frames must be same size, use the largest
    let max_size = *frame_sizes.iter().max().unwrap_or(&0);
    let filename = "transaction.gif";
    let file = match std::fs::File::create(filename) {
        Ok(f) => f,
        Err(e) => { eprintln!("Failed to create {}: {}", filename, e); return; }
    };

    let palette = &[255, 255, 255, 0, 0, 0]; // index 0 = white, index 1 = black
    let mut encoder = gif::Encoder::new(file, max_size as u16, max_size as u16, palette)
        .expect("GIF encoder init");
    encoder.set_repeat(gif::Repeat::Infinite).expect("GIF repeat");

    for (pixels, &fsize) in frame_images.iter().zip(frame_sizes.iter()) {
        // Pad smaller frames to max_size (center them)
        let mut padded = vec![0u8; (max_size * max_size) as usize]; // 0 = white
        let offset = (max_size - fsize) / 2;
        for y in 0..fsize {
            for x in 0..fsize {
                let src = (y * fsize + x) as usize;
                let dst = ((y + offset) * max_size + (x + offset)) as usize;
                padded[dst] = pixels[src];
            }
        }

        let mut frame = gif::Frame {
            width: max_size as u16,
            height: max_size as u16,
            delay: 150,
            ..gif::Frame::default()
        };
        frame.dispose = gif::DisposalMethod::Background;
        frame.transparent = None;
        frame.needs_user_input = false;
        frame.top = 0;
        frame.left = 0;
        frame.interlaced = false;
        frame.palette = None;
        frame.buffer = std::borrow::Cow::Owned(padded);
        encoder.write_frame(&frame).expect("GIF write frame");
    }

    drop(encoder);
    println!("\nSaved: {} ({} frames, cycling every 1.5s)", filename, total_frames);
    println!("Also saved: frame_1.png, frame_2.png, ...");
    let _ = std::process::Command::new("open").arg(filename).spawn();
    println!("Point KasSigner camera at the animated QR.");
}

// ─── Node connection ───

async fn connect_to_node(node_url: Option<&str>) -> Result<kaspa_wrpc_client::KaspaRpcClient, String> {
    use kaspa_wrpc_client::{KaspaRpcClient, Resolver, WrpcEncoding};
    use kaspa_consensus_core::network::{NetworkType, NetworkId};

    let network_id = NetworkId::new(NetworkType::Mainnet);

    let client = if let Some(url) = node_url {
        // Warn if ws:// (unencrypted) to a non-local address
        if url.starts_with("ws://") {
            let is_local = url.starts_with("ws://127.")
                || url.starts_with("ws://localhost")
                || url.starts_with("ws://192.168.")
                || url.starts_with("ws://10.")
                || url.starts_with("ws://172.16.")
                || url.starts_with("ws://[::1]");
            if !is_local {
                eprintln!("  \u{26A0} Warning: unencrypted connection to remote node.");
                eprintln!("    Use wss:// for nodes outside your LAN.");
                eprintln!();
            }
        }
        // Direct connection to user's own node
        println!("  Connecting to node: {}...", url);
        KaspaRpcClient::new(
            WrpcEncoding::Borsh,
            Some(url),
            None,
            Some(network_id),
            None,
        ).map_err(|e| format!("RPC client error: {}", e))?
    } else {
        // Use default resolver (public nodes)
        let resolver = Resolver::default();
        println!("  Connecting to Kaspa network...");
        KaspaRpcClient::new(
            WrpcEncoding::Borsh,
            None,
            Some(resolver),
            Some(network_id),
            None,
        ).map_err(|e| format!("RPC client error: {}", e))?
    };

    client.connect(None).await
        .map_err(|e| format!("Connection failed: {}", e))?;
    println!("  Connected!");

    Ok(client)
}

// ─── UTXO fetch ───

#[derive(Clone)]
pub struct UtxoEntry {
    pub tx_id: String,
    pub index: u32,
    pub amount: u64,
    pub script_public_key: Vec<u8>,
    pub block_daa_score: u64,
}

async fn fetch_utxos(client: &kaspa_wrpc_client::KaspaRpcClient, address: &str) -> Result<Vec<UtxoEntry>, String> {
    use kaspa_rpc_core::api::rpc::RpcApi;

    let addr = Address::try_from(address)
        .map_err(|e| format!("Invalid address {}: {}", address, e))?;

    let resp = client.get_utxos_by_addresses(vec![addr]).await
        .map_err(|e| format!("UTXO fetch failed: {}", e))?;

    let utxos: Vec<UtxoEntry> = resp.iter().map(|entry| {
        UtxoEntry {
            tx_id: entry.outpoint.transaction_id.to_string(),
            index: entry.outpoint.index,
            amount: entry.utxo_entry.amount,
            script_public_key: entry.utxo_entry.script_public_key.script().to_vec(),
            block_daa_score: entry.utxo_entry.block_daa_score,
        }
    }).collect();

    Ok(utxos)
}
