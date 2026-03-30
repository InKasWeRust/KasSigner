// KasSigner Companion — wallet module
// Handles kpub import, address derivation, UTXO tracking, PSKB creation

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

pub async fn show_balance() -> Result<BalanceInfo, String> {
    let data = load_wallet()?;
    let all_addresses: Vec<&str> = data.receive_addresses.iter()
        .chain(data.change_addresses.iter())
        .map(|s| s.as_str())
        .collect();

    let client = connect_to_node().await?;

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

// ─── Send (create unsigned PSKB) ───

pub async fn create_pskb(dest_address: &str, amount_kas: f64, fee: u64) -> Result<String, String> {
    let mut data = load_wallet()?;
    let amount_sompi = (amount_kas * 100_000_000.0) as u64;

    let _dest = Address::try_from(dest_address)
        .map_err(|e| format!("Invalid destination address: {}", e))?;

    let client = connect_to_node().await?;

    // Fetch fee estimate from node
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

/// Internal: build PSKB/KSPT from selected UTXOs and output parameters.
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
    let kspt = serialize_kspt(&selected, amount_sompi, &dest_script, change_amount, &change_script)?;

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

pub async fn broadcast_pskb(signed_hex: &str) -> Result<String, String> {
    let bytes = hex::decode(signed_hex)
        .map_err(|e| format!("Invalid hex: {}", e))?;

    // Parse signed KSPT binary
    if bytes.len() < 6 || &bytes[0..4] != b"KSPT" {
        return Err("Not a signed KSPT (missing KSPT header)".into());
    }
    let version = bytes[4];
    let flags = bytes[5];
    if flags != 0x01 {
        return Err(format!("Not a signed KSPT (flags={:#x}, expected 0x01)", flags));
    }

    println!("  Parsing signed KSPT v{}, {} bytes", version, bytes.len());

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

        // Signature
        let sig_len = bytes[pos] as usize; pos += 1;
        let mut sig_script = Vec::new();
        if sig_len > 0 {
            let sig_bytes = &bytes[pos..pos+sig_len]; pos += sig_len;
            let sighash_type = bytes[pos]; pos += 1;

            // Build signature script: <sig_len+1> <sig_bytes> <sighash_type>
            // Schnorr signature script format for Kaspa
            sig_script.push((sig_len + 1) as u8); // push opcode: data length
            sig_script.extend_from_slice(sig_bytes);
            sig_script.push(sighash_type);

            println!("  Input {}: signed ({} byte sig, sighash={:#x})", i, sig_len, sighash_type);
        } else {
            println!("  Input {}: UNSIGNED", i);
            return Err(format!("Input {} has no signature", i));
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
            0, // block_daa_score — not needed for broadcast
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
        0, // locktime
        SUBNETWORK_ID_NATIVE,
        0, // gas
        vec![], // payload
    );

    let tx_id = tx.id();
    println!("  TX ID: {}", tx_id);
    println!("  TX version: {}", tx_version);
    println!("  Inputs: {}", num_inputs);
    for (i, inp) in tx.inputs.iter().enumerate() {
        println!("    Input {}: sig_script {} bytes = {}",
            i, inp.signature_script.len(), hex::encode(&inp.signature_script));
    }
    println!("  Outputs: {}", num_outputs);

    // Connect and submit
    let client = connect_to_node().await?;

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

pub fn generate_test_kspt(num_inputs: u8, num_outputs: u8) -> Result<String, String> {
    let ni = num_inputs.max(1).min(8) as usize;
    let no = num_outputs.max(1).min(4) as usize;

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

// ─── QR display ───

/// Maximum payload per QR frame.
/// Each frame: 3 bytes header + data. Must produce QR version ≤8 (192 byte binary capacity).
/// 120 bytes data + 3 byte header = 123 bytes → version 7 QR (154 capacity). Safe for all cameras.
const MAX_FRAME_DATA: usize = 120;

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
    let total_frames = (data.len() + MAX_FRAME_DATA - 1) / MAX_FRAME_DATA;
    if total_frames > 16 {
        eprintln!("Error: data too large ({} bytes, {} frames needed, max 16)",
            data.len(), total_frames);
        return;
    }

    let total = total_frames as u8;
    // Compute balanced frame size: split evenly so all frames are similar size
    let balanced_frame_size = (data.len() + total_frames - 1) / total_frames;
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

        let mut frame = gif::Frame::default();
        frame.width = max_size as u16;
        frame.height = max_size as u16;
        frame.delay = 150;
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

async fn connect_to_node() -> Result<kaspa_wrpc_client::KaspaRpcClient, String> {
    use kaspa_wrpc_client::{KaspaRpcClient, Resolver, WrpcEncoding};
    use kaspa_consensus_core::network::{NetworkType, NetworkId};

    let resolver = Resolver::default();
    let network_id = NetworkId::new(NetworkType::Mainnet);

    let client = KaspaRpcClient::new(
        WrpcEncoding::Borsh,
        None,
        Some(resolver),
        Some(network_id),
        None,
    ).map_err(|e| format!("RPC client error: {}", e))?;

    println!("  Connecting to Kaspa network...");
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
