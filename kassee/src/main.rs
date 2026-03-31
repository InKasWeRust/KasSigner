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

// kassee/main.rs — CLI entry point
//
// Flow:
//   1. kassee import <kpub>            — store kpub, derive addresses
//   2. kassee balance                  — connect to node, show balance
//   3. kassee send <addr> <amount>     — build unsigned KSPT, show as QR
//   4. kassee broadcast <hex>          — broadcast signed KSPT from device
//   5. kassee relay <hex>              — relay partial KSPT as QR for next signer

use clap::{Parser, Subcommand};

mod wallet;

#[derive(Parser)]
#[command(name = "kassee")]
#[command(about = "KasSigner Companion — watch-only wallet for air-gapped signing")]
struct Cli {
    /// Connect to your own Kaspa node (wRPC URL, e.g. ws://192.168.1.100:17110)
    #[arg(long, global = true)]
    node: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Import a kpub from KasSigner and derive addresses
    Import {
        /// The kpub string (e.g. kpub2...)
        kpub: String,
    },
    /// Show balance for the imported kpub
    Balance,
    /// Show derived addresses
    Addresses {
        /// Number of addresses to show (default 10)
        #[arg(short = 'n', long, default_value = "10")]
        count: u32,
        /// Show change addresses instead of receive
        #[arg(long)]
        change: bool,
    },
    /// Create an unsigned KSPT and display as QR
    Send {
        /// Destination kaspa: address
        address: String,
        /// Amount in KAS (e.g. 1.5)
        amount: f64,
        /// Total fee in sompi (default 10000 = 0.0001 KAS)
        #[arg(short, long, default_value = "10000")]
        fee: u64,
    },
    /// Broadcast a signed KSPT (hex string from KasSigner)
    Broadcast {
        /// Signed KSPT hex
        pskb: String,
    },
    /// Relay a partial or signed KSPT as QR for another device to scan
    Relay {
        /// KSPT hex (partial or fully signed, from another device's serial output)
        hex: String,
    },
    /// Show stored wallet info
    Info,
    /// Generate a fake multi-input KSPT to test QR scanning
    Test {
        /// Number of inputs (1-8)
        #[arg(short, long, default_value = "3")]
        inputs: u8,
        /// Number of outputs (1-4)
        #[arg(short, long, default_value = "2")]
        outputs: u8,
    },
    /// Generate a fake multisig KSPT for testing co-signing flow
    TestMultisig {
        /// M (required signatures)
        #[arg(short, long, default_value = "2")]
        m: u8,
        /// N (total keys)
        #[arg(short, long, default_value = "3")]
        n: u8,
        /// Number of inputs (1-4)
        #[arg(short, long, default_value = "1")]
        inputs: u8,
    },
    /// Generate a multisig KSPT using real kpubs for end-to-end testing
    TestMultisigReal {
        /// M (required signatures)
        #[arg(short, long, default_value = "2")]
        m: u8,
        /// kpub strings for each signer (space-separated)
        #[arg(required = true)]
        kpubs: Vec<String>,
        /// Address index to use for each kpub (default 0)
        #[arg(short = 'a', long, default_value = "0")]
        addr_index: u32,
    },
    /// Send KAS from your wallet to a multisig address (fund the multisig)
    SendToMultisig {
        /// Amount in KAS to send
        amount: f64,
        /// M (required signatures)
        #[arg(short, long, default_value = "2")]
        m: u8,
        /// kpub strings for each signer
        #[arg(required = true)]
        kpubs: Vec<String>,
        /// Address index to use for each kpub (default 0)
        #[arg(short = 'a', long, default_value = "0")]
        addr_index: u32,
        /// Total fee in sompi (default 10000)
        #[arg(short, long, default_value = "10000")]
        fee: u64,
    },
    /// Spend from a multisig UTXO (co-sign with devices)
    SendFromMultisig {
        /// Destination kaspa: address
        address: String,
        /// TX ID of the multisig UTXO
        #[arg(long)]
        txid: String,
        /// Output index of the multisig UTXO
        #[arg(long, default_value = "0")]
        vout: u32,
        /// Amount in the multisig UTXO (sompi)
        #[arg(long)]
        utxo_amount: u64,
        /// M (required signatures)
        #[arg(short, long, default_value = "2")]
        m: u8,
        /// kpub strings for each signer
        #[arg(required = true)]
        kpubs: Vec<String>,
        /// Address index used when funding (default 0)
        #[arg(short = 'a', long, default_value = "0")]
        addr_index: u32,
        /// Total fee in sompi (default 10000)
        #[arg(short, long, default_value = "10000")]
        fee: u64,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let node_url = cli.node;

    match cli.command {
        Commands::Import { kpub } => {
            match wallet::import_kpub(&kpub).await {
                Ok(info) => {
                    println!("Imported kpub successfully!");
                    println!("  First address: {}", info.first_address);
                    println!("  Addresses derived: {}", info.address_count);
                    println!("  Saved to: {}", info.wallet_file);
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::Balance => {
            match wallet::show_balance(node_url.as_deref()).await {
                Ok(bal) => {
                    println!("Balance: {} KAS", bal.total_kas());
                    println!("  UTXOs: {}", bal.utxo_count);
                    println!("  Addresses with funds: {}", bal.funded_addresses);
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::Addresses { count, change } => {
            match wallet::show_addresses_with_type(count, change).await {
                Ok(addrs) => {
                    if change {
                        println!("  Change addresses (m/.../1/x):");
                    } else {
                        println!("  Receive addresses (m/.../0/x):");
                    }
                    for (i, addr) in addrs.iter().enumerate() {
                        println!("  #{}: {}", i, addr);
                    }
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::Send { address, amount, fee } => {
            match wallet::create_pskb(&address, amount, fee, node_url.as_deref()).await {
                Ok(kspt_hex) => {
                    println!("Unsigned KSPT created ({} bytes)", kspt_hex.len() / 2);
                    println!();
                    // Display as QR in terminal (binary, not text)
                    wallet::display_qr(&kspt_hex);
                    println!();
                    println!("Scan this QR with KasSigner to sign.");
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::Broadcast { pskb } => {
            match wallet::broadcast_pskb(&pskb, node_url.as_deref()).await {
                Ok(txid) => {
                    println!("Transaction broadcast!");
                    println!("  TX ID: {}", txid);
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::Relay { hex } => {
            let clean = hex.trim();
            if clean.len() < 12 || !clean.starts_with("4b535054") {
                eprintln!("Error: Not a KSPT hex (must start with 4b535054 / 'KSPT')");
            } else {
                let version = u8::from_str_radix(&clean[8..10], 16).unwrap_or(0);
                let flags = u8::from_str_radix(&clean[10..12], 16).unwrap_or(0);
                let status = match (version, flags) {
                    (0x02, 0x00) => "PARTIAL — needs more signatures",
                    (0x02, 0x01) => "FULLY SIGNED — ready to broadcast",
                    (0x01, 0x01) => "SIGNED (v1) — ready to broadcast",
                    _ => "unknown status",
                };
                println!("Relaying KSPT v{}, flags={:#x} ({})", version, flags, status);
                println!("  {} bytes", clean.len() / 2);
                println!();
                wallet::display_qr(clean);
                println!();
                println!("Point the next signer's camera at the animated QR.");
            }
        }
        Commands::Info => {
            match wallet::show_info().await {
                Ok(info) => println!("{}", info),
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::Test { inputs, outputs } => {
            match wallet::generate_test_kspt(inputs, outputs) {
                Ok(kspt_hex) => {
                    println!("Test KSPT: {} inputs, {} outputs ({} bytes)",
                        inputs, outputs, kspt_hex.len() / 2);
                    println!();
                    wallet::display_qr(&kspt_hex);
                    println!();
                    println!("This is a FAKE transaction for testing multi-frame QR.");
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::TestMultisig { m, n, inputs } => {
            match wallet::generate_test_multisig_kspt(m, n, inputs) {
                Ok(kspt_hex) => {
                    println!("Test Multisig KSPT: {}-of-{}, {} inputs ({} bytes)",
                        m, n, inputs, kspt_hex.len() / 2);
                    println!();
                    wallet::display_qr(&kspt_hex);
                    println!();
                    println!("This is a FAKE multisig transaction for testing co-signing.");
                    println!("Load {} different seeds on the device and sign {} times.", n, m);
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::TestMultisigReal { m, kpubs, addr_index } => {
            match wallet::generate_real_multisig_kspt(m, &kpubs, addr_index) {
                Ok(kspt_hex) => {
                    println!("Real Multisig KSPT: {}-of-{} ({} bytes)",
                        m, kpubs.len(), kspt_hex.len() / 2);
                    println!();
                    wallet::display_qr(&kspt_hex);
                    println!();
                    println!("Scan with KasSigner. Needs {} signatures from {} keys.", m, kpubs.len());
                    println!("Load the corresponding seeds and sign on each device.");
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::SendToMultisig { amount, m, kpubs, addr_index, fee } => {
            match wallet::send_to_multisig(amount, m, &kpubs, addr_index, fee, node_url.as_deref()).await {
                Ok(kspt_hex) => {
                    println!("Multisig funding KSPT created ({} bytes)", kspt_hex.len() / 2);
                    println!();
                    wallet::display_qr(&kspt_hex);
                    println!();
                    println!("Sign with your device to fund the {}-of-{} multisig.", m, kpubs.len());
                    println!("After broadcast, note the TX ID for spend-from-multisig.");
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
        Commands::SendFromMultisig { address, txid, vout, utxo_amount, m, kpubs, addr_index, fee } => {
            match wallet::send_from_multisig(&address, &txid, vout, utxo_amount, m, &kpubs, addr_index, fee) {
                Ok(kspt_hex) => {
                    println!("Multisig spend KSPT created ({} bytes)", kspt_hex.len() / 2);
                    println!();
                    wallet::display_qr(&kspt_hex);
                    println!();
                    println!("Co-sign with {} devices, then broadcast the fully signed TX.", m);
                }
                Err(e) => eprintln!("Error: {}", e),
            }
        }
    }
}
