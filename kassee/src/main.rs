// KasSigner Companion — Watch-only wallet for air-gapped PSKT signing
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
// GPL-3.0 License
//
// This tool imports a kpub (extended public key) from KasSigner,
// derives addresses, tracks UTXOs via a public Kaspa node,
// and creates unsigned PSKBs for the device to sign.
//
// Flow:
//   1. companion import <kpub>        — store kpub, derive addresses
//   2. companion balance              — connect to node, show balance
//   3. companion send <addr> <amount> — build unsigned PSKB, show as QR
//   4. companion broadcast <pskb>     — broadcast signed PSKB from device

use clap::{Parser, Subcommand};

mod wallet;

#[derive(Parser)]
#[command(name = "kassigner-companion")]
#[command(about = "KasSigner Companion — watch-only wallet for air-gapped signing")]
struct Cli {
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
    /// Create an unsigned PSKB and display as QR
    Send {
        /// Destination kaspa: address
        address: String,
        /// Amount in KAS (e.g. 1.5)
        amount: f64,
        /// Total fee in sompi (default 10000 = 0.0001 KAS)
        #[arg(short, long, default_value = "10000")]
        fee: u64,
    },
    /// Broadcast a signed PSKB (hex string from KasSigner)
    Broadcast {
        /// Signed PSKB hex
        pskb: String,
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
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

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
            match wallet::show_balance().await {
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
            match wallet::create_pskb(&address, amount, fee).await {
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
            match wallet::broadcast_pskb(&pskb).await {
                Ok(txid) => {
                    println!("Transaction broadcast!");
                    println!("  TX ID: {}", txid);
                }
                Err(e) => eprintln!("Error: {}", e),
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
    }
}
