use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use offline_signer::{
    derivation::{bip39, xpub},
    transaction::{
        kspt,
        model::{SigHashType, Transaction},
    },
    OfflineSigner,
};
use rand_core::{OsRng, RngCore};
use shared_signer::{PsktParsed, TxInputFormat};

const STATE_MAGIC: &str = "KASSIGNER_FUNDED_E2E_V1";

fn main() {
    if let Err(error) = run() {
        eprintln!("ERROR: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let command = args.next().ok_or_else(usage)?;
    match command.as_str() {
        "wallet" => {
            let state = args.next().ok_or_else(usage)?;
            reject_extra(args)?;
            wallet(Path::new(&state))
        }
        "sign" => {
            let state = args.next().ok_or_else(usage)?;
            let kspt_hex = args.next().ok_or_else(usage)?;
            reject_extra(args)?;
            sign(Path::new(&state), &kspt_hex)
        }
        _ => Err(usage()),
    }
}

fn usage() -> String {
    "usage: kassigner-funded-e2e wallet <secret-state-file> | sign <secret-state-file> <kspt-hex>"
        .to_string()
}

fn reject_extra(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    if args.next().is_some() {
        Err(usage())
    } else {
        Ok(())
    }
}

fn wallet(path: &Path) -> Result<(), String> {
    let (mnemonic, created) = if path.exists() {
        (read_mnemonic(path)?, false)
    } else {
        (create_mnemonic(path)?, true)
    };
    let kpub = derive_kpub(&mnemonic)?;
    println!("created={}", u8::from(created));
    println!("kpub={kpub}");
    Ok(())
}

fn sign(path: &Path, kspt_hex: &str) -> Result<(), String> {
    let mnemonic = read_mnemonic(path)?;
    let signer = OfflineSigner::new();
    let seed = signer
        .restore_wallet_24(&mnemonic, "")
        .map_err(|error| format!("stored funded-E2E mnemonic is invalid: {error:?}"))?;
    let wire = decode_hex(kspt_hex)?;
    let mut transaction = Transaction::try_new()
        .map_err(|_| "cannot allocate funded-E2E transaction state".to_string())?;
    let mut parsed = PsktParsed::default();
    let mut scratch = [];
    signer
        .review_transaction(
            TxInputFormat::KsptCompact,
            &wire,
            &mut scratch,
            &mut transaction,
            &mut parsed,
        )
        .map_err(|error| format!("signer rejected relayed KSPT: {error:?}"))?;

    let mut signing_entropy = [0u8; 32];
    OsRng.fill_bytes(&mut signing_entropy);
    let signed_count = kspt::sign_transaction_multi_addr_with_entropy(
        &mut transaction,
        &seed.bytes,
        SigHashType::All,
        &signing_entropy,
    )
    .map_err(|error| format!("signer failed to sign relayed KSPT: {error:?}"))?;
    signing_entropy.fill(0);

    if signed_count != transaction.num_inputs || !kspt::is_fully_signed(&transaction) {
        return Err(format!(
            "signer did not fully sign transaction (signed {signed_count} of {} inputs)",
            transaction.num_inputs
        ));
    }

    let signed_wire = kspt::serialize_compact_kspt_vec(&transaction)
        .map_err(|error| format!("signed KSPT serialization failed: {error:?}"))?;
    println!("{}", encode_hex(&signed_wire));
    Ok(())
}

fn create_mnemonic(path: &Path) -> Result<bip39::Mnemonic24, String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create funded-E2E state directory: {error}"))?;
    }

    let signer = OfflineSigner::new();
    let mut entropy = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);
    let mnemonic = signer.generate_wallet_24(&entropy);
    entropy.fill(0);

    let sentence = mnemonic_sentence(&mnemonic);
    let mut file = secure_create_new(path)?;
    writeln!(file, "{STATE_MAGIC}")
        .and_then(|_| writeln!(file, "{sentence}"))
        .and_then(|_| file.sync_all())
        .map_err(|error| format!("cannot persist funded-E2E wallet secret: {error}"))?;
    secure_existing_permissions(path)?;
    Ok(mnemonic)
}

fn read_mnemonic(path: &Path) -> Result<bip39::Mnemonic24, String> {
    secure_existing_permissions(path)?;
    let mut file = File::open(path)
        .map_err(|error| format!("cannot open funded-E2E wallet secret: {error}"))?;
    let mut text = String::new();
    file.read_to_string(&mut text)
        .map_err(|error| format!("cannot read funded-E2E wallet secret: {error}"))?;
    let mut lines = text.lines();
    if lines.next() != Some(STATE_MAGIC) {
        return Err("funded-E2E wallet state has an unsupported format".to_string());
    }
    let sentence = lines
        .next()
        .ok_or_else(|| "funded-E2E wallet state is missing its mnemonic".to_string())?;
    if lines.any(|line| !line.trim().is_empty()) {
        return Err("funded-E2E wallet state contains unexpected trailing data".to_string());
    }
    parse_mnemonic(sentence)
}

fn derive_kpub(mnemonic: &bip39::Mnemonic24) -> Result<String, String> {
    let signer = OfflineSigner::new();
    let seed = signer
        .restore_wallet_24(mnemonic, "")
        .map_err(|error| format!("funded-E2E mnemonic validation failed: {error:?}"))?;
    let mut output = [0u8; xpub::KPUB_MAX_LEN];
    let length = signer
        .export_watch_account(&seed.bytes, &mut output)
        .map_err(|error| format!("funded-E2E kpub derivation failed: {error:?}"))?;
    core::str::from_utf8(&output[..length])
        .map(str::to_owned)
        .map_err(|_| "derived funded-E2E kpub was not UTF-8".to_string())
}

fn mnemonic_sentence(mnemonic: &bip39::Mnemonic24) -> String {
    mnemonic
        .indices
        .iter()
        .map(|index| bip39::index_to_word(*index))
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_mnemonic(sentence: &str) -> Result<bip39::Mnemonic24, String> {
    let words = sentence.split_whitespace().collect::<Vec<_>>();
    if words.len() != 24 {
        return Err(format!(
            "funded-E2E wallet mnemonic must contain 24 words, found {}",
            words.len()
        ));
    }
    let mut indices = [0u16; 24];
    for (slot, word) in indices.iter_mut().zip(words) {
        *slot = bip39::word_to_index(word)
            .map_err(|_| format!("funded-E2E wallet mnemonic contains unknown word: {word}"))?;
    }
    let mnemonic = bip39::Mnemonic24 { indices };
    bip39::validate_mnemonic_24(&mnemonic)
        .map_err(|error| format!("funded-E2E wallet mnemonic checksum failed: {error:?}"))?;
    Ok(mnemonic)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("KSPT hex length must be even".to_string());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0])?;
            let low = hex_nibble(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("KSPT contains non-hexadecimal text".to_string()),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[cfg(unix)]
fn secure_create_new(path: &Path) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| format!("cannot create funded-E2E wallet secret: {error}"))
}

#[cfg(not(unix))]
fn secure_create_new(path: &Path) -> Result<File, String> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("cannot create funded-E2E wallet secret: {error}"))
}

#[cfg(unix)]
fn secure_existing_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::{PermissionsExt};
    let permissions = fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, permissions)
        .map_err(|error| format!("cannot restrict funded-E2E wallet secret permissions: {error}"))
}

#[cfg(not(unix))]
fn secure_existing_permissions(_path: &Path) -> Result<(), String> {
    Ok(())
}

