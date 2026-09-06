//! Generate a canonical v3 signed firmware-update manifest.

use sha2::{Digest, Sha256};
use signer_firmware_core::update::manifest as update_manifest;
use signer_firmware_core::update::manifest::FirmwareUpdateManifest;
use std::{env, fs, path::Path};

fn main() {
    if let Err(error) = run() {
        eprintln!("ERROR: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 9 {
        return Err(format!(
            "usage: {} <firmware.bin> <signing-key.bin> <board> <version> <release-sequence> <security-version> <partition.csv|none> <output.ksfu>",
            args.first().map(String::as_str).unwrap_or("gen-update-manifest")
        ));
    }
    let image = fs::read(&args[1]).map_err(|error| format!("read image: {error}"))?;
    let key = read_key(Path::new(&args[2]))?;
    let board = board_id(&args[3])?;
    let version = parse_version(&args[4])?;
    let release_sequence = parse_positive_u32(&args[5], "release-sequence")?;
    let security_version = parse_positive_u32(&args[6], "security-version")?;
    if security_version > 16 {
        return Err("security-version must be within ESP32-S3 range 1..=16".to_string());
    }
    let partition_layout_hash = partition_hash(board, &args[7])?;
    let image_size = u32::try_from(image.len()).map_err(|_| "firmware image exceeds u32 length".to_string())?;
    let image_hash = sha256(&image);

    let mut manifest = FirmwareUpdateManifest {
        schema: update_manifest::SCHEMA_VERSION,
        board,
        channel: update_manifest::CHANNEL_PRODUCTION,
        version,
        release_sequence,
        security_version,
        image_size,
        partition_layout_hash,
        image_hash,
        signature: [0; update_manifest::SIGNATURE_LEN],
    };
    manifest.signature = firmware_tools::sign_release_digest(&key, &manifest.signing_digest())
        .map_err(|error| format!("release signature rejected: {error:?}"))?;
    fs::write(&args[8], manifest.encode()).map_err(|error| format!("write manifest: {error}"))?;
    println!("Wrote {}-byte canonical KSFU v3 manifest: {}", update_manifest::MANIFEST_LEN, args[8]);
    println!("release_sequence={}", manifest.release_sequence);
    println!("security_version={}", manifest.security_version);
    println!("image_sha256={}", hex(&manifest.image_hash));
    println!("partition_layout_sha256={}", hex(&manifest.partition_layout_hash));
    Ok(())
}

fn parse_positive_u32(value: &str, label: &str) -> Result<u32, String> {
    let parsed = value.parse::<u32>().map_err(|_| format!("{label} must be an integer"))?;
    (parsed > 0).then_some(parsed).ok_or_else(|| format!("{label} must be greater than zero"))
}

fn board_id(name: &str) -> Result<u8, String> {
    match name {
        "m5stack" => Ok(update_manifest::BOARD_M5STACK_CORES3),
        "waveshare" => Ok(update_manifest::BOARD_WAVESHARE),
        "waveshare-af" => Ok(update_manifest::BOARD_WAVESHARE_AF),
        _ => Err(format!("unsupported board: {name}")),
    }
}

fn partition_hash(board: u8, value: &str) -> Result<[u8; 32], String> {
    if board != update_manifest::BOARD_M5STACK_CORES3 {
        if value != "none" {
            return Err("boards without repository-owned partition tables must use 'none'".to_string());
        }
        return Ok([0; 32]);
    }
    if value == "none" {
        return Err("m5stack requires the exact CoreS3 partition CSV".to_string());
    }
    let bytes = fs::read(value).map_err(|error| format!("read partition table: {error}"))?;
    Ok(sha256(&bytes))
}

fn parse_version(value: &str) -> Result<u32, String> {
    let mut parts = value.split('.');
    let major = parse_component(parts.next(), "major")?;
    let minor = parse_component(parts.next(), "minor")?;
    let patch = parse_component(parts.next(), "patch")?;
    if parts.next().is_some() || minor > 99 || patch > 99 {
        return Err("version must be MAJOR.MINOR.PATCH with minor/patch <= 99".to_string());
    }
    major
        .checked_mul(10_000)
        .and_then(|value| value.checked_add(minor * 100))
        .and_then(|value| value.checked_add(patch))
        .ok_or_else(|| "version numeric encoding overflow".to_string())
}

fn parse_component(value: Option<&str>, label: &str) -> Result<u32, String> {
    value
        .ok_or_else(|| format!("missing version {label}"))?
        .parse::<u32>()
        .map_err(|_| format!("invalid version {label}"))
}

fn read_key(path: &Path) -> Result<[u8; 32], String> {
    let bytes = fs::read(path).map_err(|error| format!("read signing key: {error}"))?;
    bytes.as_slice().try_into().map_err(|_| "signing key must be exactly 32 bytes".to_string())
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(data);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
