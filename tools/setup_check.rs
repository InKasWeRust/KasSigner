// KasSigner Setup Check — Cross-platform build environment validator
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
//
// Run: cargo run --bin kassigner-setup
//
// Checks everything needed to build KasSigner from source:
//   - OS and architecture detection
//   - Rust toolchain (stable + espup Xtensa)
//   - espflash for flashing
//   - Docker for reproducible builds (optional)
//   - Serial port detection for connected devices
//
// Works on macOS (Intel + Apple Silicon), Linux (x86_64 + aarch64), Windows.

use std::process::Command;
use std::env;

// ═══════════════════════════════════════════════════════════════
// ANSI colors (disabled on Windows unless VIRTUAL_TERMINAL)
// ═══════════════════════════════════════════════════════════════

const GREEN: &str = "\x1b[32m";
const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const CYAN: &str = "\x1b[36m";
const BOLD: &str = "\x1b[1m";
const RESET: &str = "\x1b[0m";

fn ok(msg: &str) {
    println!("  {GREEN}✓{RESET} {msg}");
}

fn fail(msg: &str) {
    println!("  {RED}✗{RESET} {msg}");
}

fn warn(msg: &str) {
    println!("  {YELLOW}⚠{RESET} {msg}");
}

fn info(msg: &str) {
    println!("  {CYAN}→{RESET} {msg}");
}

fn header(msg: &str) {
    println!("\n{BOLD}{msg}{RESET}");
}

// ═══════════════════════════════════════════════════════════════
// Command helpers
// ═══════════════════════════════════════════════════════════════

/// Run a command, return (success, stdout_trimmed)
fn run_cmd(program: &str, args: &[&str]) -> (bool, String) {
    match Command::new(program).args(args).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            // Some tools print version to stderr
            let combined = if stdout.is_empty() { stderr } else { stdout };
            (output.status.success(), combined)
        }
        Err(_) => (false, String::new()),
    }
}

/// Get first line of command output
fn cmd_first_line(program: &str, args: &[&str]) -> Option<String> {
    let (success, output) = run_cmd(program, args);
    if success || !output.is_empty() {
        output.lines().next().map(|s| s.to_string())
    } else {
        None
    }
}

// ═══════════════════════════════════════════════════════════════
// Checks
// ═══════════════════════════════════════════════════════════════

fn check_os() {
    header("Platform");

    let os = env::consts::OS;
    let arch = env::consts::ARCH;

    let os_name = match os {
        "macos" => "macOS",
        "linux" => "Linux",
        "windows" => "Windows",
        other => other,
    };

    let arch_name = match arch {
        "x86_64" => "x86_64 (Intel/AMD)",
        "aarch64" => "aarch64 (ARM64 / Apple Silicon)",
        other => other,
    };

    ok(&format!("{os_name} — {arch_name}"));

    if os == "windows" {
        warn("Windows: use PowerShell or Git Bash. WSL2 also works.");
    }
}

fn check_rust() -> bool {
    header("Rust toolchain");

    // Check rustc
    let rustc_ok = match cmd_first_line("rustc", &["--version"]) {
        Some(v) => {
            ok(&format!("rustc: {v}"));
            true
        }
        None => {
            fail("rustc not found");
            info("Install: https://rustup.rs");
            false
        }
    };

    // Check cargo
    let cargo_ok = match cmd_first_line("cargo", &["--version"]) {
        Some(v) => {
            ok(&format!("cargo: {v}"));
            true
        }
        None => {
            fail("cargo not found");
            info("Install Rust: https://rustup.rs");
            false
        }
    };

    // Check rustup
    match cmd_first_line("rustup", &["--version"]) {
        Some(v) => ok(&format!("rustup: {v}")),
        None => {
            fail("rustup not found");
            info("Install: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh");
        }
    }

    rustc_ok && cargo_ok
}

fn check_espup() -> bool {
    header("ESP32 toolchain (espup)");

    // Check espup
    let espup_ok = match cmd_first_line("espup", &["--version"]) {
        Some(v) => {
            ok(&format!("espup: {v}"));
            true
        }
        None => {
            fail("espup not found — required for Xtensa ESP32-S3 target");
            info("Install: cargo install espup");
            info("Then run: espup install");
            false
        }
    };

    // Check for Xtensa toolchain
    let (_, toolchains) = run_cmd("rustup", &["toolchain", "list"]);
    let has_esp = toolchains.lines().any(|l| l.contains("esp"));

    if has_esp {
        ok("Xtensa toolchain installed (esp)");
    } else {
        fail("Xtensa toolchain not found");
        if espup_ok {
            info("Run: espup install");
        } else {
            info("Install espup first, then run: espup install");
        }
    }

    // Check for xtensa-esp32s3-none-elf target
    // This is provided by espup, not rustup target add
    let xtensa_check = std::path::Path::new(&format!(
        "{}/.rustup/toolchains/esp",
        env::var("HOME").unwrap_or_else(|_| env::var("USERPROFILE").unwrap_or_default())
    ))
    .exists();

    if xtensa_check {
        ok("ESP toolchain directory exists (~/.rustup/toolchains/esp)");
    } else {
        // Try Windows path
        let win_path = format!(
            "{}\\.rustup\\toolchains\\esp",
            env::var("USERPROFILE").unwrap_or_default()
        );
        if std::path::Path::new(&win_path).exists() {
            ok("ESP toolchain directory exists");
        } else {
            warn("ESP toolchain directory not found — may need: espup install");
        }
    }

    espup_ok && has_esp
}

fn check_espflash() -> bool {
    header("espflash (flashing tool)");

    match cmd_first_line("espflash", &["--version"]) {
        Some(v) => {
            ok(&format!("espflash: {v}"));

            // Check version >= 3.0
            if let Some(ver_str) = v.split_whitespace().nth(1) {
                if let Some(major) = ver_str.split('.').next().and_then(|s| s.parse::<u32>().ok()) {
                    if major >= 3 {
                        ok("Version 3.x+ (compatible)");
                    } else {
                        warn(&format!("Version {ver_str} may be outdated — consider: cargo install espflash"));
                    }
                }
            }
            true
        }
        None => {
            fail("espflash not found — required for flashing firmware");
            info("Install: cargo install espflash");
            false
        }
    }
}

fn check_docker() {
    header("Docker (optional — for reproducible builds)");

    match cmd_first_line("docker", &["--version"]) {
        Some(v) => {
            ok(&format!("{v}"));

            // Check if Docker daemon is running
            let (running, _) = run_cmd("docker", &["info"]);
            if running {
                ok("Docker daemon is running");
            } else {
                warn("Docker installed but daemon not running");
                info("Start Docker Desktop or: sudo systemctl start docker");
            }
        }
        None => {
            warn("Docker not found (optional — needed only for reproducible builds)");
            info("Install: https://docs.docker.com/get-docker/");
        }
    }
}

fn check_serial_ports() {
    header("Serial ports (connected devices)");

    let os = env::consts::OS;

    match os {
        "macos" => {
            // Glob doesn't expand in Command args — use shell
            let (_, output) = run_cmd("sh", &["-c", "ls /dev/cu.usbmodem* /dev/cu.usbserial* /dev/cu.SLAB* 2>/dev/null"]);
            if output.is_empty() {
                warn("No USB serial devices found — connect your device and retry");
            } else {
                for line in output.lines() {
                    if !line.is_empty() {
                        ok(&format!("Found: {line}"));
                    }
                }
            }
        }
        "linux" => {
            let (_, output) = run_cmd("sh", &["-c", "ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null"]);
            if output.is_empty() {
                warn("No USB serial devices found");
                info("Connect device and check: ls /dev/ttyUSB* /dev/ttyACM*");
                info("May need: sudo usermod -aG dialout $USER (then re-login)");
            } else {
                for line in output.lines() {
                    if !line.is_empty() {
                        ok(&format!("Found: {line}"));
                    }
                }
            }
        }
        "windows" => {
            warn("Serial port detection on Windows: use Device Manager or:");
            info("mode (in Command Prompt) to list COM ports");
        }
        _ => {
            warn("Unknown OS — check serial ports manually");
        }
    }
}

fn check_build_env() {
    header("Build environment");

    // Check if we're in the project root, bootloader/, or tools/
    let at_root = std::path::Path::new("bootloader/Cargo.toml").exists()
        && std::path::Path::new("tools/Cargo.toml").exists();
    let at_bootloader = std::fs::read_to_string("Cargo.toml")
        .map(|s| s.contains("kassigner-bootloader"))
        .unwrap_or(false);
    let at_tools = std::fs::read_to_string("Cargo.toml")
        .map(|s| s.contains("firmware-tools"))
        .unwrap_or(false);
    let parent_is_root = std::path::Path::new("../bootloader/Cargo.toml").exists()
        && std::path::Path::new("../tools/Cargo.toml").exists();

    if at_root {
        ok("KasSigner project root detected");
    } else if at_tools && parent_is_root {
        ok("Inside tools/ — project root is ../");
    } else if at_bootloader && parent_is_root {
        ok("Inside bootloader/ — project root is ../");
    } else if at_bootloader || at_tools {
        ok("Inside KasSigner project directory");
    } else {
        warn("Not in KasSigner project directory");
        info("Clone: git clone https://github.com/InKasWeRust/KasSigner.git");
    }

    // Check for required env var awareness
    info("Waveshare builds require: ESP_HAL_CONFIG_PSRAM_MODE=octal");
    info("M5Stack builds use: --no-default-features --features m5stack");
}

// ═══════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════

fn main() {
    println!("{BOLD}╔══════════════════════════════════════════╗{RESET}");
    println!("{BOLD}║  KasSigner Build Environment Check       ║{RESET}");
    println!("{BOLD}╚══════════════════════════════════════════╝{RESET}");

    check_os();
    let rust_ok = check_rust();
    let esp_ok = check_espup();
    let flash_ok = check_espflash();
    check_docker();
    check_serial_ports();
    check_build_env();

    // Summary
    header("Summary");

    let mut issues = 0;

    if !rust_ok {
        fail("Rust toolchain: MISSING");
        info("Fix: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh");
        issues += 1;
    }
    if !esp_ok {
        fail("ESP32 Xtensa toolchain: MISSING");
        if rust_ok {
            info("Fix: cargo install espup && espup install");
        } else {
            info("Fix: install Rust first, then: cargo install espup && espup install");
        }
        issues += 1;
    }
    if !flash_ok {
        fail("espflash: MISSING");
        if rust_ok {
            info("Fix: cargo install espflash");
        } else {
            info("Fix: install Rust first, then: cargo install espflash");
        }
        issues += 1;
    }

    if issues == 0 {
        println!();
        println!("  {GREEN}{BOLD}All required tools installed.{RESET}");
        println!();
        println!("  Waveshare ESP32-S3-Touch-LCD-2:");
        println!("    {CYAN}cd ../bootloader{RESET}");
        println!("    {CYAN}ESP_HAL_CONFIG_PSRAM_MODE=octal cargo run --release{RESET}");
        println!();
        println!("  M5Stack CoreS3 / CoreS3 Lite:");
        println!("    {CYAN}cd ../bootloader{RESET}");
        println!("    {CYAN}cargo run --release --no-default-features --features m5stack{RESET}");
        println!();
    } else {
        println!();
        println!("  {RED}{BOLD}{issues} issue(s) found.{RESET} Fix them and run this check again.");
        println!();
    }
}
