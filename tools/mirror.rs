// KasSigner Mirror — Live display mirror tool
// Copyright (C) 2025 KasSigner Project (kassigner@proton.me)
//
// Reads the KasSigner serial output, captures SCREENSHOT_BEGIN/END
// framebuffer hex dumps, converts RGB565 to RGB888, and displays
// in a native window using minifb.
//
// Usage:
//   cargo run --release --bin kassigner-mirror -- /dev/cu.usbmodem21201
//
// The serial port path is the same one espflash uses.
// The KasSigner firmware must be built with --features mirror.

use minifb::{Key, Window, WindowOptions, Scale, ScaleMode};
use std::io::{BufRead, BufReader};
use std::time::Duration;

const W: usize = 320;
const H: usize = 240;

/// Convert RGB565 (big-endian as stored in KasSigner shadow buffer) to u32 for minifb
fn rgb565_to_u32(hi: u8, lo: u8) -> u32 {
    let raw = ((hi as u16) << 8) | (lo as u16);
    let r = ((raw >> 11) & 0x1F) as u32;
    let g = ((raw >> 5) & 0x3F) as u32;
    let b = (raw & 0x1F) as u32;
    let r8 = (r << 3) | (r >> 2);
    let g8 = (g << 2) | (g >> 4);
    let b8 = (b << 3) | (b >> 2);
    (r8 << 16) | (g8 << 8) | b8
}

/// Parse a hex row (640 hex chars = 320 pixels) into pixel buffer
fn parse_hex_row(hex_line: &str, row_pixels: &mut [u32; W]) {
    let hex = hex_line.trim().as_bytes();
    let pixel_count = (hex.len() / 4).min(W);
    for i in 0..pixel_count {
        let o = i * 4;
        if o + 4 > hex.len() { break; }
        let hi = hex_byte(hex[o], hex[o + 1]);
        let lo = hex_byte(hex[o + 2], hex[o + 3]);
        row_pixels[i] = rgb565_to_u32(hi, lo);
    }
}

fn hex_byte(high: u8, low: u8) -> u8 {
    (hex_nibble(high) << 4) | hex_nibble(low)
}

fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: kassigner-mirror <serial-port>");
        eprintln!("  e.g: kassigner-mirror /dev/cu.usbmodem21201");
        eprintln!();
        match serialport::available_ports() {
            Ok(ports) => {
                if ports.is_empty() {
                    eprintln!("No serial ports found.");
                } else {
                    eprintln!("Available ports:");
                    for p in &ports { eprintln!("  {}", p.port_name); }
                }
            }
            Err(e) => eprintln!("Error listing ports: {}", e),
        }
        std::process::exit(1);
    }

    let port_name = &args[1];
    let baud: u32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(115_200);

    println!("KasSigner Mirror — {} @ {} baud", port_name, baud);
    println!("Waiting for frames... (tap device screen to trigger redraw)");

    let port = serialport::new(port_name, baud)
        .timeout(Duration::from_millis(50))
        .open()
        .unwrap_or_else(|e| {
            eprintln!("Failed to open {}: {}", port_name, e);
            std::process::exit(1);
        });

    let reader = BufReader::new(port);

    let mut window = Window::new(
        "KasSigner Mirror",
        W, H,
        WindowOptions {
            scale: Scale::X4,
            scale_mode: ScaleMode::AspectRatioStretch,
            resize: true,
            ..WindowOptions::default()
        },
    ).expect("Failed to create window");

    let mut framebuf = vec![0u32; W * H];
    let mut row_pixels = [0u32; W];
    let mut frame_count: u64 = 0;
    let mut capturing = false;
    let mut row_idx: usize = 0;

    window.update_with_buffer(&framebuf, W, H).ok();

    let mut lines = reader.lines();

    while window.is_open() && !window.is_key_down(Key::Escape) {
        // Process lines — non-blocking due to 50ms timeout
        for _ in 0..20 {
            match lines.next() {
                Some(Ok(line)) => {
                    if line.starts_with("SCREENSHOT_BEGIN") {
                        capturing = true;
                        row_idx = 0;
                    } else if line.starts_with("SCREENSHOT_END") {
                        if capturing {
                            capturing = false;
                            frame_count += 1;
                            window.set_title(&format!(
                                "KasSigner Mirror — frame {}", frame_count
                            ));
                            // Update window immediately on frame complete
                            window.update_with_buffer(&framebuf, W, H).ok();
                        }
                    } else if capturing && row_idx < H {
                        parse_hex_row(&line, &mut row_pixels);
                        let offset = row_idx * W;
                        framebuf[offset..offset + W].copy_from_slice(&row_pixels);
                        row_idx += 1;
                        // Partial update every 60 rows for progressive feel
                        if row_idx % 60 == 0 {
                            window.update_with_buffer(&framebuf, W, H).ok();
                        }
                    }
                }
                Some(Err(_)) => break, // timeout
                None => break,
            }
        }

        // Pump window events even when no data
        window.update();
    }

    println!("Mirror closed. {} frames displayed.", frame_count);
}
