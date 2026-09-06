//! ESP image and ELF segment discovery.

use super::output::{hash_code_segment, SigningIdentity};

pub const IRAM_FLASH_BASE: u32 = 0x4200_0000;
pub const IRAM_FLASH_END: u32 = 0x4400_0000;
pub const ESP_IMAGE_MAGIC: u8 = 0xE9;
pub const ESP_IMAGE_HEADER_SIZE: usize = 24;
pub const SEGMENT_HEADER_SIZE: usize = 8;

// ─── Parser de ESP-IDF image format ───────────────────────────────────

pub fn process_esp_image(data: &[u8], signing_key: Option<&str>, signing_identity: SigningIdentity) {
    println!("  Format: ESP-IDF image");

    let segment_count = data[1] as usize;
    println!("  Segments: {}", segment_count);

    // Entry point
    let entry = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    println!("  Entry point: 0x{:08X}", entry);

    // Iterate over segments
    let mut offset = ESP_IMAGE_HEADER_SIZE;
    let mut code_segment: Option<(usize, usize, u32)> = None; // (data_offset, size, load_addr)

    for i in 0..segment_count {
        if offset + SEGMENT_HEADER_SIZE > data.len() {
            eprintln!("  Segment {} truncated (offset {} > len {})", i, offset, data.len());
            break;
        }

        let load_addr = u32::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        ]);
        let seg_size = u32::from_le_bytes([
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]) as usize;

        let data_offset = offset + SEGMENT_HEADER_SIZE;

        println!("  Segment {}: load=0x{:08X}  size=0x{:05X} ({:6} bytes) {}",
            i, load_addr, seg_size, seg_size,
            if load_addr >= IRAM_FLASH_BASE && load_addr < IRAM_FLASH_END {
                " ← CODE (IRAM)"
            } else {
                ""
            }
        );

        // Find the code segment (mapped on instruction bus)
        if load_addr >= IRAM_FLASH_BASE && load_addr < IRAM_FLASH_END {
            if code_segment.is_some() {
                eprintln!("  ERROR: Multiple flash-mapped code segments are ambiguous");
                std::process::exit(1);
            }
            code_segment = Some((data_offset, seg_size, load_addr));
        }

        offset = data_offset + seg_size;
    }

    // ── Hash the code segment ───────────────────────────
    match code_segment {
        Some((data_offset, seg_size, load_addr)) => {
            hash_code_segment(data, data_offset, seg_size, load_addr, signing_key, signing_identity);
        }
        None => {
            eprintln!("  Code segment not found (IRAM 0x4200_0000+)!");
            eprintln!("  Available segments do not include flash-mapped code.");
            std::process::exit(1);
        }
    }
}

// ─── Parser de ELF (fallback) ─────────────────────────────────────────
//
// Xtensa ESP32-S3 binaries are ELF32 little-endian.
// Find the section with virtual address in the IRAM flash range.

pub fn process_elf(data: &[u8], signing_key: Option<&str>, signing_identity: SigningIdentity) {
    println!("  Format: ELF");

    // ELF32 header parsing (minimal)
    if data.len() < 52 {
        eprintln!("  ELF too small");
        std::process::exit(1);
    }

    // e_phoff: offset de la program header table
    let ph_offset = u32::from_le_bytes([data[28], data[29], data[30], data[31]]) as usize;
    // e_phentsize: size of each program header entry
    let ph_entry_size = u16::from_le_bytes([data[42], data[43]]) as usize;
    // e_phnum: number of program header entries
    let ph_num = u16::from_le_bytes([data[44], data[45]]) as usize;

    println!("  Program headers: {} entries @ offset 0x{:X}", ph_num, ph_offset);

    let mut code_segment: Option<(usize, usize, u32)> = None;

    for i in 0..ph_num {
        let off = ph_offset + i * ph_entry_size;
        if off + 32 > data.len() {
            break;
        }

        let p_type = u32::from_le_bytes([data[off], data[off+1], data[off+2], data[off+3]]);
        let p_offset = u32::from_le_bytes([data[off+4], data[off+5], data[off+6], data[off+7]]) as usize;
        let p_vaddr = u32::from_le_bytes([data[off+8], data[off+9], data[off+10], data[off+11]]);
        let p_filesz = u32::from_le_bytes([data[off+16], data[off+17], data[off+18], data[off+19]]) as usize;

        // PT_LOAD = 1
        if p_type == 1 {
            println!("  LOAD {}: vaddr=0x{:08X}  filesz=0x{:05X} ({:6} bytes) {}",
                i, p_vaddr, p_filesz, p_filesz,
                if p_vaddr >= IRAM_FLASH_BASE && p_vaddr < IRAM_FLASH_END {
                    " ← CODE"
                } else {
                    ""
                }
            );

            if p_vaddr >= IRAM_FLASH_BASE && p_vaddr < IRAM_FLASH_END {
                if code_segment.is_some() {
                    eprintln!("  ERROR: Multiple flash-mapped ELF LOAD segments are ambiguous");
                    std::process::exit(1);
                }
                code_segment = Some((p_offset, p_filesz, p_vaddr));
            }
        }
    }

    match code_segment {
        Some((data_offset, seg_size, load_addr)) => {
            hash_code_segment(data, data_offset, seg_size, load_addr, signing_key, signing_identity);
        }
        None => {
            eprintln!("  No LOAD segment found with vaddr in IRAM flash range.");
            eprintln!("  Try generating a .bin first:");
            eprintln!("    espflash save-image --chip esp32s3 <ELF> firmware.bin");
            std::process::exit(1);
        }
    }
}
