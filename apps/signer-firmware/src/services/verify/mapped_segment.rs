use super::{
    DRAM_FLASH_BASE,
    Digest,
    embedded_firmware_size,
    FirmwareInfo,
    IRAM_FLASH_BASE,
    Ordering,
    Sha256,
    VerificationResult,
    compiler_fence,
    constant_time,
    flow,
};
// Mapped executable-segment hashing and comparison.

impl FirmwareInfo {
pub(super) fn do_verify_mapped_code(
        &self,
        code_start_iram: u32,
        max_size: usize,
    ) -> VerificationResult {
        flow::advance(flow::Stage::MapStart);

        // ── Convert IRAM address → DRAM ─────────────────────
        //
        // code_start_iram is on instruction bus (0x4201_0020)
        // We need the equivalent address on data bus (0x3C01_0020)
        let code_start = if (IRAM_FLASH_BASE..(IRAM_FLASH_BASE + 0x0200_0000)).contains(&code_start_iram)
        {
            code_start_iram - IRAM_FLASH_BASE + DRAM_FLASH_BASE
        } else if (DRAM_FLASH_BASE..(DRAM_FLASH_BASE + 0x0200_0000)).contains(&code_start_iram)
        {
            // Already a DRAM address, use directly
            code_start_iram
        } else {
            log!("   ERROR: 0x{:08X} is not a valid flash address!", code_start_iram);
            return VerificationResult::ReadError;
        };

        // ── Determine segment size ───────────────────────
        //
        // Use FIRMWARE_SIZE from firmware_hash.rs, which gen_hash extracted
        // from the segment header in the ESP-IDF .bin. This ensures we
        // hash exactly the same bytes that gen_hash hashed.
        //
        // If FIRMWARE_SIZE is not set (= 0 or > max_size),
        // fall back to scanning for 0xFF.

        let firmware_size = embedded_firmware_size();
        let code_size: usize = if firmware_size > 0 && firmware_size <= max_size {
            log!("   Segment size: {} bytes ({} KB)", firmware_size, firmware_size / 1024);
            firmware_size
        } else {
            // Fallback: scan for end of code
            log!("   FIRMWARE_SIZE not available, scanning...");
            let mut size: usize = 0;
            let mut consecutive_ff: u32 = 0;
            const FF_THRESHOLD: u32 = 16;
            let scan_limit = core::cmp::min(max_size, 0x0010_0000);

            let mut offset: usize = 0;
            while offset < scan_limit {
                let addr = code_start as usize + offset;
                let word = unsafe {
                    core::ptr::read_volatile(addr as *const u32)
                };

                if word == 0xFFFF_FFFF {
                    consecutive_ff += 1;
                    if consecutive_ff >= FF_THRESHOLD {
                        size = offset - ((FF_THRESHOLD as usize - 1) * 4);
                        break;
                    }
                } else {
                    consecutive_ff = 0;
                    size = offset + 4;
                }
                offset += 4;
            }

            if size == 0 {
                log!("   ERROR: Empty or unmapped segment");
                return VerificationResult::ReadError;
            }
            // Align to 4 bytes
            size = (size + 3) & !3;
            log!("   Scanned segment: {} bytes ({} KB)", size, size / 1024);
            size
        };

        // ── Sanity check ────────────────────────────────────────
        let data: &[u8] = unsafe {
            core::slice::from_raw_parts(code_start as *const u8, code_size)
        };

        // Verify not all zeros
        let mut all_00 = true;
        let check_len = core::cmp::min(256, data.len());
        for i in 0..check_len {
            let val = unsafe { core::ptr::read_volatile(&data[i] as *const u8) };
            if val != 0x00 { all_00 = false; break; }
        }
        if all_00 {
            log!("   Segment reads as zeros (DRAM mapping unavailable)");
            return VerificationResult::ReadError;
        }
        flow::advance(flow::Stage::SegmentReady);

        // ── Compute SHA256 ─────────────────────────────────────
        let mut hasher = Sha256::new();
        const CHUNK_SIZE: usize = 4096;
        let mut off = 0;
        while off < code_size {
            let end = core::cmp::min(off + CHUNK_SIZE, code_size);
            hasher.update(&data[off..end]);
            off = end;
        }

        let computed_hash: [u8; 32] = hasher.finalize().into();
        flow::advance(flow::Stage::HashComplete);

        log!("   Computed hash: {}...", self.hash_to_hex_short(&computed_hash).as_str());
        log!("   Expected hash: {}...", self.hash_to_hex_short(&self.expected_hash).as_str());

        // ── Compare in constant time ────────────────────────
        let hashes_match = constant_time::eq(&computed_hash, &self.expected_hash);
        compiler_fence(Ordering::SeqCst);
        flow::advance(flow::Stage::CompareComplete);

        if hashes_match {
            VerificationResult::Valid
        } else {
            log!("   FAIL: Hash does NOT match!");
            log!("   Embedded build hash does not match the mapped executable segment");
            VerificationResult::InvalidHash
        }
    }
}
