// KasSigner — Air-gapped offline signing device for Kaspa
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

// app/stack_probe.rs — paint the stack, then measure how deep it was used.
//
// Why this exists: every stack-guard panic so far has been diagnosed by
// inference from register dumps. This replaces the inference with a number.
//
// How the stack is laid out, from esp-hal 1.0.0 `ld/sections/stack.x`:
//
//     .stack (NOLOAD) : ALIGN(4) {
//       _stack_end        = ABSOLUTE(.);                     // LOWEST address
//       __stack_chk_guard = _stack_end + STACK_GUARD_OFFSET; // default +60
//       . = ORIGIN(RWDATA) + LENGTH(RWDATA);
//       _stack_start      = ABSOLUTE(.);                     // HIGHEST address
//     }
//
// Two consequences worth stating plainly, because both have bitten us:
//
// 1. The stack grows DOWN from `_stack_start` toward `_stack_end`.
//
// 2. `.stack` is the last segment in RWDATA and `_stack_end` is simply
//    "wherever RWDATA has got to". So `_stack_end` is not a constant. Every
//    byte of static `.data` or `.bss` the firmware adds raises the floor,
//    raises the guard with it, and takes that byte away from the stack. A
//    build can start tripping the guard at an unchanged call depth purely
//    because static memory grew underneath it. That is why this module logs
//    the absolute addresses: comparing `_stack_end` between two builds
//    measures static memory growth directly, with no painting involved.
//
// 3. The default guard offset is 60 bytes. The guard is not a safety margin,
//    it is a tripwire 60 bytes above real corruption.
//
// Usage: call `paint()` once, early, then `report(label)` at points of
// interest. The high-water mark is cumulative since `paint()`, so a report
// after any operation includes everything that ran before it.

use crate::log;

/// Fill pattern. Chosen to be an unlikely value for real stack data: not
/// zero, not a plausible pointer into DRAM (0x3Fxx_xxxx) or IRAM
/// (0x4Cxx_xxxx), and not a small integer.
const PAINT: u32 = 0xC0DE_FEED;

/// Bytes left unpainted immediately below the caller's frame, so painting
/// cannot touch the frame doing the painting.
const PAINT_MARGIN: usize = 256;

extern "C" {
    static mut _stack_end: u32;
    static mut _stack_start: u32;
    static mut __stack_chk_guard: u32;
}

/// Guard value observed at `paint()` time.
///
/// Read from the guard rather than taken from `ESP_HAL_CONFIG_STACK_GUARD_VALUE`,
/// so this module needs no dependency on esp-config and stays correct if the
/// configured value ever changes.
static GUARD_SNAPSHOT: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

/// Lowest address the stack may occupy.
#[inline(always)]
pub fn stack_end() -> usize {
    core::ptr::addr_of!(_stack_end) as usize
}

/// Highest address the stack occupies. The stack pointer starts here.
#[inline(always)]
pub fn stack_start() -> usize {
    core::ptr::addr_of!(_stack_start) as usize
}

/// Address of the guard word. Anything that writes at or below this has
/// overflowed.
#[inline(always)]
pub fn guard_addr() -> usize {
    core::ptr::addr_of!(__stack_chk_guard) as usize
}

/// Total bytes between the guard and the top of the stack.
#[inline(always)]
pub fn usable_total() -> usize {
    stack_start().saturating_sub(guard_addr() + 4)
}

/// Approximate current stack pointer: the address of a local in this frame.
///
/// Deliberately not inline assembly. The address of a stack local is within a
/// few words of the real SP, which is all this needs, and it keeps the module
/// free of target-specific asm.
#[inline(never)]
fn approx_sp() -> usize {
    let marker: u32 = 0;
    core::ptr::addr_of!(marker) as usize
}

/// Paint the unused stack.
///
/// Call once, as early as possible and from as shallow a frame as possible:
/// everything below the caller's frame at the moment of the call is what gets
/// painted, so calling this from deep in the call tree leaves the deep region
/// unpainted and under-reports.
///
/// Does no logging. `log!` descends into the region being painted, which would
/// immediately dirty it and inflate the first measurement.
///
/// Returns the byte range painted, low then high, for the caller to log.
#[inline(never)]
pub fn paint() -> (usize, usize) {
    GUARD_SNAPSHOT.store(
        unsafe { core::ptr::read_volatile(guard_addr() as *const u32) },
        core::sync::atomic::Ordering::Relaxed,
    );
    let low = guard_addr() + 4;
    let high = approx_sp().saturating_sub(PAINT_MARGIN);
    if high <= low {
        return (0, 0);
    }
    let mut addr = low & !3;
    while addr < high {
        unsafe {
            core::ptr::write_volatile(addr as *mut u32, PAINT);
        }
        addr += 4;
    }
    (low, high)
}

/// Deepest address the stack has reached since `paint()`.
///
/// Scans up from the guard for the first word that is no longer the paint
/// pattern. Returns `None` if the paint is entirely intact, which means either
/// `paint()` was never called or nothing has gone that deep.
pub fn deepest() -> Option<usize> {
    let low = (guard_addr() + 4) & !3;
    let high = stack_start();
    let mut addr = low;
    while addr < high {
        let v = unsafe { core::ptr::read_volatile(addr as *const u32) };
        if v != PAINT {
            return Some(addr);
        }
        addr += 4;
    }
    None
}

/// True if the guard word still holds the value esp-hal wrote.
///
/// Cheap enough to call at chosen points. Catches an overflow that has already
/// happened but has not yet triggered the watchpoint, and works even on builds
/// where watchpoint monitoring is off.
pub fn guard_intact() -> bool {
    let expected = GUARD_SNAPSHOT.load(core::sync::atomic::Ordering::Relaxed);
    if expected == 0 {
        // paint() has not run, so there is nothing to compare against.
        return true;
    }
    let actual = unsafe { core::ptr::read_volatile(guard_addr() as *const u32) };
    actual == expected
}

/// Zero the unused stack, from the guard up to just below this frame.
///
/// Closes the H-01 residual: both wipe paths clear the two heap structures they
/// know about, `AppData` and the separately allocated `chain_cache`, and neither
/// touches the stack. So after a panic, whatever was live at the moment of the
/// fault stays live: PBKDF2 intermediate state, the 64-byte BIP39 seed inside
/// `ensure_session_account_key`, Schnorr scalars, `SeedSlot` temporaries. The
/// device has halted, so it stays until power is removed.
///
/// Why this is safe where `hw::lockdown::panic_wipe` is not. That function zeroes
/// a fixed `0x3FC8_8000..0x3FCF_0000` twice, which contains the live stack, every
/// static, and, through the ESP32-S3 dual-bus aliasing, memory the instruction
/// bus sees as IRAM. It erases its own return address when it reaches the stack
/// and the instructions it is executing when it reaches the alias, so it faults
/// partway through inside a panic handler. This function writes only between the
/// guard and its own frame: that span is stack by definition, cannot reach the
/// alias, and cannot contain anything live.
///
/// INTERRUPTS MUST BE OFF. An ISR pushes its frame below the current stack
/// pointer, which is precisely the region being zeroed. Safe from the panic
/// handler, where interrupts are already down. Any other caller needs a critical
/// section.
///
/// Returns the number of bytes cleared, for the caller to log or ignore.
#[inline(never)]
pub fn wipe_below_sp() -> usize {
    let low = (guard_addr() + 4) & !3;
    let high = approx_sp().saturating_sub(PAINT_MARGIN);
    if high <= low {
        return 0;
    }
    let mut addr = low;
    while addr < high {
        unsafe {
            core::ptr::write_volatile(addr as *mut u32, 0);
        }
        addr += 4;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    high - low
}

// ─── Sentinel scan (feature `sentinel-scan`) ─────────────────────────
//
// Proves a wipe reached a real secret, which a byte count cannot.
//
// `wipe_below_sp` returning 92,628 says the loop ran over the intended range.
// It does not say any particular secret was inside that range. In particular
// the wipe clears from the guard up to `wipe_secrets`'s own frame, so anything
// higher is untouched, including `main`'s 18 KB frame, which is live for the
// whole life of the device. A secret spilled into `main`'s frame would survive
// every wipe and the byte count would still look perfect.
//
// The sentinel is the account private key of the M5Stack boot signing test.
// That test loads a mnemonic fixed in `main.rs::run_signing_pipeline_test`
// ("girl mad pet galaxy egg matter matrix prison refuse sense ordinary nose",
// empty passphrase), so its account key at m/44'/111111'/0' is a constant that
// can be computed on the host. It is a real derived private key that really
// sits on the stack during the test.
//
// Verified against an independent PBKDF2 and BIP32 implementation. The same
// derivation yields BIP39 seed 242abe4ded7903cd..., which matches the
// BIP85-TEST line printed at boot for the same words.
//
// NEVER ship this. It compiles a private key into the binary as a search
// pattern. It is behind its own feature for that reason and no production path
// references it.
//
// Only usable for the duress and idle wipes: a panic halts the device, so
// nothing can run afterwards to scan, and JTAG is closed by eFuse.

/// Account private key of the boot signing test's fixed mnemonic.
#[cfg(feature = "sentinel-scan")]
const SENTINEL: [u8; 32] = [
    0x66, 0x7c, 0x26, 0xc1, 0x4c, 0xd3, 0x77, 0xa9,
    0xde, 0x4f, 0x89, 0x93, 0xe3, 0x5a, 0xb2, 0x42,
    0x78, 0xff, 0x2c, 0x03, 0xef, 0x30, 0x43, 0xd5,
    0x3e, 0x38, 0x80, 0xcd, 0x1f, 0x99, 0x4c, 0x94,
];

/// Scan the whole stack region for the sentinel and log every hit.
///
/// Scans `_stack_end` to `_stack_start`, deliberately wider than the wipe
/// range: a hit ABOVE the wipe ceiling is the interesting result, because it
/// means a secret is living somewhere no wipe reaches.
///
/// Call once after the boot signing test, where hits are expected and prove the
/// scan works, and once after a wipe, where none should remain. A second scan
/// alone proves nothing without the first.
#[cfg(feature = "sentinel-scan")]
pub fn scan_sentinel(label: &str) {
    let low = stack_end() & !3;
    let high = stack_start().saturating_sub(SENTINEL.len());
    let wipe_ceiling = approx_sp();
    let mut hits = 0u32;
    let mut addr = low;
    while addr < high {
        let mut matched = true;
        for (i, &b) in SENTINEL.iter().enumerate() {
            let got = unsafe { core::ptr::read_volatile((addr + i) as *const u8) };
            if got != b {
                matched = false;
                break;
            }
        }
        if matched {
            hits += 1;
            log!("   [sentinel] {}: HIT at 0x{:08X}{}",
                label, addr,
                if addr >= wipe_ceiling { "  ABOVE WIPE CEILING" } else { "" });
        }
        addr += 1;
    }
    log!("   [sentinel] {}: {} hit(s), scanned 0x{:08X}..0x{:08X}",
        label, hits, low, high);
}

/// Log the layout. Call once after `paint()`.
///
/// The absolute addresses are the point. Comparing `_stack_end` between two
/// builds tells you how much static memory one added and therefore how much
/// stack it took away, which no amount of staring at a register dump will.
pub fn report_layout(painted_low: usize, painted_high: usize) {
    log!("   [stack] _stack_end   = 0x{:08X}  (floor, rises with static RWDATA)", stack_end());
    log!("   [stack] guard        = 0x{:08X}  (+{} from floor)", guard_addr(), guard_addr() - stack_end());
    log!("   [stack] _stack_start = 0x{:08X}  (top)", stack_start());
    log!("   [stack] usable       = {} bytes", usable_total());
    if painted_high > painted_low {
        log!("   [stack] painted      = 0x{:08X}..0x{:08X} ({} bytes)",
            painted_low, painted_high, painted_high - painted_low);
    } else {
        log!("   [stack] painted      = NOTHING (called too deep?)");
    }
}

/// Log both the live stack pointer and the high-water mark.
///
/// The two answer different questions and conflating them has already cost a
/// day of guessing:
///
/// `now` is the stack pointer at this call, so `head` is the headroom the
/// CURRENT call chain has left before the guard. That is the number that
/// decides whether the next function fits.
///
/// `deepest` is the lowest address reached since `paint()`, cumulative across
/// everything that has run. If an earlier deep chain (the boot self-tests, or
/// `test_signing_pipeline` with its ~16 KB of Schnorr on M5Stack) went further
/// than the current one, `deepest` reports that historical low and says
/// nothing about the headroom here.
///
/// When `now` and `deepest` are close, the current chain IS the deepest and
/// the two numbers agree. When they diverge, trust `head`.
pub fn report(label: &str) {
    let now = approx_sp();
    let floor = guard_addr() + 4;
    let head = now.saturating_sub(floor);
    let here = stack_start().saturating_sub(now);
    match deepest() {
        Some(addr) => {
            let used = stack_start().saturating_sub(addr);
            let free = addr.saturating_sub(floor);
            log!("   [stack] {}: now 0x{:08X} depth {} B head {} B | deepest 0x{:08X} used {} B free {} B | guard {}",
                label, now, here, head, addr, used, free,
                if guard_intact() { "ok" } else { "CLOBBERED" });
        }
        None => {
            log!("   [stack] {}: now 0x{:08X} depth {} B head {} B | paint intact | guard {}",
                label, now, here, head,
                if guard_intact() { "ok" } else { "CLOBBERED" });
        }
    }
}
