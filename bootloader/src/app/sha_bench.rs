// ═══════════════════════════════════════════════════════════════════════
// sha_bench.rs: is the ESP32-S3 SHA accelerator worth wiring into PBKDF2?
// ═══════════════════════════════════════════════════════════════════════
//
// Measurement only. This module is compiled ONLY under the `sha-bench`
// feature and is reachable from nowhere else: it derives no keys, signs
// nothing, and no production code path calls into it. It exists to turn
// an argument into a number.
//
// Background, all measured on device:
//
//   The 100k-iteration PBKDF2 behind SD backup encryption cost 35,401
//   cycles/iteration. Caching the HMAC pad midstates (the key is constant
//   across iterations, so both pad blocks can be hashed once and resumed
//   from) halved the SHA-256 compressions per iteration from four to two
//   and brought it to 22,097 cycles/iteration, 14.75s -> 9.21s.
//
//   22,097 cycles for two compressions is ~11,000 per compression, i.e.
//   ~172 cycles per SHA-256 round where the algorithm needs 15-20. That
//   gap is not the algorithm, it is instruction fetch: this firmware
//   builds at opt-level "z" and executes from flash through an icache,
//   and raising the opt-level made things 3x WORSE (SHA-512's 80 rounds
//   fully unroll and blow the cache). A hardware peripheral sidesteps
//   instruction fetch entirely, which is why it is worth measuring.
//
// What this measures: one PBKDF2 inner step, HMAC-SHA256(key, 32 bytes),
// done both ways from cached midstates, which is exactly the shape the
// real loop runs 100,000 times.
//
// The decision rule, fixed BEFORE seeing the number so it cannot be
// rationalised afterwards:
//
//   < 3x   -> drop it. A funds-guarding path does not take on a dual
//             implementation, a peripheral holder and a fallback for a
//             modest win.
//   >= 5x  -> worth building, as a hardware path ALONGSIDE the software
//             one with a boot equivalence test and software fallback.
//   3-5x   -> judgement call.
//
// Correctness is checked here too: if the two paths disagree on a single
// byte the ratio is meaningless, and that disagreement would be the real
// finding.

use esp_hal::peripherals::SHA;
use esp_hal::sha::{Context, Sha, Sha256, ShaDigest};
use esp_hal::xtensa_lx::timer::get_cycle_count;
use sha2::{Digest, Sha256 as SwSha256};

use crate::log;

/// Iterations per side. Large enough to swamp timer granularity and
/// one-off cache warming, small enough to be invisible at boot.
const ROUNDS: u32 = 500;

const BLOCK: usize = 64;
const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5C;

/// Spin until a non-blocking SHA call completes.
///
/// The driver is `nb`, so every update/finish/save can report WouldBlock
/// while the peripheral is busy. That polling is part of the real cost
/// and is deliberately inside the timed region.
/// The error payload is `Infallible`, so the only reachable Err is
/// WouldBlock; matching on `Err(_)` avoids naming `nb`, which is only a
/// transitive dependency here.
macro_rules! sha_block {
    ($e:expr) => {
        loop {
            match $e {
                Ok(v) => break v,
                Err(_) => {}
            }
        }
    };
}

/// Build the two pad blocks for an HMAC key, as PBKDF2 does once.
fn pads(key: &[u8]) -> ([u8; BLOCK], [u8; BLOCK]) {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let h = SwSha256::digest(key);
        k[..32].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ip = [0u8; BLOCK];
    let mut op = [0u8; BLOCK];
    for i in 0..BLOCK {
        ip[i] = k[i] ^ IPAD;
        op[i] = k[i] ^ OPAD;
    }
    (ip, op)
}

/// Run the benchmark and log the result. Consumes the SHA peripheral.
pub fn run(sha_periph: SHA<'static>) {
    let key = b"benchmark-passphrase";
    let (ipad, opad) = pads(key);
    let seed = [0xA5u8; 32];

    log!();
    log!("[sha-bench] {} rounds of HMAC-SHA256(32B) from cached midstates", ROUNDS);

    // ── Software: sha2 crate, midstates captured by clone() ───────────
    let mut sw_inner = SwSha256::new();
    sw_inner.update(ipad);
    let mut sw_outer = SwSha256::new();
    sw_outer.update(opad);

    let t0 = get_cycle_count();
    let sw_out = {
        let mut u = seed;
        for _ in 0..ROUNDS {
            let mut i = sw_inner.clone();
            i.update(u);
            let ih = i.finalize();
            let mut o = sw_outer.clone();
            o.update(ih);
            let oh = o.finalize();
            u.copy_from_slice(&oh);
        }
        u
    };
    let sw_cycles = get_cycle_count().wrapping_sub(t0);

    // ── Hardware: esp-hal SHA, midstates via save()/restore() ─────────
    let mut sha = Sha::new(sha_periph);

    // Prime both pad states once, outside the timed region, mirroring
    // what the real PBKDF2 would do once per derivation.
    // `update` returns the bytes it did NOT consume, so it is driven in a
    // loop here as well as in the timed section. Feeding exactly one
    // block should complete in a single call, but discarding the
    // remainder would silently prime the wrong state and only show up as
    // a mismatch at the end.
    let mut ictx: Context<Sha256> = Context::new();
    {
        let mut d = sha.start::<Sha256>();
        let mut rest: &[u8] = &ipad;
        while !rest.is_empty() {
            rest = sha_block!(d.update(rest));
        }
        sha_block!(d.save(&mut ictx));
    }
    let mut octx: Context<Sha256> = Context::new();
    {
        let mut d = sha.start::<Sha256>();
        let mut rest: &[u8] = &opad;
        while !rest.is_empty() {
            rest = sha_block!(d.update(rest));
        }
        sha_block!(d.save(&mut octx));
    }

    let t1 = get_cycle_count();
    let hw_out = {
        let mut u = seed;
        for _ in 0..ROUNDS {
            // The primed contexts are reused directly, not copied.
            //
            // `restore` takes `&mut Context` but does not modify it: it
            // reads `buffer`, reads `saved_digest`, and clones `state`.
            // The `&mut` comes only from `volatile_write_regset`, whose
            // receiver is `&mut self` yet which touches nothing on self,
            // it just writes the register block from `src`. So the same
            // primed context is valid for every round, and the per-round
            // cost stays a restore rather than a restore plus a copy.
            //
            // (`Context` does derive Clone, but the derive generates an
            // `A: Clone` bound and the `Sha256` marker type is not Clone,
            // so cloning would not compile anyway.)
            let mut ih = [0u8; 32];
            {
                let mut d = ShaDigest::restore(&mut sha, &mut ictx);
                let mut rest: &[u8] = &u;
                while !rest.is_empty() {
                    rest = sha_block!(d.update(rest));
                }
                sha_block!(d.finish(&mut ih));
            }
            {
                let mut d = ShaDigest::restore(&mut sha, &mut octx);
                let mut rest: &[u8] = &ih;
                while !rest.is_empty() {
                    rest = sha_block!(d.update(rest));
                }
                sha_block!(d.finish(&mut u));
            }
        }
        u
    };
    let hw_cycles = get_cycle_count().wrapping_sub(t1);

    // ── Report ────────────────────────────────────────────────────────
    let sw_per = sw_cycles / ROUNDS;
    let hw_per = hw_cycles / ROUNDS;

    log!("[sha-bench] software: {} cyc/round ({} ms total)",
        sw_per, sw_cycles / 240_000);
    log!("[sha-bench] hardware: {} cyc/round ({} ms total)",
        hw_per, hw_cycles / 240_000);

    if hw_per == 0 {
        log!("[sha-bench] hardware time below timer resolution, raise ROUNDS");
    } else {
        // Integer ratio to two decimals, no float formatting in no_std.
        let ratio_x100 = (sw_per as u64 * 100) / hw_per as u64;
        log!("[sha-bench] speedup: {}.{:02}x",
            ratio_x100 / 100, ratio_x100 % 100);
    }

    if sw_out == hw_out {
        log!("[sha-bench] outputs MATCH ({} rounds chained)", ROUNDS);
    } else {
        // This, not the timing, would be the finding.
        log!("[sha-bench] outputs DIFFER - hardware path is NOT equivalent");
        log!("[sha-bench]   sw[0..8] = {:02x?}", &sw_out[..8]);
        log!("[sha-bench]   hw[0..8] = {:02x?}", &hw_out[..8]);
    }

    // Projection onto the real workload, stated as arithmetic rather
    // than as a promise: the measured 22,097 cyc/iteration is very
    // nearly all SHA, so the SD derivation should scale with this ratio.
    if hw_per > 0 {
        let projected_ms = (hw_per as u64 * 100_000) / 240_000;
        log!("[sha-bench] projected 100k-iter PBKDF2: ~{}ms (measured now: 9207ms)",
            projected_ms);
    }
    log!();
}
