// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// The boot-time self-test set, run on the host.
//
// The firmware runs these at every boot through app/boot_test.rs; each
// returns `(passed, total)`. Here they run under `cargo test` with the same
// pass criterion, so the same known-answer tests that gate a device boot
// gate a commit. `--features boot-kats-full` adds the full BIP32 and
// Schnorr sets that the boot default trims for time.
//
// This lives inside the crate (`#[cfg(test)] mod self_tests` in lib.rs)
// rather than under tests/ because several of the entry points are gated
// `#[cfg(any(test, feature = "verbose-boot"))]`, and `cfg(test)` is only
// set for the crate's own test build, not for an integration test's copy
// of the library.

extern crate std;
use std::println;
use std::sync::{Mutex, MutexGuard};
use crate::{entropy, log, wallet, qr};

// The logger and the entropy source are process-wide globals, and the test
// harness runs tests on parallel threads, so every test holds this lock
// while it runs. Without it, `signing_refuses_without_entropy` swapping in a
// dead source would race the signing tests on the other threads.
static SERIAL: Mutex<()> = Mutex::new(());

/// Host stand-in for the hardware entropy source. Not random and not meant
/// to be, but it must differ between calls: `test_hedged_nonce` signs the
/// same message twice and requires different signatures, which is the
/// property the hedging exists for (a fixed stub fails that test, and it
/// should). A call counter mixed into every byte is enough.
fn host_entropy(out: &mut [u8]) -> Result<(), ()> {
    use core::sync::atomic::{AtomicU32, Ordering};
    static CALLS: AtomicU32 = AtomicU32::new(0);
    let n = CALLS.fetch_add(1, Ordering::Relaxed);
    for (i, b) in out.iter_mut().enumerate() {
        let x = (i as u32).wrapping_mul(0x9e37_79b9) ^ n.wrapping_mul(0x85eb_ca6b);
        *b = (x ^ (x >> 13) ^ (x >> 24)) as u8;
    }
    Ok(())
}

fn host_log(args: core::fmt::Arguments<'_>) {
    println!("{}", args);
}

fn setup() -> MutexGuard<'static, ()> {
    let g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    entropy::set_source(host_entropy);
    log::set_logger(host_log);
    g
}

fn all<T: Copy + TryInto<u64>>(name: &str, r: (T, T)) {
    let passed: u64 = r.0.try_into().ok().expect("count fits u64");
    let total: u64 = r.1.try_into().ok().expect("count fits u64");
    assert!(total > 0, "{name}: no tests ran");
    assert_eq!(passed, total, "{name}: {passed}/{total}");
}

#[test] fn address()   { let _g = setup(); all("address",  wallet::address::run_address_tests()); }
#[test] fn bip32()     { let _g = setup(); all("bip32",    wallet::bip32::run_bip32_tests()); }
#[test] fn bip39()     { let _g = setup(); all("bip39",    wallet::bip39::run_bip39_tests()); }
#[test] fn bip85()     { let _g = setup(); assert!(wallet::bip85::test_bip85_12word_index0()); }
#[test] fn pskt()      { let _g = setup(); all("pskt",     wallet::pskt::run_pskt_tests()); }
#[test] fn schnorr()   { let _g = setup(); all("schnorr",  wallet::schnorr::run_schnorr_tests()); }
#[test] fn sighash()   { let _g = setup(); all("sighash",  wallet::sighash::run_sighash_tests()); }
#[test] fn sighash_vectors() { let _g = setup(); all("sighash vectors", wallet::sighash::run_sighash_vectors()); }
#[test] fn storage()   { let _g = setup(); all("storage",  wallet::storage::run_storage_tests()); }
#[test] fn multisig()  { let _g = setup(); all("multisig", wallet::transaction::run_multisig_tests()); }
#[test] fn xpub()      { let _g = setup(); all("xpub",     wallet::xpub::run_xpub_tests()); }
#[test] fn qr_payload() { let _g = setup(); all("qr payload", qr::payload::run_tests()); }

/// With a failing entropy source, signing must refuse. This is the H-05
/// fail-closed property and the one thing the injection could have quietly
/// broken. The unregistered (null) case is the same branch of
/// `entropy::fill` and cannot be reproduced once any test has registered a
/// source, so the failing source stands in for it.
#[test]
fn signing_refuses_without_entropy() {
    let _g = setup();
    fn dead(_: &mut [u8]) -> Result<(), ()> { Err(()) }
    entropy::set_source(dead);
    let mut buf = [0u8; 32];
    assert!(entropy::fill(&mut buf).is_err());
    let key = [7u8; 32];
    let msg = [1u8; 32];
    assert!(matches!(
        wallet::schnorr::schnorr_sign(&key, &msg),
        Err(wallet::schnorr::SchnorrError::EntropyUnavailable)
    ));
    entropy::set_source(host_entropy);
}
