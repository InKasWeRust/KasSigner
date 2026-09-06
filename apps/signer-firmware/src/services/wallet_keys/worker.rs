//! CoreS3 second-core finalizer for expensive public derivation work.
//!
//! Core0 owns UI/peripherals and advances BIP39 PBKDF2 cooperatively in short
//! event-loop chunks. Bounded BIP32/secp256k1 public derivation runs on Core1
//! with a dedicated static stack so ordinary GUI actions cannot starve the
//! production watchdog. Cross-core secret material is zeroized on every exit.

use signer_firmware_core::runtime::worker::{CrossCoreMailbox, ReserveError};

use crate::wallet::seed_manager::SeedSlot;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WorkerResultKind {
    AccountKpub,
    MultisigKpub,
    AddressCache,
}

enum KpubSource {
    AccountKpubSeed([u8; 64]),
    MultisigKpubSeed([u8; 64]),
    AddressSeed([u8; 64]),
    AccountKpub {
        raw: [u8; 65],
        parent_fingerprint: [u8; 4],
    },
    AddressAccount([u8; 65]),
    AddressRawKey([u8; 32]),
}

struct KpubJob {
    generation: u8,
    source: KpubSource,
}

impl Drop for KpubJob {
    fn drop(&mut self) {
        match &mut self.source {
            KpubSource::AccountKpubSeed(seed)
            | KpubSource::MultisigKpubSeed(seed)
            | KpubSource::AddressSeed(seed) => shared_signer::bytes::zeroize_bytes(seed),
            KpubSource::AccountKpub { raw, parent_fingerprint } => {
                shared_signer::bytes::zeroize_bytes(raw);
                shared_signer::bytes::zeroize_bytes(parent_fingerprint);
            }
            KpubSource::AddressAccount(raw) => shared_signer::bytes::zeroize_bytes(raw),
            KpubSource::AddressRawKey(raw) => shared_signer::bytes::zeroize_bytes(raw),
        }
    }
}

pub(crate) struct KpubWorkerResult {
    generation: u8,
    kind: WorkerResultKind,
    encoded: [u8; offline_signer::derivation::xpub::KPUB_MAX_LEN],
    length: usize,
    account_raw: [u8; 65],
    receive_cache: [[u8; 32]; 20],
    change_cache: [[u8; 32]; 5],
    error: Option<&'static str>,
}

impl KpubWorkerResult {
    pub(crate) fn generation(&self) -> u8 { self.generation }
    pub(crate) fn kind(&self) -> WorkerResultKind { self.kind }
    pub(crate) fn error(&self) -> Option<&'static str> { self.error }
    pub(crate) fn encoded_mut(&mut self) -> &mut [u8; offline_signer::derivation::xpub::KPUB_MAX_LEN] {
        &mut self.encoded
    }
    pub(crate) fn length(&self) -> usize { self.length }
    pub(crate) fn take_address_cache(
        &mut self,
        account_raw: &mut [u8; 65],
        receive_cache: &mut [[u8; 32]; 20],
        change_cache: &mut [[u8; 32]; 5],
    ) -> bool {
        if self.kind != WorkerResultKind::AddressCache || self.error.is_some() { return false; }
        account_raw.copy_from_slice(&self.account_raw);
        *receive_cache = self.receive_cache;
        *change_cache = self.change_cache;
        true
    }
}

impl Drop for KpubWorkerResult {
    fn drop(&mut self) {
        shared_signer::bytes::zeroize_bytes(&mut self.encoded);
        shared_signer::bytes::zeroize_bytes(&mut self.account_raw);
        for key in &mut self.receive_cache { shared_signer::bytes::zeroize_bytes(key); }
        for key in &mut self.change_cache { shared_signer::bytes::zeroize_bytes(key); }
        self.length = 0;
    }
}

static MAILBOX: CrossCoreMailbox<KpubJob, KpubWorkerResult> = CrossCoreMailbox::new();

pub(crate) fn mark_ready() { MAILBOX.mark_ready(); }

pub(crate) fn is_idle() -> bool { MAILBOX.is_idle() }

pub(crate) fn submit_seed(
    seed: &mut offline_signer::derivation::bip39::Seed,
) -> Result<u8, &'static str> {
    submit_seed_job(seed, KpubSource::AccountKpubSeed, 90)
}

pub(crate) fn submit_multisig_seed(
    seed: &mut offline_signer::derivation::bip39::Seed,
) -> Result<u8, &'static str> {
    submit_seed_job(seed, KpubSource::MultisigKpubSeed, 90)
}

pub(crate) fn submit_address_seed(
    seed: &mut offline_signer::derivation::bip39::Seed,
) -> Result<u8, &'static str> {
    submit_seed_job(seed, KpubSource::AddressSeed, 86)
}

fn submit_seed_job(
    seed: &mut offline_signer::derivation::bip39::Seed,
    wrap: fn([u8; 64]) -> KpubSource,
    progress: u8,
) -> Result<u8, &'static str> {
    let generation = match next_generation() {
        Ok(generation) => generation,
        Err(error) => {
            shared_signer::bytes::zeroize_bytes(&mut seed.bytes);
            return Err(error);
        }
    };
    let mut seed_bytes = [0u8; 64];
    seed_bytes.copy_from_slice(&seed.bytes);
    shared_signer::bytes::zeroize_bytes(&mut seed.bytes);
    publish_job(KpubJob { generation, source: wrap(seed_bytes) }, progress)?;
    Ok(generation)
}

pub(crate) fn submit_account(slot: &SeedSlot) -> Result<u8, &'static str> {
    if !slot.is_account_key() {
        return Err("Active wallet is not an account key");
    }
    let generation = next_generation()?;
    let mut raw = [0u8; 65];
    if !slot.account_key_raw(&mut raw) {
        abandon_reservation(generation);
        return Err("Invalid account key slot");
    }
    let job = KpubJob {
        generation,
        source: KpubSource::AccountKpub {
            raw,
            parent_fingerprint: slot.account_parent_fingerprint,
        },
    };
    publish_job(job, 96)?;
    Ok(generation)
}

pub(crate) fn submit_address_slot(slot: &SeedSlot) -> Result<u8, &'static str> {
    let generation = next_generation()?;
    let source = if slot.is_account_key() {
        let mut raw = [0u8; 65];
        if !slot.account_key_raw(&mut raw) {
            abandon_reservation(generation);
            return Err("Invalid account key slot");
        }
        KpubSource::AddressAccount(raw)
    } else if slot.is_raw_key() {
        let mut raw = [0u8; 32];
        if !slot.raw_key_bytes(&mut raw) {
            abandon_reservation(generation);
            return Err("Invalid raw key");
        }
        KpubSource::AddressRawKey(raw)
    } else {
        abandon_reservation(generation);
        return Err("Address slot must be imported account/raw key");
    };
    publish_job(KpubJob { generation, source }, 86)?;
    Ok(generation)
}

fn next_generation() -> Result<u8, &'static str> {
    MAILBOX.reserve().map_err(|error| match error {
        ReserveError::Unavailable => "Derivation worker unavailable",
        ReserveError::Busy => "Derivation worker busy",
    })
}

fn abandon_reservation(generation: u8) {
    MAILBOX.cancel(generation);
}

fn publish_job(job: KpubJob, initial_progress: u8) -> Result<(), &'static str> {
    let generation = job.generation;
    if MAILBOX.publish_job(generation, job, initial_progress) {
        Ok(())
    } else {
        Err("Derivation worker publication cancelled")
    }
}

pub(crate) fn progress(generation: u8) -> u8 {
    MAILBOX.progress(generation)
}

pub(crate) fn take_result(generation: u8) -> Option<KpubWorkerResult> {
    let mut result = MAILBOX.take_result(generation)?;
    if result.generation() != generation {
        result.error = Some("Derivation worker generation mismatch");
    }
    Some(result)
}

pub(crate) fn discard_completed() {
    MAILBOX.discard_completed();
}

pub(crate) fn cancel(generation: u8) {
    MAILBOX.cancel(generation);
}

pub(crate) fn cancel_active() {
    MAILBOX.cancel_active();
}

pub(crate) fn core1_main() -> ! {
    loop {
        let Some(job) = MAILBOX.take_job() else {
            core::hint::spin_loop();
            continue;
        };
        let generation = job.generation;
        let outcome = process(job);
        let _ = MAILBOX.publish_result(generation, outcome);
    }
}

fn empty_result(generation: u8, kind: WorkerResultKind) -> KpubWorkerResult {
    KpubWorkerResult {
        generation,
        kind,
        encoded: [0u8; offline_signer::derivation::xpub::KPUB_MAX_LEN],
        length: 0,
        account_raw: [0u8; 65],
        receive_cache: [[0u8; 32]; 20],
        change_cache: [[0u8; 32]; 5],
        error: None,
    }
}

#[inline(never)]
fn process(job: KpubJob) -> KpubWorkerResult {
    let generation = job.generation;
    match &job.source {
        KpubSource::AccountKpubSeed(seed) => process_kpub_seed(generation, seed, false),
        KpubSource::MultisigKpubSeed(seed) => process_kpub_seed(generation, seed, true),
        KpubSource::AccountKpub { raw, parent_fingerprint } => {
            let mut out = empty_result(generation, WorkerResultKind::AccountKpub);
            MAILBOX.set_progress(98);
            let account = offline_signer::derivation::bip32::ExtendedPrivKey::from_raw(raw);
            match offline_signer::derivation::xpub::serialize_account_kpub(
                &account, *parent_fingerprint, &mut out.encoded,
            ) {
                Ok(length) => { out.length = length; MAILBOX.set_progress(100); }
                Err(_) => out.error = Some("kpub serialization failed"),
            }
            out
        }
        KpubSource::AddressSeed(seed) => {
            let mut out = empty_result(generation, WorkerResultKind::AddressCache);
            match offline_signer::derivation::bip32::derive_account_key(seed) {
                Ok(account) => fill_address_cache(&account, &mut out),
                Err(_) => out.error = Some("Account key derivation failed"),
            }
            out
        }
        KpubSource::AddressAccount(raw) => {
            let mut out = empty_result(generation, WorkerResultKind::AddressCache);
            let account = offline_signer::derivation::bip32::ExtendedPrivKey::from_raw(raw);
            if account.public_key_x_only().is_err() {
                out.error = Some("Invalid account key slot");
            } else {
                fill_address_cache(&account, &mut out);
            }
            out
        }
        KpubSource::AddressRawKey(raw) => {
            let mut out = empty_result(generation, WorkerResultKind::AddressCache);
            match offline_signer::derivation::bip32::pubkey_from_raw_key(raw) {
                Ok(public) => {
                    out.receive_cache[0] = public;
                    MAILBOX.set_progress(100);
                }
                Err(_) => out.error = Some("Invalid raw key"),
            }
            out
        }
    }
}

fn process_kpub_seed(generation: u8, seed: &[u8; 64], multisig: bool) -> KpubWorkerResult {
    let kind = if multisig { WorkerResultKind::MultisigKpub } else { WorkerResultKind::AccountKpub };
    let mut out = empty_result(generation, kind);
    MAILBOX.set_progress(92);
    let result = if multisig {
        offline_signer::derivation::xpub::derive_and_serialize_multisig_kpub(seed, &mut out.encoded)
    } else {
        offline_signer::derivation::xpub::derive_and_serialize_kpub(seed, &mut out.encoded)
    };
    match result {
        Ok(length) => { out.length = length; MAILBOX.set_progress(100); }
        Err(_) => out.error = Some(if multisig { "45' kpub derivation failed" } else { "kpub derivation failed" }),
    }
    out
}

fn fill_address_cache(
    account: &offline_signer::derivation::bip32::ExtendedPrivKey,
    out: &mut KpubWorkerResult,
) {
    out.account_raw.copy_from_slice(&account.to_raw());
    for index in 0..20u32 {
        MAILBOX.set_progress(88 + (index / 4) as u8);
        let Ok(key) = offline_signer::derivation::bip32::derive_address_key(account, index) else {
            out.error = Some("Address key derivation failed");
            return;
        };
        let Ok(public) = key.public_key_x_only() else {
            out.error = Some("Public key derivation failed");
            return;
        };
        out.receive_cache[index as usize] = public;
    }
    for index in 0..5u32 {
        MAILBOX.set_progress(94 + index as u8);
        let Ok(key) = offline_signer::derivation::bip32::derive_change_key(account, index) else {
            out.error = Some("Change key derivation failed");
            return;
        };
        let Ok(public) = key.public_key_x_only() else {
            out.error = Some("Change public key derivation failed");
            return;
        };
        out.change_cache[index as usize] = public;
    }
    MAILBOX.set_progress(100);
}
