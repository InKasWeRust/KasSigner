//! Stage-3 Connect KasSee and multisig kpub operation workers.

use crate::runtime::data::AppData;

const KPUB_PBKDF2_ROUNDS_PER_STEP: u16 = 1;

mod cancel;

pub(in crate::runtime::event_loop) use cancel::cancel_operation;
#[cfg(not(feature = "workflow-test-auto"))]
pub(in crate::runtime::event_loop) use cancel::service;

pub(in crate::runtime::event_loop) fn service_operation(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    use crate::runtime::data::OperationKind;
    let Some(kind) = crate::runtime::presentation::operation_kind(ad) else { return; };
    if !matches!(kind, OperationKind::ConnectKasSee | OperationKind::DeriveMultisigKpub) { return; }
    match kind {
        OperationKind::ConnectKasSee => service_connect_operation(ad, boot_display, liveness),
        OperationKind::DeriveMultisigKpub => service_multisig_operation(ad, boot_display, liveness),
        _ => {}
    }
    liveness();
}

#[cfg(feature = "waveshare")]
fn service_connect_operation(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    liveness();
    if ad.export.kpub_seed_derivation.is_none() && ad.export.kpub_account_derivation.is_none() {
        begin_staged(ad);
    } else if ad.export.kpub_seed_derivation.is_some() {
        advance_seed(ad, boot_display);
    } else {
        advance_account(ad, boot_display);
    }
}

#[cfg(feature = "m5stack")]
fn service_connect_operation(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    liveness();
    service_connect_kpub_m5stack(ad, boot_display);
}

#[cfg(feature = "waveshare")]
fn service_multisig_operation(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    liveness();
    let Some(slot) = ad.wallet.seeds.seed_mgr.active_slot() else {
        fail(ad, "No active wallet");
        return;
    };
    let Ok(mut seed) = crate::services::wallet_keys::derive_slot_seed_with_checkpoint(slot, liveness) else {
        fail(ad, "45' key derivation failed");
        return;
    };
    let mut encoded = [0u8; offline_signer::derivation::xpub::KPUB_MAX_LEN];
    let result = offline_signer::derivation::xpub::derive_and_serialize_multisig_kpub(
        &seed.bytes, &mut encoded,
    );
    crate::runtime::signing::zeroize_seed(&mut seed.bytes);
    match result {
        Ok(length) if length <= ad.export.kpub_data.len() => {
            if !encoded_kpub_is_valid(&encoded[..length]) {
                shared_signer::bytes::zeroize_bytes(&mut encoded);
                fail(ad, "Multisig kpub format invalid");
                return;
            }
            ad.export.kpub_data[..length].copy_from_slice(&encoded[..length]);
            shared_signer::bytes::zeroize_bytes(&mut encoded);
            ad.export.kpub_len = length;
            boot_display.update_progress_bar(100);
            crate::runtime::presentation::finish_success(ad);
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportKpub));
        }
        _ => {
            shared_signer::bytes::zeroize_bytes(&mut encoded);
            fail(ad, "Multisig kpub derivation failed");
        }
    }
}

#[cfg(feature = "m5stack")]
fn service_multisig_operation(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    liveness: &mut (impl FnMut() + ?Sized),
) {
    liveness();
    service_multisig_kpub_m5stack(ad, boot_display);
}

#[cfg(feature = "m5stack")]
fn service_connect_kpub_m5stack(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
) {
    use crate::services::wallet_keys::worker as kpub_worker;

    if let Some(generation) = ad.export.kpub_worker_generation {
        update_progress(ad, boot_display, kpub_worker::progress(generation));
        let Some(mut result) = kpub_worker::take_result(generation) else { return; };
        ad.export.kpub_worker_generation = None;
        if result.kind() != kpub_worker::WorkerResultKind::AccountKpub {
            fail(ad, "Account derivation worker result mismatch");
            return;
        }
        if let Some(error) = result.error() {
            fail(ad, error);
            return;
        }
        crate::log!("   Connect KasSee Core1 finalizer result received");
        let length = result.length();
        finish_encoded(ad, result.encoded_mut(), length);
        return;
    }

    if ad.export.kpub_seed_derivation.is_some() {
        advance_m5stack_seed(ad, boot_display);
        return;
    }

    // Never steal a worker generation from Receive/Change or multisig export.
    if ad.wallet.addresses.cache_worker_generation.is_some()
        || ad.export.multisig_worker_generation.is_some()
    {
        return;
    }
    kpub_worker::discard_completed();
    if !kpub_worker::is_idle() { return; }
    begin_m5stack(ad);
}

#[cfg(feature = "m5stack")]
fn service_multisig_kpub_m5stack(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
) {
    use crate::services::wallet_keys::worker as kpub_worker;

    if let Some(generation) = ad.export.multisig_worker_generation {
        update_progress(ad, boot_display, kpub_worker::progress(generation));
        let Some(mut result) = kpub_worker::take_result(generation) else { return; };
        ad.export.multisig_worker_generation = None;
        if result.kind() != kpub_worker::WorkerResultKind::MultisigKpub {
            fail_multisig(ad, "Multisig derivation worker result mismatch");
            return;
        }
        if let Some(error) = result.error() {
            fail_multisig(ad, error);
            return;
        }
        let length = result.length();
        if length > ad.export.kpub_data.len() {
            fail_multisig(ad, "Multisig kpub serialization length invalid");
            return;
        }
        if !encoded_kpub_is_valid(&result.encoded_mut()[..length]) {
            shared_signer::bytes::zeroize_bytes(result.encoded_mut());
            fail_multisig(ad, "Multisig kpub format invalid");
            return;
        }
        ad.export.kpub_data[..length].copy_from_slice(&result.encoded_mut()[..length]);
        shared_signer::bytes::zeroize_bytes(result.encoded_mut());
        ad.export.kpub_len = length;
        ad.export.reset_multisig_kpub_work();
        crate::log!("   Multisig kpub cooperative derivation DONE");
        crate::runtime::presentation::finish_success(ad);
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportKpub));
        return;
    }

    if ad.export.multisig_seed_derivation.is_some() {
        let (seed, progress) = {
            let Some(work) = ad.export.multisig_seed_derivation.as_mut() else { return; };
            let seed = work.advance(KPUB_PBKDF2_ROUNDS_PER_STEP);
            let progress = ((u16::from(work.progress_percent()) * 88) / 100) as u8;
            (seed, progress)
        };
        update_progress(ad, boot_display, progress);
        let Some(mut seed) = seed else { return; };
        ad.export.multisig_seed_derivation = None;
        match kpub_worker::submit_multisig_seed(&mut seed) {
            Ok(generation) => {
                ad.export.multisig_worker_generation = Some(generation);
                crate::log!("   Multisig PBKDF2 DONE; Core1 BIP45 finalizer submitted");
            }
            Err(error) => {
                shared_signer::bytes::zeroize_bytes(&mut seed.bytes);
                fail_multisig(ad, error);
            }
        }
        return;
    }

    if ad.wallet.addresses.cache_worker_generation.is_some()
        || ad.export.kpub_worker_generation.is_some()
    {
        return;
    }
    kpub_worker::discard_completed();
    if !kpub_worker::is_idle() { return; }
    let Some(slot) = ad.wallet.seeds.seed_mgr.active_slot() else {
        fail_multisig(ad, "No active wallet");
        return;
    };
    match crate::runtime::signing::begin_mnemonic_seed(slot) {
        Ok(work) => {
            ad.export.multisig_seed_derivation = Some(work);
            ad.export.kpub_progress = 1;
            boot_display.update_progress_bar(1);
            crate::log!("   Multisig cooperative PBKDF2 BEGIN");
        }
        Err(error) => fail_multisig(ad, error),
    }
}

#[cfg(feature = "m5stack")]
fn fail_multisig(ad: &mut AppData, error: &'static str) {
    ad.export.kpub_len = 0;
    ad.export.reset_multisig_kpub_work();
    crate::log!("   Multisig kpub derivation failed: {}", error);
    crate::runtime::presentation::fail_recoverable(ad, error, "KPUB-MULTI-01", 0);
}

#[cfg(feature = "m5stack")]
#[inline(never)]
fn begin_m5stack(ad: &mut AppData) {
    use crate::services::wallet_keys::worker as kpub_worker;
    ad.export.kpub_len = 0;
    ad.export.kpub_progress = 0;
    crate::log!("   Connect KasSee cooperative derivation BEGIN");
    let Some(slot) = ad.wallet.seeds.seed_mgr.active_slot() else {
        fail(ad, "No active wallet");
        return;
    };
    if slot.is_raw_key() {
        fail(ad, "Raw key has no watch account");
        return;
    }
    if slot.is_account_key() {
        match kpub_worker::submit_account(slot) {
            Ok(generation) => {
                ad.export.kpub_worker_generation = Some(generation);
                crate::log!("   Connect KasSee account finalizer submitted to Core1");
            }
            Err(error) => fail(ad, error),
        }
        return;
    }
    match crate::runtime::signing::begin_mnemonic_seed(slot) {
        Ok(work) => {
            ad.export.kpub_seed_derivation = Some(work);
            crate::log!("   Connect KasSee PBKDF2 staged on Core0; one round per UI loop");
        }
        Err(error) => fail(ad, error),
    }
}

#[cfg(feature = "m5stack")]
#[inline(never)]
fn advance_m5stack_seed(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
) {
    let (seed, progress) = {
        let Some(work) = ad.export.kpub_seed_derivation.as_mut() else { return; };
        let seed = work.advance(KPUB_PBKDF2_ROUNDS_PER_STEP);
        let progress = ((u16::from(work.progress_percent()) * 88) / 100) as u8;
        (seed, progress)
    };
    update_progress(ad, boot_display, progress);
    let Some(mut seed) = seed else { return; };
    ad.export.kpub_seed_derivation = None;
    crate::log!("   Connect KasSee PBKDF2 DONE; Core1 finalizer submit BEGIN");
    match crate::services::wallet_keys::worker::submit_seed(&mut seed) {
        Ok(generation) => {
            ad.export.kpub_worker_generation = Some(generation);
            crate::log!("   Connect KasSee Core1 finalizer submitted");
        }
        Err(error) => {
            shared_signer::bytes::zeroize_bytes(&mut seed.bytes);
            fail(ad, error);
        }
    }
}

#[cfg(feature = "waveshare")]
#[inline(never)]
fn begin_staged(ad: &mut AppData) {
    ad.export.kpub_len = 0;
    ad.export.kpub_progress = 0;
    crate::log!("   Connect KasSee account derivation BEGIN");
    match crate::runtime::signing::begin_active_kpub_derivation(ad) {
        Ok(start) => stage_start(ad, start),
        Err(error) => fail(ad, error),
    }
}

#[cfg(feature = "waveshare")]
fn stage_start(ad: &mut AppData, start: crate::runtime::signing::KpubDerivationStart) {
    if let Some(work) = start.pending_seed {
        ad.export.kpub_seed_derivation = Some(work);
        crate::log!("   Connect KasSee PBKDF2 staged; cooperative rounds start next loop");
        return;
    }
    if let Some(work) = start.pending_account {
        ad.export.kpub_account_derivation = Some(work);
        ad.export.kpub_progress = 96;
        crate::log!("   Connect KasSee account serialization staged");
        return;
    }
    fail(ad, "Account derivation did not start");
}

#[cfg(feature = "waveshare")]
#[inline(never)]
fn advance_seed(ad: &mut AppData, boot_display: &mut crate::hw::display::BootDisplay<'_>) {
    let (seed, progress) = {
        let Some(work) = ad.export.kpub_seed_derivation.as_mut() else { return; };
        let seed = work.advance(KPUB_PBKDF2_ROUNDS_PER_STEP);
        let progress = ((u16::from(work.progress_percent()) * 90) / 100) as u8;
        (seed, progress)
    };
    update_progress(ad, boot_display, progress);
    let Some(mut seed) = seed else { return; };
    ad.export.kpub_seed_derivation = None;
    match crate::runtime::signing::stage_active_kpub_account_derivation(ad, &mut seed) {
        Ok(work) => {
            ad.export.kpub_account_derivation = Some(work);
            crate::log!("   Connect KasSee BIP32 staged; one account child per loop");
        }
        Err(error) => fail(ad, error),
    }
}

#[cfg(feature = "waveshare")]
#[inline(never)]
fn advance_account(ad: &mut AppData, boot_display: &mut crate::hw::display::BootDisplay<'_>) {
    let Some(work) = ad.export.kpub_account_derivation.as_mut() else { return; };
    if work.is_complete() {
        finish_account(ad, boot_display);
        return;
    }
    match work.advance_one() {
        Ok(_) => {
            let steps = work.completed_steps();
            crate::log!("   Connect KasSee BIP32 step {}/3 DONE", steps);
            let progress = 90u8.saturating_add((steps as u8).saturating_mul(2));
            update_progress(ad, boot_display, progress.min(96));
        }
        Err(_) => fail(ad, "Account key derivation failed"),
    }
}

#[cfg(feature = "waveshare")]
#[inline(never)]
fn finish_account(ad: &mut AppData, boot_display: &mut crate::hw::display::BootDisplay<'_>) {
    let Some(work) = ad.export.kpub_account_derivation.take() else { return; };
    crate::log!("   Connect KasSee account serialization BEGIN");
    let mut encoded = [0u8; offline_signer::derivation::xpub::KPUB_MAX_LEN];
    let result = crate::runtime::signing::finish_active_kpub_derivation(ad, work, &mut encoded);
    match result {
        Ok(length) => {
            update_progress(ad, boot_display, 100);
            crate::log!("   Connect KasSee account serialization DONE");
            finish_encoded(ad, &mut encoded, length);
        }
        Err(error) => {
            shared_signer::bytes::zeroize_bytes(&mut encoded);
            fail(ad, error);
        }
    }
}

fn update_progress(
    ad: &mut AppData,
    boot_display: &mut crate::hw::display::BootDisplay<'_>,
    progress: u8,
) {
    if progress == ad.export.kpub_progress { return; }
    ad.export.kpub_progress = progress;
    crate::runtime::presentation::set_progress(ad, progress);
    boot_display.update_progress_bar(progress);
}

fn finish_encoded(
    ad: &mut AppData,
    encoded: &mut [u8; offline_signer::derivation::xpub::KPUB_MAX_LEN],
    length: usize,
) {
    if length > ad.export.kpub_data.len() {
        shared_signer::bytes::zeroize_bytes(encoded);
        fail(ad, "kpub serialization length invalid");
        return;
    }
    if !encoded_kpub_is_valid(&encoded[..length]) {
        shared_signer::bytes::zeroize_bytes(encoded);
        fail(ad, "Account key format invalid");
        return;
    }
    ad.export.kpub_data[..length].copy_from_slice(&encoded[..length]);
    ad.export.cache_connect_kpub(&encoded[..length]);
    shared_signer::bytes::zeroize_bytes(encoded);
    ad.export.kpub_len = length;
    ad.export.reset_kpub_work();
    crate::log!("   Connect KasSee account derivation DONE");
    crate::runtime::presentation::finish_success(ad);
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ExportKpub));
}


fn encoded_kpub_is_valid(encoded: &[u8]) -> bool {
    let mut payload = [0u8; offline_signer::derivation::xpub::XPUB_PAYLOAD_LEN];
    let valid = offline_signer::derivation::xpub::decode_kpub_compatible(encoded, &mut payload).is_ok();
    shared_signer::bytes::zeroize_bytes(&mut payload);
    valid
}

fn fail(ad: &mut AppData, error: &'static str) {
    ad.export.kpub_len = 0;
    ad.export.reset_kpub_work();
    crate::log!("   Connect KasSee account derivation failed: {}", error);
    crate::runtime::presentation::fail_recoverable(ad, error, "KPUB-01", 0);
}
