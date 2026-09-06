use crate::{runtime::data::AppData};

pub(super) fn update_kspt(ad: &mut AppData) {
    let (present, required) = offline_signer::transaction::kspt::signature_status(
        &ad.signing.transaction.active,
    );
    update(ad, present, required);
}

pub(super) fn update_pskt(ad: &mut AppData) {
    let (present, required) = offline_signer::transaction::std_pskt::pskt_signature_status(
        &ad.signing.transaction.active,
    );
    update(ad, present, required);
}

pub(crate) fn rollback_added_signatures(
    ad: &mut AppData,
    initial_counts: &[u8],
) {
    use offline_signer::transaction::model::InputSig;

    let input_count = ad.signing.transaction.active.num_inputs;
    for input_index in 0..input_count {
        let input = &mut ad.signing.transaction.active.inputs[input_index];
        let keep = usize::from(initial_counts[input_index]).min(input.sigs.len());
        let current = usize::from(input.sig_count).min(input.sigs.len());
        for signature in &mut input.sigs[keep..current] {
            *signature = InputSig::empty();
        }
        input.sig_count = keep as u8;
    }
}


fn update(ad: &mut AppData, present: u32, required: u32) {
    ad.signing.transaction.signatures_present = present;
    ad.signing.transaction.signatures_required = required;
    if present < required {
        log!("   Partial: {}/{} sigs — pass to next signer", present, required);
    } else {
        log!("   Fully signed: {}/{}", present, required);
    }
}
