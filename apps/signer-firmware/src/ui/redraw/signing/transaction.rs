use crate::{
    hw::display,
    runtime::data::AppData,
};

pub(super) fn draw_guide(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) {
    // Before scanning the transaction, the network is unknown. Do not render a
    // guessed mainnet address; the transaction review verifies and displays
    // the explicit network/HRP carried by KSPT v4.
    boot_display.draw_sign_tx_guide(ad.wallet.seeds.seed_loaded, "");
}

pub(super) fn draw_review(
    ad: &AppData,
    boot_display: &mut display::BootDisplay<'_>,
    page: u8,
) {
    boot_display.draw_tx_page(
        &ad.signing.transaction.active,
        page,
        &ad.signing.transaction.output_ownership,
    );
}

pub(super) fn draw_utxo_summary(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) {
    let Ok(totals) = crate::runtime::signing::transaction_review_totals(
        &ad.signing.transaction.active,
        &ad.signing.transaction.output_ownership,
    ) else {
        boot_display.draw_tx_error_screen("Invalid transaction", "Invalid monetary totals");
        return;
    };
    boot_display.draw_utxo_summary_screen(&ad.signing.transaction.active, totals);
}

pub(super) fn draw_utxo(
    ad: &AppData,
    boot_display: &mut display::BootDisplay<'_>,
    index: usize,
    address_page: bool,
) {
    boot_display.draw_utxo_detail_screen(&ad.signing.transaction.active, index, address_page);
}

pub(super) fn draw_confirmation(
    ad: &AppData,
    boot_display: &mut display::BootDisplay<'_>,
) {
    let Ok(totals) = crate::runtime::signing::transaction_review_totals(
        &ad.signing.transaction.active,
        &ad.signing.transaction.output_ownership,
    ) else {
        boot_display.draw_tx_error_screen("Invalid transaction", "Invalid monetary totals");
        return;
    };
    let amount = format_kas(totals.external_total);
    let fee = format_kas(totals.fee);
    let change = format_kas(totals.change_total);
    let destination = short_external_destination(ad);

    if has_multisig_input(ad) {
        let (present, required) =
            offline_signer::transaction::kspt::signature_status(&ad.signing.transaction.active);
        boot_display.draw_confirm_send_multisig(&amount, &fee, &change, destination.as_str(), present, required);
    } else if has_covenant_input(ad) {
        boot_display.draw_confirm_send_covenant(&amount, &fee, &change, destination.as_str());
    } else {
        boot_display.draw_confirm_send_screen(&amount, &fee, &change, destination.as_str());
    }
}

fn format_kas(value: u64) -> heapless::String<24> {
    let mut bytes = [0u8; 20];
    let length = offline_signer::transaction::model::Transaction::format_kas(value, &mut bytes);
    let formatted = core::str::from_utf8(&bytes[..length]).unwrap_or("?.??");
    let mut result = heapless::String::new();
    core::fmt::Write::write_fmt(&mut result, format_args!("{formatted} KAS")).ok();
    result
}


fn short_external_destination(ad: &AppData) -> heapless::String<32> {
    use crate::runtime::data::OutputOwnership;
    let tx = &ad.signing.transaction.active;
    let mut count = 0usize;
    let mut first = 0usize;
    for index in 0..tx.num_outputs {
        if ad.signing.transaction.output_ownership[index] == OutputOwnership::External {
            if count == 0 { first = index; }
            count += 1;
        }
    }
    if count != 1 {
        let mut result = heapless::String::new();
        if count == 0 {
            let _ = core::fmt::Write::write_str(&mut result, "self/change only");
        } else {
            let _ = core::fmt::Write::write_fmt(&mut result, format_args!("MULTI ({count} outputs)"));
        }
        return result;
    }
    short_script_destination(&tx.outputs[first].script_public_key, tx.network)
}

fn short_script_destination(
    script: &offline_signer::transaction::model::ScriptPublicKey,
    network: offline_signer::address::KaspaNetwork,
) -> heapless::String<32> {
    let is_p2pk = script.script_len == 34 && script.script[0] == 0x20 && script.script[33] == 0xAC;
    let is_p2sh = script.script_len == 35 && script.script[0] == 0xAA && script.script[1] == 0x20 && script.script[34] == 0x87;
    if !(is_p2pk || is_p2sh) || network == offline_signer::address::KaspaNetwork::Unknown {
        let mut result = heapless::String::new();
        let _ = core::fmt::Write::write_str(&mut result, "script output");
        return result;
    }
    let mut material = [0u8; 32];
    let (kind, start) = if is_p2pk {
        (offline_signer::address::AddressType::P2pk, 1usize)
    } else {
        (offline_signer::address::AddressType::P2sh, 2usize)
    };
    material.copy_from_slice(&script.script[start..start + 32]);
    let mut buffer = [0u8; offline_signer::address::MAX_ADDR_LEN];
    let address = offline_signer::address::encode_address_str_for_network(&material, kind, network, &mut buffer);
    let payload = address.split_once(':').map(|(_, payload)| payload).unwrap_or(address);
    let mut result = heapless::String::new();
    if payload.len() <= 11 {
        let _ = core::fmt::Write::write_str(&mut result, payload);
        return result;
    }
    let _ = core::fmt::Write::write_str(&mut result, &payload[..4]);
    let _ = core::fmt::Write::write_str(&mut result, "...");
    let _ = core::fmt::Write::write_str(&mut result, &payload[payload.len() - 4..]);
    result
}

fn has_multisig_input(ad: &AppData) -> bool {
    (0..ad.signing.transaction.active.num_inputs).any(|index| {
        let (script_type, _) =
            offline_signer::transaction::kspt::analyze_input_script(&ad.signing.transaction.active, index);
        script_type == offline_signer::transaction::model::ScriptType::Multisig
    })
}

fn has_covenant_input(ad: &AppData) -> bool {
    (0..ad.signing.transaction.active.num_inputs).any(|index| {
        let (script_type, multisig) =
            offline_signer::transaction::kspt::analyze_input_script(&ad.signing.transaction.active, index);
        script_type == offline_signer::transaction::model::ScriptType::P2SH && multisig.is_none()
    })
}
