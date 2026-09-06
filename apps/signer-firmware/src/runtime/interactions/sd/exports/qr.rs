use super::super::common::context::{SdActionContext, SdIoContext};
// SD controller workflow: qr.
use super::super::{format_auto_name, scan_auto_increment};
pub(crate) fn handle_show_qr_popup(ctx: SdIoContext<'_, '_, '_>) -> bool {
    let SdIoContext {
        ad,
        delay,
        i2c,
        x,
        y,
        is_back,
        ..
    } = ctx;
    let mut needs_redraw = false;

    if is_back {
        crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ShowQrModeChoice));
        needs_redraw = true;
    } else {
        // Two buttons: "Save to SD" and "Back to QR"
        // Save to SD button zone: center-left area
        if (30..=155).contains(&x) && (140..=185).contains(&y) {
            // Save to SD → detect content type for correct extension
            let outgoing = &ad.qr.outgoing.buffer[..ad.qr.outgoing.length];
            let is_descriptor = outgoing.starts_with(b"multi_hd45(") || outgoing.starts_with(b"multi_hd(");
            if is_descriptor {
                let next = scan_auto_increment(i2c, delay, b"MD", b"TXT");
                let name = format_auto_name(b"MD", next, b"TXT");
                ad.storage.export_file.filename = name;
                ad.wallet.seeds.pp_input.reset();
                for j in 0..8usize {
                    if name[j] != b' ' {
                        ad.wallet.seeds.pp_input.push_char(name[j]);
                    }
                }
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdMsDescFilename));
            } else {
                let next = scan_auto_increment(i2c, delay, b"TX", b"KSP");
                let name = format_auto_name(b"TX", next, b"KSP");
                ad.storage.export_file.filename = name;
                ad.wallet.seeds.pp_input.reset();
                for j in 0..8usize {
                    if name[j] != b' ' {
                        ad.wallet.seeds.pp_input.push_char(name[j]);
                    }
                }
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdKsptFilename));
            }
            needs_redraw = true;
        }
        // Back to QR button zone: center-right area
        else if (165..=290).contains(&x) && (140..=185).contains(&y) {
            ad.qr.outgoing.frame = 0;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ShowQR));
            needs_redraw = true;
        }
    }

    needs_redraw
}

pub(crate) fn handle_show_qr_mode_choice(ctx: SdActionContext<'_>) -> bool {
    let SdActionContext {
        ad,
        x,
        y,
        is_back,
        ..
    } = ctx;

    if is_back {
        ad.qr.outgoing.frame_count = 0;
        if ad.signing.multisig.creating.n > 0 {
            // Descriptor QR — back to descriptor view
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(MultisigDescriptor));
        } else {
            crate::runtime::effects::home(ad);
        }
    } else {
        // "Auto Cycle" button: left
        if (30..=155).contains(&x) && (140..=185).contains(&y) {
            ad.qr.outgoing.manual_frames = false;
            ad.qr.outgoing.frame = 0; // start at frame 0 so the
            // frame-0 screen clear in redraw fires and wipes the
            // mode-choice text (Manual already resets this).
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ShowQR));
        }
        // "Manual" button: right
        else if (165..=290).contains(&x) && (140..=185).contains(&y) {
            ad.qr.outgoing.manual_frames = true;
            ad.qr.outgoing.frame = 0;
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ShowQR));
        }
    }
    true
}
