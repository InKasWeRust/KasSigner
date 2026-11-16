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

//! Drawing: the halt and logo screens, every screen the flow names, the
//! camera view and the codes.

use super::*;

/// The PANIC screen, saying `reason`, for a board that failed after its
/// panel came up. A frame of its own, as [`draw`]: inlined, the band
/// would make `run`'s frame 4,800 bytes larger on the P4, for good.
#[inline(never)]
pub(super) fn draw_halt<L: Display>(lcd: &mut L, reason: &str) {
    let size = lcd.size();
    let whole = Rect::new(0, 0, size.width, size.height);
    let mut band = [BACKGROUND; BAND_WIDTH * BAND_ROWS];
    let _ = render(lcd, whole, BACKGROUND, &mut band, |b| {
        refusal::panic(b, Scale::for_panel(size), KIT, reason)
    });
}

/// The logo screen, in a frame of its own as [`draw`].
#[inline(never)]
pub(super) fn draw_logo<L: Display>(lcd: &mut L) {
    let size = lcd.size();
    let whole = Rect::new(0, 0, size.width, size.height);
    let mut band = [BACKGROUND; BAND_WIDTH * BAND_ROWS];
    let _ = render(lcd, whole, BACKGROUND, &mut band, |b| {
        brand::logo(b, Scale::for_panel(size), KIT, VERSION, crate::UNIT)
    });
}

/// Paint the screen the flow named, through the band renderer, or a code
/// straight to the panel. Unless `fresh`, only what changed is drawn,
/// which matters where a viewfinder paints over the rest. Anything
/// secret or typed (letters, words, keys, hints, rolls) comes from the
/// flow, never from `screen`, which a `diag` build prints.
///
/// Returns false for a review page or CONFIRM SEND? that did not go on
/// the panel whole, which the flow must be told (`Event::NotDrawn`); any
/// other screen's failure leaves nothing the flow could count as seen.
///
/// Never inlined: the band, 15 KB on the P4, is on this frame's stack
/// and gone when it returns; inlined into `run`, it would take that
/// stack from signing for good.
#[inline(never)]
pub(super) fn draw<L: Display>(
    lcd: &mut L,
    flow: &Flow<'_, SLOTS>,
    screen: &Screen,
    fresh: bool,
    battery: Option<Gauge>,
    image_hash: Option<&[u8; brand::HASH_SHOWN]>,
    kept: &mut Option<Stretched>,
) -> bool {
    let size = lcd.size();
    let scale = Scale::for_panel(size);
    let whole = Rect::new(0, 0, size.width, size.height);
    let mut band = [BACKGROUND; BAND_WIDTH * BAND_ROWS];
    match screen {
        Screen::Booting => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                brand::logo(b, scale, KIT, VERSION, crate::UNIT)
            });
        }
        // Home again is its battery changing: that zone alone.
        Screen::Home => {
            let area = redraw(fresh, whole, brand::gauge_zone(scale));
            let _ = render_with(lcd, area, BACKGROUND, &mut band, kept.as_mut(), |b| {
                brand::home(b, scale, KIT, None, battery)
            });
        }
        Screen::Wiped => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                brand::wiped(b, scale, KIT)
            });
        }
        Screen::Menu { menu: id, page } => {
            let (m, dimmed) = (flow.menu(*id), flow.dimmed(*id));
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                menu::draw_dimmed(b, scale, KIT, m, *page, None, dimmed)
            });
        }
        Screen::CreateMultisig { m, n } => {
            let (m, n) = (usize::from(*m), usize::from(*n));
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                multisig::draw_create(b, scale, KIT, m, n)
            });
        }
        Screen::AddKey { key, of } => {
            let at = (usize::from(*key), usize::from(*of));
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                multisig::draw_add_key(b, scale, KIT, at, None)
            });
        }
        Screen::SelectSeed { page, key, of } => {
            let (rows, n) = flow.seed_rows();
            let title = multisig::select_seed(usize::from(*key), usize::from(*of));
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                seeds::draw_pick(b, scale, KIT, title, &rows[..n], *page, None)
            });
        }
        // DESCRIPTOR: the held group's keys, a line each.
        Screen::Descriptor { own } => {
            if let Some(group) = flow.group() {
                let (m, n) = (group.required(), group.total().min(5));
                let mut texts = [[0u8; 128]; 5];
                let mut lens = [0usize; 5];
                for (i, (text, len)) in texts.iter_mut().zip(lens.iter_mut()).enumerate() {
                    *len = flow.group_key_text(i, text).map_or(0, str::len);
                }
                let keys: [&str; 5] = core::array::from_fn(|i| {
                    core::str::from_utf8(&texts[i][..lens[i]]).unwrap_or("")
                });
                let own = own.map(usize::from);
                let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                    multisig::draw_descriptor(b, scale, KIT, (m, n), &keys[..n], own, None)
                });
            }
        }
        Screen::LoadGroup { m, n, seed, held } => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                multisig::draw_load(b, scale, KIT, (*m, *n), (*seed, *held), None)
            });
        }
        // SAVINGS CARD; while searching, only the search's button.
        Screen::Savings { page } | Screen::SavingsSearching { page, .. } => {
            let mut texts = savings::NO_TEXTS;
            if let Some(shown) = flow.savings_shown(&mut texts) {
                let page = usize::from(*page);
                let area = match screen {
                    Screen::SavingsSearching { .. } if !fresh => rect(savings::search_area(scale)),
                    _ => whole,
                };
                let _ = render_with(lcd, area, BACKGROUND, &mut band, kept.as_mut(), |b| {
                    savings::draw(b, scale, KIT, &shown, page, None)
                });
            }
        }
        // The address's code alone, as large as the panel allows.
        Screen::SavingsAddressQr => match flow.savings_address_code() {
            Some(code) => draw_code(lcd, scale, &code),
            None => {
                let _ = lcd.clear(BLACK);
            }
        },
        // SAVINGS CARD QR: one code or frames, both live.
        Screen::SavingsFormat => {
            let (mut one, mut two) = ([0u8; 24], [0u8; 24]);
            let wallet = kpub::codes_hint(kpub::TEXT, flow.savings_codes(true), &mut one);
            let unit = kpub::codes_hint(kpub::TEXT, flow.savings_codes(false), &mut two);
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                kpub::format(b, scale, KIT, kpub::SAVINGS_TITLE, (wallet, unit))
            });
        }
        Screen::Seeds { page } => {
            let (rows, n) = flow.seed_rows();
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                seeds::draw(b, scale, KIT, &rows[..n], SLOTS, *page, None)
            });
        }
        Screen::RawKeyConfirm => {
            let text = flow.address_text();
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                address::draw_ask(b, scale, KIT, &dialog::import_key(), text)
            });
        }
        Screen::MessageConfirm => {
            let text = flow.address_text();
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                address::draw_ask(b, scale, KIT, &dialog::sign_with(), text)
            });
        }
        Screen::MessagePreview {
            page,
            pages,
            signed,
            live,
        } => {
            let text = flow.message_text();
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                address::draw_message(b, scale, KIT, text, (*page, *pages), (*signed, *live))
            });
        }
        Screen::MessageCheck { valid } => {
            let text = flow.address_text();
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                address::draw_ask(b, scale, KIT, &dialog::checked(*valid), text)
            });
        }
        Screen::SignWith { change, index } => {
            let text = flow.address_text();
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                address::draw_sign_with(b, scale, KIT, text, *change, *index)
            });
        }
        Screen::MessageResult { page } => {
            let (signature, signer) = (flow.signature_text(), flow.address_text());
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                address::draw_signed(b, scale, KIT, *page, signature, signer)
            });
        }
        // A choice past the frames a unit reassembles is dimmed and says
        // so instead of its count; DESCRIPTOR QR and the reply's likewise.
        Screen::MessageFormat => {
            let (mut one, mut two) = ([0u8; 24], [0u8; 24]);
            let live = (flow.message_fits(true), flow.message_fits(false));
            let wallet = hint(live.0, kpub::TEXT, || flow.message_frames(true), &mut one);
            let unit = hint(live.1, kpub::TEXT, || flow.message_frames(false), &mut two);
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                kpub::format_live(b, scale, KIT, kpub::MESSAGE_TITLE, (wallet, unit), live)
            });
        }
        Screen::DescriptorFormat => {
            let (mut one, mut two) = ([0u8; 24], [0u8; 24]);
            let live = (flow.descriptor_fits(true), flow.descriptor_fits(false));
            let wallet = hint(live.0, kpub::TEXT, || flow.descriptor_codes(true), &mut one);
            let unit = hint(
                live.1,
                kpub::TEXT,
                || flow.descriptor_codes(false),
                &mut two,
            );
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                kpub::format_live(b, scale, KIT, kpub::DESCRIPTOR_TITLE, (wallet, unit), live)
            });
        }
        Screen::PlainFormat => {
            let (mut one, mut two) = ([0u8; 24], [0u8; 24]);
            let wallet = kpub::codes_hint(kpub::TEXT, flow.plain_codes(true), &mut one);
            let unit = kpub::codes_hint(kpub::TEXT, flow.plain_codes(false), &mut two);
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                kpub::format(b, scale, KIT, kpub::PLAIN_TITLE, (wallet, unit))
            });
        }
        Screen::ReplyFormat => {
            let what = kpub::reply_what(flow.reply_format() == frame::Format::Pskb);
            // A wallet built on v1.0.7 is shown the reply in that form.
            let old = if flow.reply_v107().is_empty() {
                what
            } else {
                kpub::REPLY_V107
            };
            let (mut one, mut two) = ([0u8; 24], [0u8; 24]);
            let live = (flow.reply_fits(true), flow.reply_fits(false));
            let wallet = hint(live.0, old, || flow.reply_codes(true), &mut one);
            let unit = hint(live.1, what, || flow.reply_codes(false), &mut two);
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                kpub::format_live(b, scale, KIT, kpub::REPLY_TITLE, (wallet, unit), live)
            });
        }
        Screen::Loading { words } => {
            let d = dialog::load(*words);
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &d, None)
            });
        }
        Screen::Deleting { slot, hold } => {
            let mut line = [0u8; 40];
            let text = flow
                .seed(*slot)
                .map_or(seeds::SLOT, |s| s.describe(&mut line));
            let d = dialog::delete(text, *hold);
            // While the hold fills, only its button.
            let area = match (fresh, dialog::zone(scale, dialog::Target::Accept)) {
                (false, Some(z)) => rect(z),
                _ => whole,
            };
            let _ = render_with(lcd, area, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &d, None)
            });
        }
        Screen::Asking { checked } => {
            let mut buf = [0u8; 32];
            let line = checked_line(*checked, &mut buf);
            let d = dialog::search(line);
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &d, None)
            });
        }
        Screen::Searching { done, total } => {
            let area = redraw(fresh, whole, loading::bar_area(scale));
            let _ = render_with(lcd, area, BACKGROUND, &mut band, kept.as_mut(), |b| {
                chrome::place_back(b, scale);
                loading::draw(b, scale, KIT, loading::SEARCHING, *done, *total)
            });
        }
        Screen::Opening { done, total } => {
            let area = redraw(fresh, whole, loading::bar_area(scale));
            let _ = render_with(lcd, area, BACKGROUND, &mut band, kept.as_mut(), |b| {
                loading::draw(b, scale, KIT, loading::OPENING, *done, *total)
            });
        }
        // A new level redraws only the bar and percentage.
        Screen::Display { level } | Screen::Audio { level } => {
            let text = match screen {
                Screen::Audio { .. } => settings::AUDIO,
                _ => settings::DISPLAY,
            };
            let area = redraw(fresh, whole, settings::level_area(scale));
            let _ = render_with(lcd, area, BACKGROUND, &mut band, kept.as_mut(), |b| {
                settings::level(b, scale, KIT, text, *level, None)
            });
        }
        // The verification screen again, the unit's name at its foot.
        Screen::About(check) => {
            let version = env!("CARGO_PKG_VERSION");
            let unit = Some(crate::UNIT);
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                brand::verification(b, scale, KIT, version, image_hash, check.verdict, unit)
            });
        }
        // Around the viewfinder, which paints itself: unless fresh, the
        // right side and foot only.
        Screen::CameraTune { knob, value, auto } => {
            let t = camtune::Tuning {
                knobs: flow.knobs(),
                picked: *knob,
                value: *value,
                auto: *auto,
            };
            let areas = if fresh {
                [Some(whole), None]
            } else {
                [
                    Some(rect(camtune::panel_area(scale))),
                    Some(rect(camtune::slider_area(scale))),
                ]
            };
            for area in areas.into_iter().flatten() {
                let _ = render_with(lcd, area, BACKGROUND, &mut band, kept.as_mut(), |b| {
                    camtune::draw(b, scale, KIT, &t, None)
                });
            }
        }
        Screen::Card { status } => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                sd_card::draw(b, scale, KIT, *status, None)
            });
        }
        Screen::CardFormat { hold } => {
            let d = dialog::format(*hold);
            // While the hold fills, only its button.
            let area = match (fresh, dialog::zone(scale, dialog::Target::Accept)) {
                (false, Some(z)) => rect(z),
                _ => whole,
            };
            let _ = render_with(lcd, area, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &d, None)
            });
        }
        Screen::Keyboard { typing, page, .. } => {
            let (text, cursor) = flow.typed();
            let line = keyboard::Line {
                text,
                cursor,
                note: flow.keyboard_note(),
                mode: typing.mode(text.len()),
                word: None,
            };
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                keyboard::draw(b, scale, KIT, typing.title(), *page, line)
            });
        }
        Screen::GroupAddress {
            change,
            index,
            cosigner,
        } => {
            let text = flow.address_text();
            let (m, n) = flow.group().map_or((0, 0), |g| (g.required(), g.total()));
            let group = (m, n, usize::from(*cosigner));
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                address::draw_group(b, scale, KIT, text, (*change, *index), group)
            });
        }
        Screen::Kcc3Address { change, index } => {
            let text = flow.address_text();
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                address::draw_kcc3(b, scale, KIT, text, *change, *index)
            });
        }
        Screen::Address {
            change,
            index,
            single,
        } => {
            let text = flow.address_text();
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                address::draw(b, scale, KIT, text, *change, *index, *single)
            });
        }
        // An address read from a file, its name under it.
        Screen::FileAddress { name } => {
            let mut shown = [0u8; 12];
            let n = card::shown_name(&name.0, &mut shown);
            let name = core::str::from_utf8(&shown[..n]).unwrap_or("");
            let text = flow.file_address();
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                address::draw_file(b, scale, KIT, address::FILE_ADDRESS_TITLE, text, name)
            });
        }
        // The code alone, as large as the panel allows.
        Screen::AddressQr { .. } | Screen::FileAddressQr => {
            let text = match screen {
                Screen::FileAddressQr => flow.file_address(),
                _ => flow.address_text(),
            };
            if let Ok(code) = qr::encode(text.as_bytes()) {
                draw_code(lcd, scale, &code);
            }
        }
        Screen::PrivateKey {
            change,
            index,
            single,
        } => {
            if let Some(text) = flow.key_text() {
                let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                    address::draw_key(b, scale, KIT, text, *change, *index, *single)
                });
            }
        }
        Screen::Kprv { master } => {
            if let Some(text) = flow.key_text() {
                let title = if *master {
                    address::KPRV_MASTER
                } else {
                    address::KPRV_ACCOUNT
                };
                let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                    address::draw_text(b, scale, KIT, title, text)
                });
            }
        }
        // A code that cannot be made leaves the panel black, here and
        // below, so the screen before cannot stand in for it.
        Screen::PrivateKeyQr { .. } | Screen::KprvQr { .. } => {
            if let Some(code) = flow.key_code() {
                draw_code(lcd, scale, &code);
            } else {
                let _ = lcd.clear(BLACK);
            }
        }
        Screen::AddressIndex { typed, len } => {
            let typed = core::str::from_utf8(&typed.0[..usize::from(*len)]).unwrap_or("");
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                keypad::draw(b, scale, KIT, keypad::ADDRESS_TITLE, typed, keypad::HINT)
            });
        }
        // QR Export: the code full screen, made by the flow and wiped
        // when dropped; the grid view shows 7 by 7 modules.
        Screen::SeedQr { .. } | Screen::PlainQr => {
            if let Some(code) = flow.export_code() {
                draw_code(lcd, scale, &code);
            } else {
                let _ = lcd.clear(BLACK);
            }
        }
        Screen::SeedQrGrid { x, y, .. } => {
            if let Some(code) = flow.export_code() {
                let at = (*x, *y);
                let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                    seedqr::draw(b, scale, KIT, &code, at)
                });
            } else {
                let _ = lcd.clear(BLACK);
            }
        }
        Screen::KpubFormat => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                kpub::format(b, scale, KIT, kpub::KPUB_TITLE, kpub::KPUB_HINTS)
            });
        }
        Screen::KpubMode
        | Screen::MessageMode
        | Screen::DescriptorMode
        | Screen::PlainMode
        | Screen::SavingsMode
        | Screen::ReplyMode
        | Screen::ReplyDone
        | Screen::MessageDone
        | Screen::AddressDone
        | Screen::SeedDone
        | Screen::KpubExported
        | Screen::KpubEncrypt
        | Screen::KpubScanned
        | Screen::CosignerKey => {
            let d = match screen {
                Screen::KpubMode
                | Screen::MessageMode
                | Screen::DescriptorMode
                | Screen::PlainMode
                | Screen::SavingsMode
                | Screen::ReplyMode => dialog::qr_mode(),
                Screen::ReplyDone => dialog::signed_tx(),
                Screen::MessageDone => dialog::message_exported(),
                Screen::AddressDone => dialog::address_exported(),
                Screen::SeedDone => dialog::seed_exported(),
                Screen::KpubExported => dialog::kpub_exported(),
                Screen::KpubScanned => dialog::kpub_scanned(),
                Screen::CosignerKey => dialog::cosigner_key(),
                _ => dialog::encrypt_file(),
            };
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &d, None)
            });
        }
        // One code full screen; frames at the left, FRAMES n/N beside
        // them and a multisig reply's SIGNER count above.
        Screen::KpubQr { frame, frames }
        | Screen::MessageFrames { frame, frames }
        | Screen::DescriptorFrames { frame, frames }
        | Screen::SavingsFrames { frame, frames }
        | Screen::PlainFrames { frame, frames }
        | Screen::Reply { frame, frames } => {
            let (code, signers) = match screen {
                Screen::KpubQr { .. } => (flow.kpub_code(*frame), None),
                Screen::PlainFrames { .. } => (flow.plain_frame(*frame), None),
                Screen::DescriptorFrames { .. } => (flow.descriptor_frame(*frame), None),
                Screen::SavingsFrames { .. } => (flow.savings_frame(*frame), None),
                Screen::Reply { .. } => (flow.reply_code(*frame), flow.reply_signers()),
                _ => (flow.message_frame(*frame), None),
            };
            if let Some(code) = code {
                if *frames <= 1 {
                    draw_code(lcd, scale, &code);
                } else {
                    // Each next frame over the last, its modules only,
                    // so nothing flashes.
                    if fresh {
                        paint::draw_code_left(lcd, &code, margin(scale));
                    } else {
                        paint::code_again(lcd, &code, margin(scale), true);
                    }
                    let size = lcd.size();
                    let panel = (size.width, size.height);
                    let column = Rect::new(size.height, 0, size.width - size.height, size.height);
                    let at = (usize::from(*frame), usize::from(*frames));
                    let _ = render_with(lcd, column, paint::BLACK, &mut band, None, |b| {
                        if let Some(s) = signers {
                            kpub::signer(b, scale, KIT, panel, (s.present, s.required));
                        }
                        kpub::counter(b, scale, KIT, panel, at)
                    });
                }
            } else {
                let _ = lcd.clear(BLACK);
            }
        }
        Screen::Dice { rolled, target } => {
            let (rolled, target) = (usize::from(*rolled), usize::from(*target));
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dice::draw(b, scale, KIT, rolled, target)
            });
        }
        Screen::DiceRefused => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dice::refused(b, scale, KIT)
            });
        }
        Screen::DiceUneven => {
            if let Some(said) = flow.dice_uneven() {
                let (mut first, mut second) = ([0u8; 32], [0u8; 16]);
                let d = dialog::uneven_rolls(said, &mut first, &mut second);
                let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                    dialog::draw(b, scale, KIT, &d, None)
                });
            }
        }
        // The backup check: BACKUP CHECK, CHECK n/3, a failure on the
        // ERROR screen, BACKUP CHECKED.
        Screen::BackupAsk { qr } => {
            let d = dialog::backup_check(*qr);
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &d, None)
            });
        }
        Screen::WordCheck { round, .. } => {
            if let Some((place, offered)) = flow.check_words() {
                let at = (*round, CHECK_ROUNDS);
                let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                    words::check(b, scale, KIT, at, place, offered, None)
                });
            }
        }
        Screen::CheckFailed { qr } => {
            let said = if *qr {
                refusal::NOT_THIS_SEED
            } else {
                refusal::WRONG_WORD
            };
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                refusal::draw(b, scale, KIT, said)
            });
        }
        Screen::BackupChecked => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                words::checked(b, scale, KIT)
            });
        }
        Screen::Bip85 { words, index } => {
            let words = usize::from(*words);
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                bip85::draw(b, scale, KIT, words, index.0)
            });
        }
        Screen::Bip85Index { typed, len } => {
            let typed = core::str::from_utf8(&typed.0[..usize::from(*len)]).unwrap_or("");
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                keypad::draw(b, scale, KIT, keypad::CHILD_TITLE, typed, keypad::HINT)
            });
        }
        Screen::Bip85Deriving => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                loading::draw(b, scale, KIT, loading::DERIVING, 1, 2)
            });
        }
        Screen::KprvDeriving => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                loading::draw(b, scale, KIT, loading::MASTER, 1, 2)
            });
        }
        Screen::KeyDeriving => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                loading::draw(b, scale, KIT, loading::PRIVATE_KEY, 1, 2)
            });
        }
        // Multisig Address's first opening: the bar alone, a step per
        // key worked out.
        Screen::GroupDeriving { done, total } => {
            let area = redraw(fresh, whole, loading::bar_area(scale));
            let _ = render_with(lcd, area, BACKGROUND, &mut band, kept.as_mut(), |b| {
                loading::draw(b, scale, KIT, loading::GROUP_ADDRESS, *done, *total)
            });
        }
        Screen::ShowWords { pos, of } => {
            if let Some(word) = flow.shown_word() {
                let (pos, of) = (usize::from(*pos), usize::from(*of));
                let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                    words::show(b, scale, KIT, pos, of, word)
                });
            }
        }
        Screen::WordCount { action } => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                words::count(b, scale, KIT, action.title())
            });
        }
        Screen::Words {
            action, pos, of, ..
        } => {
            let mut title = [0u8; 24];
            let title = words::title(&mut title, action.heading(), *pos, *of);
            let (text, cursor) = flow.typed();
            let (mode, word) = flow.word_line();
            let line = keyboard::Line {
                text,
                cursor,
                note: None,
                mode,
                word: Some(word),
            };
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                keyboard::draw(b, scale, KIT, title, 0, line)
            });
        }
        Screen::LastWord { of, .. } => {
            if let Some((word, choice, choices)) = flow.last_word() {
                let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                    words::last(b, scale, KIT, *of, word, (choice, choices))
                });
            }
        }
        Screen::ImportExport => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                backup::import_export(b, scale, KIT)
            });
        }
        Screen::StegoCarrier => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                stego::draw(b, scale, KIT)
            });
        }
        Screen::StegoPreview => {
            let d = stego::preview(flow.descriptor());
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &d, None)
            });
        }
        Screen::StegoHintAsk => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &stego::add_hint(), None)
            });
        }
        Screen::StegoHint => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                stego::draw_hints(b, scale, KIT)
            });
        }
        Screen::StegoEmbedding => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                loading::draw(b, scale, KIT, loading::EMBEDDING, 50, 100)
            });
        }
        Screen::StegoDone => {
            let mut shown = [0u8; stego::PHOTO_LINE];
            let photo = stego::photo_line(KIT, scale, flow.photo_shown(), &mut shown);
            let d = stego::done(photo, flow.carrier());
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &d, None)
            });
        }
        Screen::StegoReading => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                loading::draw(b, scale, KIT, loading::READING, 50, 100)
            });
        }
        Screen::StegoFound {
            words,
            carrier,
            two,
        } => {
            let d = stego::found(*words, *carrier, *two);
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &d, None)
            });
        }
        Screen::StegoOverwrite => {
            let mut shown = [0u8; stego::PHOTO_LINE];
            let photo = stego::photo_line(KIT, scale, flow.photo_shown(), &mut shown);
            let d = stego::overwrite(photo);
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &d, None)
            });
        }
        Screen::StegoHintShown => {
            let d = stego::hint_shown(flow.hint());
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &d, None)
            });
        }
        Screen::StegoConfirm { hint } => {
            let mut shown = [0u8; stego::PHOTO_LINE];
            let photo = stego::photo_line(KIT, scale, flow.photo_shown(), &mut shown);
            let d = stego::confirm(photo, flow.carrier(), flow.descriptor(), *hint);
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &d, None)
            });
        }
        Screen::BackupWarning => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                backup::warning(b, scale, KIT)
            });
        }
        Screen::BackupOverwrite { name } => {
            let mut shown = [0u8; 12];
            let n = card::shown_name(&name.0, &mut shown);
            let shown = core::str::from_utf8(&shown[..n]).unwrap_or("");
            let d = dialog::overwrite(shown);
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &d, None)
            });
        }
        Screen::RestoreDelete { name, hold } => {
            let mut shown = [0u8; 12];
            let n = card::shown_name(&name.0, &mut shown);
            let shown = core::str::from_utf8(&shown[..n]).unwrap_or("");
            let d = dialog::delete_backup(shown, *hold);
            // While the hold fills, only its button.
            let area = match (fresh, dialog::zone(scale, dialog::Target::Accept)) {
                (false, Some(z)) => rect(z),
                _ => whole,
            };
            let _ = render_with(lcd, area, BACKGROUND, &mut band, kept.as_mut(), |b| {
                dialog::draw(b, scale, KIT, &d, None)
            });
        }
        Screen::RestoreList { page, extra, .. } => {
            let look = (flow.list_icon(), flow.list_trash());
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                backup::list_with(
                    b,
                    scale,
                    KIT,
                    flow.list_title(),
                    (*page, flow.backups(), flow.long_names()),
                    *extra,
                    look,
                )
            });
        }
        Screen::RestoreOpening { done, total } => {
            let area = redraw(fresh, whole, loading::bar_area(scale));
            let (done, total) = (*done as usize, *total as usize);
            let text = if flow.kdf_wait() {
                loading::DECRYPTING_WAIT
            } else {
                loading::DECRYPTING
            };
            let _ = render_with(lcd, area, BACKGROUND, &mut band, kept.as_mut(), |b| {
                loading::draw(b, scale, KIT, text, done, total)
            });
        }
        Screen::BackupSealing { done, total } => {
            let area = redraw(fresh, whole, loading::bar_area(scale));
            let (done, total) = (*done as usize, *total as usize);
            let text = if flow.kdf_wait() {
                loading::ENCRYPTING_WAIT
            } else {
                loading::ENCRYPTING
            };
            let _ = render_with(lcd, area, BACKGROUND, &mut band, kept.as_mut(), |b| {
                loading::draw(b, scale, KIT, text, done, total)
            });
        }
        Screen::CardBusy(job) => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                sd_card::busy(b, scale, KIT, *job)
            });
        }
        Screen::CardDone { job, outcome } => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                sd_card::done(b, scale, KIT, (*job, *outcome), flow.card_said())
            });
        }
        // The review's pages, then CONFIRM SEND? after the last. A page
        // with no drawing is never reached: its request is refused on
        // arrival. The flow refuses a page it cannot build, or CONFIRM
        // SEND? without its totals, before counting it seen
        // (`Refusal::NotDrawn`); one the panel did not take is told back
        // (`Event::NotDrawn`, in `apply`). Either way the panel is
        // cleared, not left showing part of it or the page before.
        Screen::Page { index, pages } => {
            let drawn = flow.review(|shown| {
                render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                    review::draw(b, scale, KIT, shown, (*index, *pages))
                })
            });
            if drawn != Some(Ok(())) {
                out!("page {}/{} not drawn: {:?}", index + 1, pages, drawn);
                let _ = lcd.clear(BLACK);
                return false;
            }
        }
        Screen::Confirm => {
            let drawn = flow.summary().map(|(totals, counted)| {
                render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                    review::draw_confirm(b, scale, KIT, &totals, &counted)
                })
            });
            if drawn != Some(Ok(())) {
                out!("confirm send? not drawn: {:?}", drawn);
                let _ = lcd.clear(BLACK);
                return false;
            }
        }
        // While the next step plans a request in one call: the bar at
        // half.
        Screen::Checking => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                loading::draw(b, scale, KIT, loading::CHECKING, 1, 2)
            });
        }
        // Likewise while the next step signs.
        Screen::Signing => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                loading::draw(b, scale, KIT, loading::SIGNING, 1, 2)
            });
        }
        Screen::MessageSigning => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                loading::draw(b, scale, KIT, loading::SIGNING_MESSAGE, 1, 2)
            });
        }
        // A failed start-up check: the PANIC screen.
        Screen::Halted(Halt::SelfTest) => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                refusal::panic(b, scale, KIT, refusal::SELF_TEST)
            });
        }
        // The verification screen: version, image hash, fuses' verdict.
        Screen::Verified(check) => {
            let version = env!("CARGO_PKG_VERSION");
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                brand::verification(b, scale, KIT, version, image_hash, check.verdict, None)
            });
        }
        // The ERROR screen, saying why.
        Screen::Refused(why) => {
            let _ = render_with(lcd, whole, BACKGROUND, &mut band, kept.as_mut(), |b| {
                refusal::draw(b, scale, KIT, why.words())
            });
        }
        // Around the viewfinder, which paints itself every frame.
        Screen::Scanning {
            have,
            total,
            received,
            hint,
        } => {
            let mut buf = [0u8; 16];
            let count = camera::scan_counter(*have, *total, &mut buf);
            let note = hint.then_some(camera::SEED_HINT);
            let text = (camera::SCAN, count, note);
            camera_screen(
                lcd,
                scale,
                &mut band,
                text,
                Some((*total, *received)),
                fresh,
            );
        }
        Screen::MessageScan {
            have,
            total,
            received,
        }
        | Screen::BackupScan {
            have,
            total,
            received,
        } => {
            let mut buf = [0u8; 16];
            let count = camera::scan_counter(*have, *total, &mut buf);
            let title = match screen {
                Screen::BackupScan { .. } => camera::CHECK_BACKUP,
                _ => camera::SCAN_TEXT,
            };
            let text = (title, count, None);
            camera_screen(
                lcd,
                scale,
                &mut band,
                text,
                Some((*total, *received)),
                fresh,
            );
        }
        Screen::Generating {
            credited, short, ..
        } => {
            let mut buf = [0u8; 16];
            let count = camera::seed_counter(*credited, &mut buf);
            let text = (camera::NEW_SEED, count, Some(camera::seed_hint(*short)));
            camera_screen(lcd, scale, &mut band, text, None, fresh);
        }
    }
    true
}

/// A camera screen's title, counter and line. A scan (`frames`: how
/// many, which) has its dots or line beside its square, a seed its line
/// below. Unless `fresh`, only the counter and the side or foot.
pub(super) fn camera_screen<L: Display>(
    lcd: &mut L,
    scale: Scale,
    band: &mut [u16],
    (title, count, note): (&str, &str, Option<&str>),
    frames: Option<(usize, u64)>,
    fresh: bool,
) {
    let foot = |b: &mut Band<'_>| match frames {
        Some(frames) => camera::scan_side(b, scale, KIT, note, frames),
        None => {
            if let Some(text) = note {
                camera::note(b, scale, KIT, text);
            }
        }
    };
    let foot_area = match frames {
        Some(_) => camera::side_area(scale),
        None => camera::note_area(scale),
    };
    if fresh {
        let size = lcd.size();
        let whole = Rect::new(0, 0, size.width, size.height);
        let _ = render(lcd, whole, BACKGROUND, band, |b| {
            camera::chrome(b, scale, KIT, title, count, None);
            foot(b);
        });
        return;
    }
    let _ = render(
        lcd,
        rect(camera::counter_area(scale)),
        BACKGROUND,
        band,
        |b| camera::counter(b, scale, KIT, count),
    );
    if note.is_some() || frames.is_some_and(|(total, _)| total > 0) {
        let _ = render(lcd, rect(foot_area), BACKGROUND, band, foot);
    }
}

/// `first 225 addresses.`, written into `out`.
pub(super) fn checked_line(checked: usize, out: &mut [u8; 32]) -> &str {
    let mut digits = [0u8; 20];
    let (mut v, mut i) = (checked, digits.len());
    loop {
        i -= 1;
        digits[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let mut n = 0;
    for part in [b"first ".as_slice(), &digits[i..], b" addresses."] {
        out[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    core::str::from_utf8(&out[..n]).unwrap_or("")
}

/// A screen's zone as the panel's rectangle.
pub(super) fn rect(z: kassigner_fw::touch::Zone) -> Rect {
    Rect::new(z.x, z.y, z.width, z.height)
}

/// What a redraw covers: the whole screen when it is new, else `zone`.
pub(super) fn redraw(fresh: bool, whole: Rect, zone: kassigner_fw::touch::Zone) -> Rect {
    if fresh {
        whole
    } else {
        rect(zone)
    }
}

/// One choice's line on a format screen: its code count, or too large
/// when its frames are more than a unit reassembles.
pub(super) fn hint<'o>(
    fits: bool,
    what: &str,
    codes: impl FnOnce() -> usize,
    out: &'o mut [u8; 24],
) -> &'o str {
    if fits {
        kpub::codes_hint(what, codes(), out)
    } else {
        refusal::TOO_LARGE
    }
}

/// Say on the console what the screen shows, never a seed's words. A
/// `diag` build's only.
pub(super) fn say(flow: &Flow<'_, SLOTS>, screen: &Screen) {
    match screen {
        Screen::Page { index, pages } => {
            let _ = flow.page(|p| diag!("page {}/{}: {p:?}", index + 1, pages));
            diag!("  left: back   right: next   back/home: cancel");
        }
        Screen::Checking => diag!("checking"),
        Screen::Signing => diag!("signing"),
        Screen::MessageSigning => diag!("signing the message"),
        Screen::Confirm => {
            if let Some((t, c)) = flow.summary() {
                diag!(
                    "confirm send? out {} in {} fee {} sompi; {} in, {} out",
                    t.out,
                    t.spent,
                    t.fee,
                    c.inputs,
                    c.outputs
                );
                if let Some((m, n)) = c.group {
                    diag!("  {m}-of-{n} multisig");
                }
            }
            diag!("  CONFIRM: sign   CANCEL, back, home: cancel   left: last page");
        }
        Screen::Generating {
            credited,
            share,
            short,
        } => diag!("seed: {credited} bits, {share} needed from each; short: {short:?}"),
        other => diag!("{other:?}"),
    }
}

/// Draw a code, noting the depth first for the scrub: a code can be a
/// SeedQR, and this panel path is a seed flow's deepest.
pub(super) fn draw_code<L: Display>(lcd: &mut L, scale: Scale, code: &qr::QrMatrix) {
    wipe::note_depth();
    paint::draw_code(lcd, code, margin(scale));
}

/// [`MARGIN`] on this panel.
pub(super) fn margin(scale: Scale) -> u16 {
    u16::try_from(scale.len(MARGIN)).unwrap_or(0)
}
