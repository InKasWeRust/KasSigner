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

//! Carrying out what the flow asks: a decoded code delivered, a step's
//! output applied, its command carried out.

use super::*;

/// A decoded code: a framed one to the reassembler, its payload to the
/// flow once complete; a bare one to the flow as a code.
pub(super) fn deliver<L, C, D, T>(
    bytes: &[u8],
    payload: &mut [u8],
    unit: &mut unit::Unit<L, C, D, T>,
    flow: &mut Flow<'_, SLOTS>,
    io: &mut Io<'_>,
) where
    L: Display,
    C: Camera,
    D: Decoder,
    T: Touch,
{
    match io.scan.offer(bytes) {
        // Not a request in any framing: a SeedQR, or something else.
        Ok(Step::NotOurs) => {
            let out = flow.step(Event::Code(bytes), &mut unit.rng);
            apply(out, unit, flow, io);
        }
        // A request in one code with no frame header, as v1.0.7 units
        // read it.
        Ok(Step::Whole) => {
            let out = flow.step(Event::Payload(bytes), &mut unit.rng);
            apply(out, unit, flow, io);
        }
        Ok(Step::Accepted { have, need, .. }) => {
            if have == 1 {
                io.read_from = Some((unit.timer.now_us(), need));
            }
            let received = io.scan.received();
            let out = flow.step(
                Event::Progress {
                    have,
                    total: need,
                    received,
                },
                &mut unit.rng,
            );
            apply(out, unit, flow, io);
        }
        // Text in frames is Sign Message's; anything else a request or
        // a kpub.
        Ok(Step::Complete { format, len }) => {
            match io.read_from.take() {
                Some((from, frames)) => diag!(
                    "read: {} frames, {} bytes of {:?}, {} ms from the first",
                    frames,
                    len,
                    format,
                    unit.timer.now_us().saturating_sub(from) / 1000
                ),
                None => diag!("read: one frame, {} bytes of {:?}", len, format),
            }
            if let Ok(n) = io.scan.collect(payload) {
                let bytes = &payload[..n];
                let event = if format == frame::Format::Opaque {
                    Event::Opaque(bytes)
                } else {
                    Event::Payload(bytes)
                };
                // A request is planned on the next tick, under CHECKING.
                let out = flow.step(event, &mut unit.rng);
                apply(out, unit, flow, io);
                wipe::wipe(&mut payload[..n]);
            }
            io.scan.reset();
            settle_scan(io);
        }
        Ok(Step::Duplicate) => {}
        // A v1.0.7 set's last frame, or maybe a compact SeedQR: the flow
        // counts how long it is read alone.
        Ok(Step::LastFrameOrSeed { .. }) => {
            let out = flow.step(Event::LastFrameOrSeed, &mut unit.rng);
            apply(out, unit, flow, io);
        }
        Ok(other) => diag!("frame: {other:?}"),
        Err(e) => diag!("frame refused: {e:?}"),
    }
}

/// Apply one step's answer: the command now, the screen if it changed.
///
/// A review page or CONFIRM SEND? the panel did not take is told to the
/// flow at once and its refusal drawn: told later, a tap could land on a
/// page counted seen, or on CONFIRM, that the panel does not show.
pub(super) fn apply<L, C, D, T>(
    out: Output,
    unit: &mut unit::Unit<L, C, D, T>,
    flow: &mut Flow<'_, SLOTS>,
    io: &mut Io<'_>,
) where
    L: Display,
    C: Camera,
    D: Decoder,
    T: Touch,
{
    #[cfg(feature = "p4")]
    reset_cut(unit, flow, io);
    if !carry_out(out, unit, flow, io) {
        let out = flow.step(Event::NotDrawn, &mut unit.rng);
        // A refusal is not a review screen: this one does not come back.
        let _ = carry_out(out, unit, flow, io);
    }
}

/// The P4's reset button a power cut while the flow holds a secret, the
/// idle wipe's measure, and a plain reset otherwise: the USB bridge's
/// auto-reset pulls the same line, and the cut takes the bridge down
/// with the unit. Run before each step's screen is drawn, so the cut is
/// on before a secret reaches the panel; a write the bus or the PMU
/// refused is tried again at the next step.
#[cfg(feature = "p4")]
pub(super) fn reset_cut<L, C, D, T>(
    unit: &unit::Unit<L, C, D, T>,
    flow: &Flow<'_, SLOTS>,
    io: &mut Io<'_>,
) {
    let want = flow.holds_secret();
    if want != io.reset_cut && unit.reset_cuts_power(want) {
        io.reset_cut = want;
    }
}

/// [`apply`]'s work, once (never inlined: `apply` calls it twice). False
/// for a review page or CONFIRM SEND? that missed the panel ([`draw`]).
#[inline(never)]
pub(super) fn carry_out<L, C, D, T>(
    out: Output,
    unit: &mut unit::Unit<L, C, D, T>,
    flow: &Flow<'_, SLOTS>,
    io: &mut Io<'_>,
) -> bool
where
    L: Display,
    C: Camera,
    D: Decoder,
    T: Touch,
{
    let mut whole = true;
    // The sound this step earns, judged against the screen before it.
    let cue = cues::for_step(&io.shown, &out.screen, io.tapped, out.command.is_some());
    let clicked = cues::clicks(&io.shown, &out.screen, io.tapped, out.command.is_some());
    let changed = out.screen != io.shown;
    io.tapped = false;
    // The busy tick, which the M5 and the P4 play from a ring on their
    // own while the processor works or the card has the bus; the
    // Waveshare is silent. It stops here, before the cue that ends the
    // job, and starts below, after the tap's click, which ends in silence
    // and would cut it off.
    let busy = |s: &Screen| {
        matches!(
            s,
            Screen::Opening { .. }
                | Screen::Checking
                | Screen::Signing
                | Screen::MessageSigning
                | Screen::BackupSealing { .. }
                | Screen::RestoreOpening { .. }
                | Screen::StegoEmbedding
                | Screen::StegoReading
                | Screen::Searching { .. }
                | Screen::SavingsSearching { .. }
                | Screen::CardBusy(Job::Write | Job::Read | Job::Test | Job::Format)
        )
    };
    let (was_busy, now_busy) = (busy(&io.shown), busy(&out.screen));
    if was_busy && !now_busy {
        unit.speaker.stop_ticking();
    }
    // A tap that did something clicks at once, before the command and
    // the screen: a click heard after the work feels laggy.
    let tap_us = io.tap_said.map(|(_, _, at)| at);
    let click_us = tap_us.map(|at| unit.timer.now_us().saturating_sub(at));
    if clicked {
        cues::start(&mut unit.speaker, cues::Cue::Click);
    }
    if out.command == Some(Command::Deferred) {
        io.deferred_from = tap_us;
    }
    match out.command {
        Some(Command::CameraOn) => {
            io.camera_on = true;
            io.no_frames = 0;
            io.scan.reset();
            io.sighting.reset();
        }
        Some(Command::CameraOff) => {
            io.camera_on = false;
            io.sighting.reset();
            unit.dec.cancel();
            // The frames go with it: one may hold a SeedQR.
            unit.cam.clear();
            io.scan.reset();
            settle_scan(io);
            io.scan_ended = true;
        }
        Some(Command::SamplesOn) => {
            io.samples_on = true;
            io.no_frames = 0;
        }
        Some(Command::SamplesOff) => {
            io.samples_on = false;
            io.samples_ended = true;
            // The frames the bands were taken from go with them, unless
            // the scanner has the camera.
            if !io.camera_on {
                unit.cam.clear();
            }
        }
        Some(Command::CloseConsole) => {
            out!("console closing: a provisioned unit goes quiet from here");
            CONSOLE_OPEN.store(false, Ordering::Relaxed);
            Port.close();
        }
        Some(Command::Backlight(level)) => {
            if let Err(e) = unit.lcd.set_backlight(Backlight::Level(level)) {
                out!("backlight {level}: {e:?}");
            }
        }
        Some(Command::Volume(level)) => {
            unit.speaker.set_volume(level);
            diag!("volume {level}");
        }
        Some(Command::TuneOn) => {
            io.tuning = true;
            io.tune_read = true;
            io.no_frames = 0;
        }
        Some(Command::TuneOff) => {
            io.tuning = false;
            unit.cam.clear();
        }
        // Each change is printed with the register's new value, so a good
        // setting can be copied into the board's tables.
        Some(Command::Tune { knob, value }) => {
            if let Some(mut t) = tuner(unit) {
                let label = t.knobs().get(knob).map_or("?", |k| k.label);
                match t.write(knob, value) {
                    Ok(()) => diag!("camera {label} = {value:#04x}"),
                    Err(e) => diag!("camera {label}: {e:?}"),
                }
            }
            io.tune_read = true;
        }
        Some(Command::TuneAuto(on)) => {
            if let Some(mut t) = tuner(unit) {
                match t.set_auto(on) {
                    Ok(()) => diag!("camera exposure loop {}", if on { "on" } else { "off" }),
                    Err(e) => diag!("camera exposure loop: {e:?}"),
                }
            }
            io.tune_read = true;
        }
        // Run by the loop once this step's screen is drawn.
        Some(Command::Card(job)) => io.card_job = Some(job),
        // The tap's work waits for the next tick; only its click now.
        Some(Command::Deferred) => {}
        None => {}
    }
    // The Waveshare's camera streams only while a screen uses it:
    // streaming throughout runs the unit hot.
    #[cfg(feature = "waveshare")]
    {
        let wanted = io.camera_on || io.tuning || io.samples_on;
        if wanted != io.camera_awake {
            use kassigner_hal::camera::Power;
            use kassigner_hal_esp32s3::waveshare::sensor;
            // Register writes go to an awake sensor: into software
            // standby before the power-down pin rises, out once it has
            // fallen and the camera has waited. The datasheet does not
            // say a sensor in hardware standby answers on its bus (2.9).
            if wanted {
                let _ = unit.cam.set_power(Power::On);
                let _ = sensor::standby(&mut unit.cam_i2c, false);
            } else {
                let _ = sensor::standby(&mut unit.cam_i2c, true);
                let _ = unit.cam.set_power(Power::Off);
            }
            io.camera_awake = wanted;
            diag!("camera {}", if wanted { "awake" } else { "asleep" });
        }
    }
    // The click plays while the screen draws; other cues follow the
    // screen.
    if out.screen != io.shown {
        // A new screen is drawn whole, the same screen only where its
        // numbers changed. A scan's hint line, its first frame (for the
        // dots) and a dropped transmission count as new screens.
        let fresh = discriminant(&out.screen) != discriminant(&io.shown)
            || match (&io.shown, &out.screen) {
                (
                    Screen::Scanning {
                        hint: was,
                        total: t,
                        ..
                    },
                    Screen::Scanning {
                        hint: now,
                        total: u,
                        ..
                    },
                ) => was != now || (*t == 0) != (*u == 0),
                (Screen::MessageScan { total: t, .. }, Screen::MessageScan { total: u, .. })
                | (Screen::BackupScan { total: t, .. }, Screen::BackupScan { total: u, .. }) => {
                    (*t == 0) != (*u == 0)
                }
                _ => false,
            };
        // How long opening a wallet took. A match of its own: the one
        // below has an arm for an opening that ends at Menu (a group's
        // key), which must still run.
        match (&io.shown, &out.screen) {
            (Screen::Opening { .. }, Screen::Opening { .. }) => {}
            (_, Screen::Opening { .. }) => io.search_from = io.now_us,
            (Screen::Opening { .. }, _) => {
                diag!("unlock: {} ms", unit.timer.since(io.search_from) / 1000)
            }
            _ => {}
        }
        // Bench timings, each from its screen coming up to the next.
        match (&io.shown, &out.screen) {
            (Screen::BackupSealing { .. }, Screen::BackupSealing { .. }) => {}
            (_, Screen::BackupSealing { .. }) => io.search_from = io.now_us,
            (Screen::BackupSealing { .. }, _) => {
                diag!("seal: {} ms", unit.timer.since(io.search_from) / 1000)
            }
            (Screen::RestoreOpening { .. }, Screen::RestoreOpening { .. }) => {}
            (_, Screen::RestoreOpening { .. }) => io.search_from = io.now_us,
            (Screen::RestoreOpening { .. }, _) => {
                diag!("open: {} ms", unit.timer.since(io.search_from) / 1000)
            }
            // Hiding the backup in the photo, its check included.
            (Screen::StegoEmbedding, Screen::StegoEmbedding) => {}
            (_, Screen::StegoEmbedding) => io.search_from = io.now_us,
            (Screen::StegoEmbedding, _) => {
                diag!("embed: {} ms", unit.timer.since(io.search_from) / 1000)
            }
            (Screen::StegoReading, Screen::StegoReading) => {}
            (_, Screen::StegoReading) => io.search_from = io.now_us,
            (Screen::StegoReading, _) => {
                diag!("unhide: {} ms", unit.timer.since(io.search_from) / 1000)
            }
            // Planning a request; the screen after is timed from then.
            (Screen::Checking, Screen::Checking) => {}
            (_, Screen::Checking) => io.search_from = io.now_us,
            (Screen::Checking, _) => {
                diag!("plan: {} ms", unit.timer.since(io.search_from) / 1000);
                io.search_from = io.now_us;
            }
            (Screen::Searching { .. }, Screen::Searching { .. }) => {}
            (_, Screen::Searching { .. }) => io.search_from = io.now_us,
            (Screen::Searching { done, .. }, _) => diag!(
                "search: {} keys in {} ms",
                done,
                unit.timer.since(io.search_from) / 1000
            ),
            (Screen::SavingsSearching { .. }, Screen::SavingsSearching { .. }) => {}
            (_, Screen::SavingsSearching { .. }) => io.search_from = io.now_us,
            (Screen::SavingsSearching { at, .. }, _) => diag!(
                "card search: to #{} in {} ms",
                at,
                unit.timer.since(io.search_from) / 1000
            ),
            (Screen::Signing, Screen::Signing) => {}
            (_, Screen::Signing) => io.search_from = io.now_us,
            (Screen::Signing, _) => {
                diag!("sign: {} ms", unit.timer.since(io.search_from) / 1000)
            }
            // A group made or loaded: its M of N and every key, with the
            // seed each came from and the seed in use marked.
            (
                Screen::Scanning { .. } | Screen::SelectSeed { .. } | Screen::Opening { .. },
                Screen::Menu { .. },
            )
            | (Screen::LoadGroup { .. }, Screen::Descriptor { .. }) => {
                if let Some(group) = flow.group() {
                    diag!("multisig: {}-of-{} held", group.required(), group.total());
                    let own = flow.group_position();
                    let mut text = [0u8; 128];
                    for i in 0..group.total() {
                        let Some(kpub) = flow.group_key_text(i, &mut text) else {
                            continue;
                        };
                        let in_use = if own == Some(i) { " (seed in use)" } else { "" };
                        match flow.group_seed(i) {
                            Some(f) => diag!(
                                "  {i}: {kpub} (seed {:02x}{:02x}{:02x}{:02x}){in_use}",
                                f[0],
                                f[1],
                                f[2],
                                f[3]
                            ),
                            None => diag!("  {i}: {kpub}{in_use}"),
                        }
                    }
                }
            }
            _ => {}
        }
        io.shown = out.screen;
        // Home's battery, read as Home is drawn.
        let battery = match io.shown {
            Screen::Home => home_battery(unit),
            _ => None,
        };
        io.gauge = battery;
        io.gauge_read = unit.timer.now_us();
        // Timed, with the panel's share, so a slow redraw says whether
        // drawing or transfer is slow.
        let start = unit.timer.now_us();
        let mut timed = Timed {
            lcd: &mut unit.lcd,
            timer: &unit.timer,
            panel_us: 0,
        };
        whole = draw(
            &mut timed,
            flow,
            &io.shown,
            fresh,
            battery,
            io.image_hash.as_ref(),
            &mut io.kept,
        );
        if fresh {
            let panel = timed.panel_us;
            diag!(
                "redraw: {} ms, {} of them sending to the panel",
                unit.timer.since(start) / 1000,
                panel / 1000
            );
        }
        // A screen with a secret left it below this frame (the band as
        // pixels, the encoder's scratch, the glyphs' copies); `draw` has
        // returned, so all of it is under the scrub. The display's
        // transfer buffer (15 KB on the P4, 512 bytes on the S3s) is not
        // scrubbed: the next screen, drawn whole through it, replaces
        // every byte, and until then the secret is on the panel anyway.
        if io.shown.shows_secret() {
            let start = unit.timer.now_us();
            let frames = wipe::scrub_flow();
            diag!("scrub: {} frames, {} us", frames, unit.timer.since(start));
        }
        if cfg!(feature = "diag") {
            say(flow, &io.shown);
        }
    }
    // Home's battery, read every two seconds while Home stays up, its
    // zone redrawn when it changes, so a charging cell's figure moves.
    if io.shown == Screen::Home && unit.timer.since(io.gauge_read) >= GAUGE_EVERY_US {
        io.gauge_read = unit.timer.now_us();
        let battery = Gauge::after(io.gauge, home_battery(unit));
        if battery != io.gauge {
            io.gauge = battery;
            draw(
                &mut unit.lcd,
                flow,
                &io.shown,
                false,
                battery,
                io.image_hash.as_ref(),
                &mut io.kept,
            );
        }
    }
    // After the screen, so what is heard follows what is seen. Timed.
    let start = unit.timer.now_us();
    if clicked {
        cues::finish(&mut unit.speaker);
    }
    match cue {
        Some(cues::Cue::Click) | None => {}
        // Already greeted by the sighting's tick.
        Some(cues::Cue::CodeFound) if io.sight_ticked => {}
        Some(cue) => cues::play(&mut unit.speaker, cue),
    }
    if let Some(cue) = cue {
        diag!("cue {:?}: {} ms", cue, unit.timer.since(start) / 1000);
    }
    if now_busy && !was_busy {
        cues::start_ticking(&mut unit.speaker);
    }
    // The tap, said now that its click and screen are done; a deferred
    // one says, on its tick, when its screen was drawn.
    if let Some((reports, over_ms, _)) = io.tap_said.take() {
        match (clicked, click_us) {
            (true, Some(us)) => {
                diag!("tap: {reports} reports over {over_ms} ms; click {us} us after it")
            }
            _ => diag!("tap: {reports} reports over {over_ms} ms; no click"),
        }
    } else if out.command.is_none() && changed {
        if let Some(at) = io.deferred_from.take() {
            diag!(
                "deferred: its screen drawn {} ms after the tap",
                unit.timer.since(at) / 1000
            );
        }
    }
    whole
}
