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

//! The device build: the drivers, the flow and the loop between them.

extern crate alloc;

use core::mem::discriminant;
use core::sync::atomic::{AtomicBool, Ordering};
use esp_hal::clock::CpuClock;
use esp_hal::main;

use esp_println::println;

use kassigner_crypto::seed::Words;
use kassigner_fw::card::{self, Job, Request};
use kassigner_fw::cues;
use kassigner_fw::flow::{
    Buffers, Command, Config, Event, Flow, Halt, Output, Screen, CHECK_ROUNDS,
};
use kassigner_fw::paint::{self, BLACK};
use kassigner_fw::scan::{Scan, Step};
use kassigner_fw::seed::Source;
use kassigner_fw::selftest;
use kassigner_fw::sizes::Sizes;
use kassigner_fw::touch::{Action, Tracker};
use kassigner_fw::ui::band::{render, render_with, Band, Stretched};
use kassigner_fw::ui::brand::Gauge;
use kassigner_fw::ui::color::BACKGROUND;
use kassigner_fw::ui::menu::Menu;
use kassigner_fw::ui::scale::{Kit, Scale};
use kassigner_fw::ui::{
    address, backup, bip85, brand, camera, camtune, chrome, dialog, dice, keyboard, keypad, kpub,
    loading, menu, multisig, refusal, review, savings, sd_card, seedqr, seeds, settings, stego,
    words,
};
use kassigner_fw::wipe;
use kassigner_hal::camera::Camera;
use kassigner_hal::decoder::{Attempt, Decoder, Outcome};
use kassigner_hal::display::{Backlight, Display, Rect};
use kassigner_hal::input::Touch;
use kassigner_hal::provisioning::{Console, Provisioning, DIGEST_SLOTS};
use kassigner_hal::speaker::Speaker;
use kassigner_hal::timer::Timer;
use kassigner_hal::tune::{Tune, MAX_KNOBS};
use kassigner_protocol::frame;
use kassigner_protocol::kspt::InputSignature;
use kassigner_protocol::stego::picture::Tables;
use kassigner_qr::encode as qr;

// ── The board-dependent lines ────────────────────────────────────────
#[cfg(feature = "p4")]
use kassigner_hal_esp32p4::{
    console::Uart0 as Port, efuse, image, memory, psram, stack, unit, watchdog::Watchdog, CAPACITY,
    PROFILE,
};
#[cfg(feature = "m5stack")]
use kassigner_hal_esp32s3::m5stack::{imu, unit, CAPACITY, PROFILE};
#[cfg(feature = "waveshare")]
use kassigner_hal_esp32s3::waveshare::{imu, unit, CAPACITY, PROFILE};
#[cfg(any(feature = "m5stack", feature = "waveshare"))]
use kassigner_hal_esp32s3::{
    cache, console::UsbSerialJtag as Port, efuse, image, memory, stack, systimer::SysTimer,
    watchdog::Watchdog,
};

// The descriptor the second-stage bootloader needs to boot the image.
esp_bootloader_esp_idf::esp_app_desc!();

/// Every buffer's size, from what this board reports.
const SIZES: Sizes = Sizes::new(&CAPACITY, &PROFILE);

/// How often the touch panel is read while a camera frame is on its way:
/// enough to see a tap begin and end, at no cost to the capture.
const TOUCH_POLL_US: u64 = 2_000;

/// Seconds the loop may go without a pass before the watchdog resets
/// the chip: above the longest job that cannot say it is alive, the P4's
/// Argon2id at about 26 s. A card job says so on every transfer
/// (`card::Alive`): formatting a 32 GB card takes 35.6 s on the M5, a
/// larger one longer than this.
const WATCHDOG_S: u64 = 60;

/// Missed frames in a row, a second's wait each, before the flow is told
/// the camera is lost: one slow frame is not a dead camera.
const CAMERA_LOST_AFTER: u8 = 3;

/// The least white round a drawn code, in design pixels (scaled on the
/// P4). The 3.5 modules `paint` keeps exceed it for every code made.
const MARGIN: i32 = 10;

/// Seed slots: [`kassigner_fw::limits::SLOTS`].
const SLOTS: usize = kassigner_fw::limits::SLOTS;

/// The version, as the logo screen shows it.
const VERSION: &str = concat!("v", env!("CARGO_PKG_VERSION"));

/// Rows a band holds, and the widest row this unit draws: the panel's.
const BAND_ROWS: usize = 16;
#[cfg(feature = "p4")]
const BAND_WIDTH: usize = 480;
#[cfg(not(feature = "p4"))]
const BAND_WIDTH: usize = 320;

/// The fonts and icons for this unit's panel, chosen at build time so
/// the other set stays out of the image.
#[cfg(feature = "p4")]
static KIT: &Kit = &kassigner_fw::ui::scale::LARGE;
#[cfg(not(feature = "p4"))]
static KIT: &Kit = &kassigner_fw::ui::scale::SMALL;

/// This unit's settings: all but Audio on the Waveshare, which has no
/// speaker.
#[cfg(any(feature = "m5stack", feature = "p4"))]
static SETTINGS: &Menu = &menu::SETTINGS;
#[cfg(feature = "waveshare")]
static SETTINGS: &Menu = &menu::SETTINGS_NO_AUDIO;

/// How often Home's battery is read again while Home stays up.
const GAUGE_EVERY_US: u64 = 2_000_000;

/// The backlight level the bring-up leaves: the board's default.
const BACKLIGHT: u8 = unit::DEFAULT_BRIGHTNESS;

/// The starting volume, 0 to 255: 8% on the M5Stack, 50% on the P4.
#[cfg(feature = "m5stack")]
const VOLUME: u8 = kassigner_hal_esp32s3::m5stack::speaker::DEFAULT_VOLUME;
#[cfg(feature = "p4")]
const VOLUME: u8 = kassigner_hal_esp32p4::speaker::DEFAULT_VOLUME;
#[cfg(feature = "waveshare")]
const VOLUME: u8 = 0;

/// Pixels kept for the P4's stretched pictures (192 KB of PSRAM): all
/// screens' pictures together come to about 44,000, as a UI test counts.
#[cfg(feature = "p4")]
const STRETCHED_PIXELS: usize = 96_000;

/// A camera sample for the seed: a band of the frame, one byte in every
/// few, as deltas against the last band, as its entropy credit was
/// measured.
const SEED_SAMPLE: usize = 512;

/// One IMU chunk for the seed, three axes interleaved.
#[cfg(any(feature = "m5stack", feature = "waveshare"))]
const IMU_CHUNK: usize = 192;

/// How long a seed the unit makes.
const WORDS: Words = Words::Twelve;

/// Whether the console is open. Cleared on [`Command::CloseConsole`]:
/// with the pads off, a write would sit in a FIFO nobody drains.
static CONSOLE_OPEN: AtomicBool = AtomicBool::new(true);

/// `println!` while the console is open: the boot, the checks, what
/// went wrong.
macro_rules! out {
    ($($t:tt)*) => {
        if CONSOLE_OPEN.load(Ordering::Relaxed) {
            println!($($t)*);
        }
    };
}

/// [`out!`] in a `diag` build only (`m5-diag`, `ws-diag`, `p4-diag`):
/// measurements and what the user is doing, screen by screen, kpubs and
/// codes read, which a shipping build never says. A branch on a
/// constant, so the arguments count as used and the text is dropped.
macro_rules! diag {
    ($($t:tt)*) => {
        if cfg!(feature = "diag") {
            out!($($t)*);
        }
    };
}

/// What the flow is told at boot, board by board the same.
struct Checks {
    /// Every start-up check passed.
    ok: bool,
    /// The gyro runs, so the seed counts it.
    imu: bool,
}

mod act;
mod board;
mod drawing;
mod input;

use act::*;
use board::*;
use drawing::*;
use input::*;

/// What the loop keeps between passes besides the drivers and the flow.
struct Io<'s> {
    scan: Scan<'s>,
    shown: Screen,
    camera_on: bool,
    samples_on: bool,
    /// The tuning screen's camera: the viewfinder, no decoding.
    tuning: bool,
    /// The camera's settings are to be read and reported.
    tune_read: bool,
    /// A job for the card, run once the screen that says so is up.
    card_job: Option<Job>,
    /// A scan ended: what it read, below `run`'s frame, is scrubbed at
    /// the top of the next pass.
    scan_ended: bool,
    /// A seed stopped taking camera samples: the bands in `run`'s frame
    /// are wiped at the top of the next pass.
    samples_ended: bool,
    /// Frames missed in a row.
    no_frames: u8,
    /// The event being stepped is a tap (one that did something clicks).
    tapped: bool,
    /// The tap being stepped (panel reports, length in ms, when), said
    /// once its click has started so the print does not delay it.
    tap_said: Option<(u32, u64, u64)>,
    /// When a tap whose work waits for the next tick was taken.
    deferred_from: Option<u64>,
    /// Whether a code has been in view lately, for the scan's edge and
    /// the tick that greets a code.
    sighting: camera::Sighting,
    /// The code being delivered was greeted with the tick this pass, so
    /// it does not tick twice.
    sight_ticked: bool,
    /// The panel's reports of the touch under way.
    touch_seen: Seen,
    /// The P4's pictures, stretched to its panel once and kept (stretching
    /// on every redraw was half of Home's drawing time). None on the S3s.
    kept: Option<Stretched>,
    /// Whether the Waveshare's sensor is out of standby and streaming.
    #[cfg(feature = "waveshare")]
    camera_awake: bool,
    /// Whether the P4's reset button cuts the power: off from boot, on
    /// while the flow holds a secret ([`reset_cut`]).
    #[cfg(feature = "p4")]
    reset_cut: bool,
    now_us: u64,
    /// When the screen being timed for the bench opened.
    search_from: u64,
    /// The battery Home shows, and when it was last read.
    gauge: Option<Gauge>,
    gauge_read: u64,
    /// The start of the running image's hash, for the verification
    /// screen; none if it could not be read.
    image_hash: Option<[u8; brand::HASH_SHOWN]>,
    /// When the first frame of the transmission being read arrived, and
    /// how many it has, to time the read.
    read_from: Option<(u64, usize)>,
    /// The frames' and the payload's buffers in PSRAM, whose wipes are
    /// written back out of the cache when a scan ends (`settle_scan`).
    #[cfg(any(feature = "m5stack", feature = "waveshare"))]
    scan_regions: [cache::Region; 2],
}

/// The photo's Huffman tables for the Picture carrier, on the heap. In
/// a frame of its own: the 9.6 KB value may sit on the stack while it is
/// copied out, but never in `run`'s frame.
#[inline(never)]
fn jpeg_tables() -> alloc::boxed::Box<Tables> {
    alloc::boxed::Box::new(Tables::EMPTY)
}

/// Clears the main stack below this frame, then runs [`run`].
///
/// A reset short of a power cut keeps the stack, and the last run's
/// flow, seed slots included, sat in the frame `run` takes again. This
/// frame is small, so all of that lies below it. PSRAM is cleared in
/// `heap::make`.
#[main]
fn main() -> ! {
    // The P4's backlight dark before anything else: the panel may still
    // hold the last screen.
    #[cfg(feature = "p4")]
    kassigner_hal_esp32p4::backlight::dark_at_reset();
    let _ = stack::clear_at_boot(wipe::SCRUB_FLOOR_MARGIN);
    run()
}

/// The program: bring-up, the checks, then the loop, for good.
#[inline(never)]
fn run() -> ! {
    // The stack probe paints the main stack's free part before use. The S3
    // units' only, as its report below: a P4 probe build is refused.
    #[cfg(all(
        feature = "stackprobe",
        any(feature = "m5stack", feature = "waveshare")
    ))]
    stack::probe::paint(wipe::SCRUB_FLOOR_MARGIN);
    let peripherals = esp_hal::init(esp_hal::Config::default().with_cpu_clock(CpuClock::max()));
    out!("KasSigner {}", super::UNIT);
    out!("reset: {:?}", esp_hal::system::reset_reason());

    // ── The board, its external RAM made the heap first ──────────────
    //
    // `heap::make` runs inside `bring_up` before anything allocates.
    // The Waveshare's frame and job buffers and the P4's camera frame are
    // in PSRAM (`kassigner_hal_esp32p4::cam` says why); the P4's decoder
    // plane stays in L2MEM. `heap.rs` sets up each unit's PSRAM.
    let up = bring_up(peripherals, super::heap::make);
    let (mut unit, checks) = match up {
        Ok(up) => up,
        Err(unit::Failed { error, panel }) => {
            out!("HALT: the board did not come up: {error:?}");
            // The PANIC screen, if the panel came up. Held to the end:
            // dropped, its pins would let go, and the screen with them.
            let _panel = panel.map(|mut lcd| {
                draw_halt(&mut lcd, halt_reason(&error));
                lcd
            });
            loop {
                core::hint::spin_loop();
            }
        }
    };
    // Reseed the generator before anything draws from it. Moved here by
    // value from `bring_up`, it left a copy of its key in each frame it
    // passed through, where its `Drop` never reaches; such a copy
    // predicts every byte until the first reseed. A failed reseed
    // poisons the generator and fails the self-test.
    let reseeded = match unit.rng.reseed_now() {
        Ok(()) => true,
        Err(e) => {
            out!("generator: reseed failed: {e:?}");
            false
        }
    };
    // The speaker at the level the flow starts with.
    unit.speaker.set_volume(VOLUME);
    // The fuses, read once: the verdict, then every fuse that matters,
    // each digest slot and key block, printed before the self-test so a
    // unit that halts there has said them first.
    let fuses = efuse::Fuses.read();
    let verdict = fuses.verdict();
    out!("{}", verdict.line());
    for line in fuses.lines() {
        out!("eFuse  {line}");
    }
    for k in 0..DIGEST_SLOTS {
        out!("eFuse  digest slot {k}: {}", fuses.slot(k));
    }
    for (i, key) in fuses.keys.iter().enumerate() {
        out!("eFuse  KEY{i}: {key}");
    }

    // The logo while the self-test runs.
    draw_logo(&mut unit.lcd);

    // The running image's hash for the verification screen: the unsigned
    // `.bin`'s SHA-256, read from flash, its appended digest checked on
    // the way (`kassigner_hal::image`).
    let hash_from = unit.timer.now_us();
    let (hashed, at) = match image::Running::find() {
        Some(mut running) => (kassigner_hal::image::hash(&mut running), running.start()),
        None => (Err(kassigner_hal::image::Error::NotFound), 0),
    };
    let hash_us = unit.timer.since(hash_from);
    let shown_hash = match hashed {
        Ok(hashed) => {
            out!("image at {at:#x}: {hashed}, read in {hash_us} us");
            Some(brand::shown(&hashed.sha256))
        }
        Err(e) => {
            out!("image: not read: {e:?}");
            None
        }
    };

    // ── The boot self-test ───────────────────────────────────────────
    //
    // Before anything touches a seed: the chip's arithmetic, its RAM and
    // the known answers, each timed. Internal RAM is tested in a fresh
    // array on this stack, PSRAM in a fresh heap allocation, both handed
    // back zeroed.
    //
    // A failed line halts the unit, blank or provisioned, after the full
    // report prints: a wrong known answer means the chip cannot be
    // trusted to derive or sign. Fuses only say how a unit was
    // provisioned, which the verification screen shows.
    let selftest_ok = {
        let mut stack_words = [0u32; selftest::INTERNAL_WORDS];
        let mut psram_words = alloc::vec![0u32; selftest::PSRAM_WORDS];
        // Argon2id's known answer on the P4, the one unit that uses it:
        // 32 KiB from the heap, no secret, handed back wiped.
        #[cfg(feature = "p4")]
        let mut argon2_blocks = alloc::vec![
            kassigner_crypto::container::Argon2Block::new();
            kassigner_crypto::kat::ARGON2ID_BLOCKS
        ];
        #[cfg(feature = "p4")]
        let argon2 = Some(&mut argon2_blocks[..]);
        #[cfg(not(feature = "p4"))]
        let argon2 = None;
        let report = selftest::run(
            &unit.timer,
            &mut memory::Volatile::new(&mut stack_words),
            &mut memory::Volatile::new(&mut psram_words),
            argon2,
        );
        let (mut passed, mut total) = (0, 0);
        for line in &report {
            out!(
                "self-test {:<13} {:>3}/{:<3} {:>8} us{}",
                line.name,
                line.passed,
                line.total,
                line.us,
                if line.ok() { "" } else { "  FAIL" }
            );
            passed += line.passed;
            total += line.total;
        }
        out!("self-test: {passed}/{total}");

        // A failed memory line says how: the pattern, the first bad word
        // and its address, the bits that disagreed, how many words went
        // wrong. A count alone cannot tell aliasing from a signal problem.
        for line in report.iter().filter(|l| !l.ok()) {
            let words: &mut [u32] = match line.name {
                "internal RAM" => &mut stack_words,
                "PSRAM" => &mut psram_words,
                _ => continue,
            };
            let (at, len) = (words.as_ptr() as usize, words.len());
            if let Some(f) = selftest::memory_fault(&mut memory::Volatile::new(&mut *words)) {
                out!(
                    "self-test {} fault: {} pattern, word {} of {} at {:#010x}, \
                     wrote {:#010x} read {:#010x} (bits {:#010x}), {} bad",
                    line.name,
                    f.pattern,
                    f.word,
                    len,
                    at + f.word * 4,
                    f.wrote,
                    f.read,
                    f.wrote ^ f.read,
                    f.bad_words
                );
            }
        }
        drop(psram_words);
        report.iter().all(selftest::Line::ok)
    };

    // ── The flow, and the memory it works in ─────────────────────────
    //
    // The flow, with its seed slots and keys, lives in this frame, in
    // internal RAM. The large buffers are PSRAM, where no secret may be:
    // only what arrived and what is sent.
    let mut request = alloc::vec![0u8; SIZES.payload];
    let mut reply = alloc::vec![0u8; SIZES.reply];
    let mut signatures = alloc::vec![InputSignature::EMPTY; SIZES.inputs];
    // A bundle's document, its scripts and the reply's edit: public.
    let mut document = alloc::vec![0u8; SIZES.pskb_document];
    let mut scripts = alloc::vec![0u8; SIZES.pskb_bytes];
    let mut redeem = alloc::vec![0u8; SIZES.redeem];
    let mut text = alloc::vec![0u8; SIZES.edited_document];
    let mut edited = alloc::vec![0u8; SIZES.edited_document];
    // The seed's public keys past its first addresses, filled while
    // idle: about 64 KB.
    let mut pump = alloc::vec![[0u8; 32]; kassigner_fw::keyring::SWEEP];
    // Steganography's photo and its copy with the sealed backup in it,
    // 2 MB each, and the Picture carrier's window: no secret, so PSRAM.
    let mut photo = alloc::vec![0u8; kassigner_fw::limits::PHOTO_MAX];
    let mut photo_out = alloc::vec![0u8; kassigner_fw::limits::PHOTO_OUT];
    let mut window = alloc::vec![0i16; kassigner_fw::limits::WINDOW_RANKS];
    let mut window_bits = alloc::vec![0u8; kassigner_fw::limits::WINDOW_BITS];
    let mut app1 = alloc::vec![0u8; kassigner_fw::limits::APP1_SCRATCH];
    // The photo's Huffman tables, about 9.6 KB, off the stack, where
    // they made the M5's deepest path.
    let mut jpeg = jpeg_tables();
    // Argon2id's 16 MiB for the P4's backups, wiped by the crate after
    // each use, through PSRAM's uncached window (`psram::buffer`): every
    // block and the wipe land in PSRAM itself, never left in the caches
    // with PSRAM still holding the blocks. The S3s seal under PBKDF2.
    #[cfg(feature = "p4")]
    let kdf = Some(
        psram::buffer::<kassigner_crypto::container::Argon2Block>(
            kassigner_crypto::container::ARGON2_BLOCKS,
        )
        .expect("PSRAM for Argon2id"),
    );
    #[cfg(not(feature = "p4"))]
    let kdf = None;
    let (bottom, top) = stack::core0();
    let main_stack = wipe::Stack::new(bottom, top).expect("the linker orders the stack");
    // The window every scrub on this core descends in, set from boot: a
    // secret can be drawn before any seed is held (words typed).
    wipe::begin_depth(main_stack);
    // What Settings' Camera moves, as the board names it.
    let (knobs, tune_auto) = match tuner(&mut unit) {
        Some(mut t) => (t.knobs(), t.auto().is_some()),
        None => (&[][..], false),
    };
    let all = [Source::Camera, Source::Touch, Source::Imu];
    let sources: &[Source] = if checks.imu { &all } else { &all[..2] };
    let mut flow: Flow<'_, SLOTS> = Flow::new(
        Buffers {
            request: &mut request,
            reply: &mut reply,
            signatures: &mut signatures,
            document: &mut document,
            scripts: &mut scripts,
            redeem: &mut redeem,
            text: &mut text,
            edited: &mut edited,
            pump: &mut pump,
            kdf,
            photo: &mut photo,
            photo_out: &mut photo_out,
            window: &mut window,
            window_bits: &mut window_bits,
            app1: &mut app1,
            jpeg: &mut jpeg,
        },
        Config {
            profile: PROFILE,
            capacity: CAPACITY,
            size: unit.lcd.size(),
            stack: main_stack,
            sources,
            words: WORDS,
            settings: SETTINGS,
            backlight: BACKLIGHT,
            volume: VOLUME,
            knobs,
            tune_auto,
        },
    );

    // Where each camera screen puts its viewfinder, as the screen says.
    let view_scale = Scale::for_panel(unit.lcd.size());
    let (scan_view, seed_view, tune_view) = {
        let scale = view_scale;
        (
            rect(camera::scan_viewfinder(scale)),
            rect(camera::viewfinder(scale)),
            rect(camtune::viewfinder(scale)),
        )
    };

    // The reassembler's buffers, in PSRAM. A seed's words can come in
    // frames too (Plain Text QR read back on Home's Scan), so their wipes
    // must reach PSRAM itself, which keeps its contents through a reset:
    // the P4 writes them through PSRAM's uncached window, the S3s write
    // their cache back when a scan ends (`settle_scan`).
    #[cfg(feature = "p4")]
    let (scan_buf, payload) = (
        psram::buffer::<u8>(SIZES.scan_buffer).expect("PSRAM for the frames"),
        psram::buffer::<u8>(SIZES.payload).expect("PSRAM for the payload"),
    );
    #[cfg(any(feature = "m5stack", feature = "waveshare"))]
    let (scan_buf, payload) = (
        alloc::vec![0u8; SIZES.scan_buffer].leak(),
        alloc::vec![0u8; SIZES.payload].leak(),
    );
    #[cfg(any(feature = "m5stack", feature = "waveshare"))]
    let scan_regions = [cache::Region::of(scan_buf), cache::Region::of(payload)];
    // A panic zeroes these two as well: their wipe at a scan's end would
    // not run, leaving a seed's frames in PSRAM.
    if !(stack::clear_on_panic(scan_buf) && stack::clear_on_panic(payload)) {
        out!("a scan buffer is not cleared on a panic");
    }
    let mut seen = alloc::vec![false; SIZES.scan_frames];
    let mut sizes = alloc::vec![0u8; SIZES.scan_frames];

    // One code's bytes, in internal RAM, not on the heap (PSRAM): it
    // holds a SeedQR, and PSRAM keeps its contents through a reset and,
    // on the M5, sits on a bus on the board. 2,953 bytes: a version 40
    // code's byte-mode capacity, the most one code carries.
    let mut decoded = [0u8; 2953];
    let mut io = Io {
        scan: Scan::new(scan_buf, &mut seen, &mut sizes, CAPACITY.bytes_per_frame),
        shown: Screen::Booting,
        camera_on: false,
        samples_on: false,
        tuning: false,
        tune_read: false,
        card_job: None,
        scan_ended: false,
        samples_ended: false,
        no_frames: 0,
        tapped: false,
        tap_said: None,
        deferred_from: None,
        sighting: camera::Sighting::new(),
        sight_ticked: false,
        touch_seen: Seen::default(),
        #[cfg(feature = "p4")]
        kept: Some(Stretched::new(alloc::boxed::Box::leak(
            alloc::vec![0u16; STRETCHED_PIXELS].into_boxed_slice(),
        ))),
        #[cfg(not(feature = "p4"))]
        kept: None,
        // The sensor streams from its set-up; the first step stops it.
        #[cfg(feature = "waveshare")]
        camera_awake: true,
        // `unit::bring_up` turned it off.
        #[cfg(feature = "p4")]
        reset_cut: false,
        search_from: 0,
        gauge: None,
        gauge_read: 0,
        image_hash: shown_hash,
        read_from: None,
        #[cfg(any(feature = "m5stack", feature = "waveshare"))]
        scan_regions,
        now_us: unit.timer.now_us(),
    };

    // Seed sampling.
    let mut prev = [0u8; SEED_SAMPLE];
    let mut cur = [0u8; SEED_SAMPLE];
    let mut have_prev = false;
    #[cfg(any(feature = "m5stack", feature = "waveshare"))]
    let mut imu_buf = [0u8; IMU_CHUNK];
    #[cfg(any(feature = "m5stack", feature = "waveshare"))]
    let mut imu_i2c = unit.device();
    let mut last_touch_us = io.now_us;
    let mut attempt = Attempt::Fast;
    // Which touches are a finger: a tap is a confirmed finger's last
    // point once the panel reads idle (a polled controller sends no lift
    // event). An unconfirmed touch taps nothing: the Waveshare and the P4
    // report phantoms. The M5's controller has shown none, and its quick
    // tap can arrive as one `PressDown` read, so its first report is
    // trusted.
    let mut tracker = if cfg!(feature = "m5stack") {
        Tracker::trusting_first_report()
    } else {
        Tracker::new()
    };
    let mut held = Held::default();
    // Frames with nothing decoded, said every thirty so a stalled camera
    // and a blind decoder do not look alike.
    let mut idle_frames = 0u32;
    let mut passes = Passes::default();
    // The die's temperature, said every five seconds on the S3 units.
    #[cfg(any(feature = "m5stack", feature = "waveshare"))]
    let mut warmth_at = {
        kassigner_hal_esp32s3::tsens::init();
        0u64
    };

    // ── Boot ─────────────────────────────────────────────────────────
    // The flow takes over from the logo.
    let out = flow.step(Event::Tick { now_us: io.now_us }, &mut unit.rng);
    apply(out, &mut unit, &mut flow, &mut io);
    let out = flow.step(
        Event::Booted {
            provisioning: verdict,
            image_read: io.image_hash.is_some(),
            checks_ok: checks.ok && selftest_ok && reseeded,
        },
        &mut unit.rng,
    );
    apply(out, &mut unit, &mut flow, &mut io);

    // The stack: `run`'s frame, and what is left below it for the loop.
    let here = kassigner_fw::wipe::Mark::here().addr();
    diag!(
        "stack: main's frame {} bytes, {} below it",
        top.saturating_sub(here),
        here.saturating_sub(bottom)
    );

    // From here a loop that stops passing resets the chip, and the boot
    // after clears the stack and PSRAM first.
    let mut dog = Watchdog::arm(WATCHDOG_S);
    out!("watchdog: armed, {WATCHDOG_S} s");
    // The watchdog probe: the loop stops feeding 20 s from here.
    #[cfg(feature = "wdtprobe")]
    let stop_at = unit.timer.now_us() + 20_000_000;

    // ── The loop ─────────────────────────────────────────────────────
    //
    // Every pass: a tick; the touch panel; the IMU and the camera if the
    // flow asked for samples; the camera and the decoder if it asked for
    // the camera. Each event is one `step`, its answer applied at once.
    loop {
        #[cfg(feature = "wdtprobe")]
        if unit.timer.now_us() >= stop_at {
            out!("wdtprobe: the loop stops here; the watchdog resets the chip in {WATCHDOG_S} s");
            loop {
                core::hint::spin_loop();
            }
        }
        dog.feed();
        // A scan that ended last pass left the flow's reading of what it
        // read, a SeedQR maybe, below this frame. `run`'s frame is above
        // it all, so the scrub is here, not in `apply`, whose frame sits
        // inside that span.
        if core::mem::take(&mut io.scan_ended) {
            let start = unit.timer.now_us();
            let frames = wipe::scrub_flow();
            diag!(
                "scrub after scan: {} frames, {} us",
                frames,
                unit.timer.since(start)
            );
        }
        // The last seed's bands: kept, they would stay in this frame and
        // the next seed's first difference would use them.
        if core::mem::take(&mut io.samples_ended) {
            wipe::wipe(&mut prev);
            wipe::wipe(&mut cur);
            have_prev = false;
        }
        io.now_us = unit.timer.now_us();
        #[cfg(any(feature = "m5stack", feature = "waveshare"))]
        if io.now_us.saturating_sub(warmth_at) >= 5_000_000 {
            warmth_at = io.now_us;
            #[cfg(feature = "stackprobe")]
            {
                let (used, size) = stack::probe::main_used(wipe::SCRUB_FLOOR_MARGIN);
                match stack::probe::core1_used(wipe::SCRUB_FLOOR_MARGIN) {
                    Some((c1, c1size)) => {
                        out!("stack: main {used} of {size} B; core 1 {c1} of {c1size} B")
                    }
                    None => out!("stack: main {used} of {size} B; core 1 not started"),
                }
            }
            if let Some(t) = kassigner_hal_esp32s3::tsens::tenths() {
                diag!("chip {}.{} C, {:?}", t / 10, (t % 10).abs(), io.shown);
            }
        }
        let out = flow.step(Event::Tick { now_us: io.now_us }, &mut unit.rng);
        apply(out, &mut unit, &mut flow, &mut io);

        // The camera's settings, read back for the tuning screen.
        if io.tune_read {
            io.tune_read = false;
            let mut values = [0u8; MAX_KNOBS];
            let read = tuner(&mut unit).map(|mut t| {
                let n = t.knobs().len().min(MAX_KNOBS);
                t.read(&mut values[..n]).map(|()| (n, t.auto()))
            });
            match read {
                Some(Ok((n, auto))) => {
                    let tuned = Event::Tuned {
                        values: &values[..n],
                        auto,
                    };
                    let out = flow.step(tuned, &mut unit.rng);
                    apply(out, &mut unit, &mut flow, &mut io);
                }
                Some(Err(e)) => out!("camera settings: {e:?}"),
                None => {}
            }
        }

        // A card job, once its screen is drawn: on the S3 units the card
        // holds the display's pins for the session.
        if let Some(job) = io.card_job.take() {
            let start = unit.timer.now_us();
            let outcome =
                card_session(&mut unit, &mut || dog.feed(), job, &mut flow.card_request());
            diag!(
                "card {job:?}: {outcome:?} in {} ms",
                unit.timer.since(start) / 1000
            );
            let out = flow.step(Event::Card(outcome), &mut unit.rng);
            apply(out, &mut unit, &mut flow, &mut io);
        }

        // The finger. While the seed wants samples, every point read is a
        // sample, confirmed or not.
        if let Ok(state) = unit.touch.read() {
            if let (Some(p), true) = (state.first(), io.samples_on) {
                let since = unit.timer.since(last_touch_us).min(u64::from(u32::MAX)) as u32;
                last_touch_us = io.now_us;
                let out = flow.step(
                    Event::TouchMoved {
                        x: p.x,
                        y: p.y,
                        since_us: since,
                    },
                    &mut unit.rng,
                );
                apply(out, &mut unit, &mut flow, &mut io);
            }
            // Reports counted; a confirmed touch that ends is a tap.
            if state.first().is_some() {
                io.touch_seen.report(io.now_us);
            }
            if let Some(event) = tracker.read(state, io.now_us).and_then(event_of) {
                let now_us = unit.timer.now_us();
                io.tapped = tap_at(&event, &mut io, now_us);
                let out = flow.step(event, &mut unit.rng);
                apply(out, &mut unit, &mut flow, &mut io);
            }
        }

        // The IMU, while the seed wants it. The P4 has none.
        #[cfg(any(feature = "m5stack", feature = "waveshare"))]
        if io.samples_on && checks.imu {
            let mut sys = SysTimer;
            let n = imu::collect(&mut imu_i2c, &mut sys, &mut imu_buf);
            let out = flow.step(Event::ImuSample(&imu_buf[..n]), &mut unit.rng);
            apply(out, &mut unit, &mut flow, &mut io);
            wipe::wipe(&mut imu_buf);
        }

        // The decoder's answer from the last pass. Collect, capture, then
        // submit: core 1 decodes, and a submit is `Busy` while it works,
        // so a result comes at a later poll.
        if io.camera_on {
            match unit.dec.poll(&mut decoded) {
                Ok(Some(Outcome::Found { len })) => {
                    attempt = Attempt::Fast;
                    idle_frames = 0;
                    io.sight_ticked = sighted(&mut unit, &mut io);
                    deliver(&decoded[..len], payload, &mut unit, &mut flow, &mut io);
                    io.sight_ticked = false;
                    wipe::wipe(&mut decoded[..len]);
                }
                Ok(Some(Outcome::Unreadable)) => {
                    attempt = Attempt::Thorough;
                    sighted(&mut unit, &mut io);
                    diag!("a code, unreadable: trying harder");
                }
                Ok(Some(Outcome::NotFound)) | Ok(None) => {}
                Err(e) => out!("decoder: {e:?}"),
            }
        }

        // After the poll: what it delivered can end the scan, and
        // `CameraOff` has then cleared the frames, since one may hold a
        // SeedQR. Capturing now would leave a fresh frame of the code
        // still held up in the frame buffer until the next scan.
        if !io.camera_on && !io.samples_on && !io.tuning {
            // Nothing to capture: an S3's core 0 sleeps until its 5 ms
            // timer or an interrupt. It never sleeps with the camera in
            // use: a capture must be polled.
            #[cfg(any(feature = "m5stack", feature = "waveshare"))]
            unit.rest();
            continue;
        }

        // A frame: the viewfinder, the decoder and the seed's band. The
        // panel is also read while the frame comes and after the
        // viewfinder: the two take up to about 110 ms on the P4, and a tap
        // read once in that time is a lone report, taken for a phantom.
        // What is read waits in `held` until the frame is let go.
        let pass_start = unit.timer.now_us();
        let mut polled = pass_start;
        let mut read_touch = || {
            let now = unit.timer.now_us();
            if now.saturating_sub(polled) >= TOUCH_POLL_US {
                polled = now;
                watch(&mut unit.touch, &mut tracker, now, &mut held);
            }
        };
        let frame = match unit
            .cam
            .frame_within_idle(&unit.timer, 1_000_000, &mut read_touch)
        {
            Ok(frame) => {
                io.no_frames = 0;
                frame
            }
            Err(e) => {
                out!(
                    "camera: no frame after {} ms: {e:?}",
                    unit.timer.since(pass_start) / 1000
                );
                // Held past this pass, a tap on a stalled scanner would
                // land on the next camera screen.
                release(&mut held, &mut unit, &mut flow, &mut io);
                // A tap may have ended the camera's screen: no miss then.
                if !io.camera_on && !io.samples_on && !io.tuning {
                    io.no_frames = 0;
                    continue;
                }
                // Three in a row: the camera is lost and its screen ends.
                io.no_frames = io.no_frames.saturating_add(1);
                if io.no_frames >= CAMERA_LOST_AFTER {
                    io.no_frames = 0;
                    out!("camera: lost, {CAMERA_LOST_AFTER} frames in a row missing");
                    let out = flow.step(Event::CameraLost, &mut unit.rng);
                    apply(out, &mut unit, &mut flow, &mut io);
                }
                continue;
            }
        };
        let captured = unit.timer.now_us();
        let view = match io.shown {
            // A scan's square, the same from first to last frame.
            Screen::Scanning { .. } | Screen::MessageScan { .. } | Screen::BackupScan { .. } => {
                scan_view
            }
            Screen::CameraTune { .. } => tune_view,
            _ => seed_view,
        };
        let picture = unit::viewfinder(&mut unit.lcd, frame, view);
        // A scan's edge: red while no code is in view, flashing green
        // while one is. Drawn on every frame, as the picture's last rows,
        // under its foot, are repainted every frame.
        if io.camera_on {
            let color = io.sighting.edge();
            let picture =
                kassigner_fw::touch::Zone::new(picture.x, picture.y, picture.width, picture.height);
            for e in camera::edges(view_scale, picture) {
                let _ = unit.lcd.fill(rect(e), color);
            }
        }
        let viewed = unit.timer.now_us();
        watch(
            &mut unit.touch,
            &mut tracker,
            unit.timer.now_us(),
            &mut held,
        );
        // The worker's answer if it came during this pass: taken before
        // this frame is offered, acted on once the frame is let go.
        let mut late = None;
        if io.camera_on {
            // Taken first so this frame finds core 1's worker free;
            // otherwise it is refused `Busy` and every decode costs a
            // pass. An unreadable code sends this frame to the thorough
            // pass.
            if unit.dec.is_ready() {
                let answer = unit.dec.poll(&mut decoded);
                if let Ok(Some(Outcome::Unreadable)) = answer {
                    attempt = Attempt::Thorough;
                }
                late = Some(answer);
            }
            // After a code is read, this frame is submitted only if the
            // code is one of several frames. A lone code (a SeedQR, a
            // single-frame request) usually ends the scan, which would
            // then wait out this frame's decode to wipe it.
            let goes_on = match late {
                Some(Ok(Some(Outcome::Found { len }))) => io.scan.of_several(&decoded[..len]),
                _ => true,
            };
            // `Busy` is ordinary while the worker has a frame.
            if goes_on {
                let _ = unit.dec.submit(frame, attempt);
            }
            // Saturating: a clock that seems to go backwards must not
            // panic, which wipes and halts the unit.
            passes.add(
                captured.saturating_sub(pass_start),
                viewed.saturating_sub(captured),
                unit.timer.since(viewed),
            );

            // One thorough pass per unreadable frame: `Thorough` kept
            // until a `Found` would send most of a scan down the slow path.
            attempt = Attempt::Fast;
            idle_frames += 1;
            if idle_frames.is_multiple_of(30) {
                diag!("{idle_frames} frames, nothing decoded yet");
            }
        }
        if io.samples_on {
            let stride = frame.len() / SEED_SAMPLE;
            for (i, b) in cur.iter_mut().enumerate() {
                *b = frame[i * stride];
            }
        }
        // The frame's borrow ends here; what follows needs the unit.
        release(&mut held, &mut unit, &mut flow, &mut io);
        // The answer taken before the submit, after this pass's taps: if
        // a tap ended the scan it goes unread, and a code is wiped anyway.
        match late {
            Some(Ok(Some(Outcome::Found { len }))) => {
                if io.camera_on && !io.scan_ended {
                    attempt = Attempt::Fast;
                    idle_frames = 0;
                    io.sight_ticked = sighted(&mut unit, &mut io);
                    deliver(&decoded[..len], payload, &mut unit, &mut flow, &mut io);
                    io.sight_ticked = false;
                }
                wipe::wipe(&mut decoded[..len]);
            }
            Some(Ok(Some(Outcome::Unreadable))) => {
                if io.camera_on && !io.scan_ended {
                    sighted(&mut unit, &mut io);
                }
                diag!("a code, unreadable: trying harder");
            }
            Some(Err(e)) => out!("decoder: {e:?}"),
            _ => {}
        }
        if io.samples_on {
            if have_prev {
                for (c, p) in cur.iter_mut().zip(prev.iter_mut()) {
                    let d = c.wrapping_sub(*p);
                    *p = *c;
                    *c = d;
                }
                let out = flow.step(Event::CameraSample(&cur), &mut unit.rng);
                apply(out, &mut unit, &mut flow, &mut io);
                wipe::wipe(&mut cur);
            } else {
                prev.copy_from_slice(&cur);
                have_prev = true;
            }
        }
    }
}

/// Ours: `esp-backtrace` keeps its handler behind a feature this build
/// does not turn on.
///
/// A panic can come from anywhere, a derivation included, and the flow
/// with its seed slots lives in `run`'s frame on core 0's stack. So,
/// whichever core panicked, the board parks the other, clears both
/// stacks (every frame but the one clearing), runs the unit's `quiesce`
/// (the decoder's buffers, the panel's transfer buffer, the camera
/// stopped and its buffers zeroed, the backlight off so the last screen
/// does not stay lit), and halts. The watchdog then resets it, and the
/// boot after clears PSRAM and the stack again. A panic in bring-up,
/// before the watchdog is armed, stays halted.
///
/// The report comes first, while the console is open: on a provisioned
/// unit it closed before a seed could be held, so the wipe starts at
/// once; on a bench unit the report is worth the milliseconds it costs.
///
/// The report is the panic's own message (an `assert_eq!` prints both
/// sides, an `expect` its text), so in every crate this binary links no
/// assert, `expect` or panic message formats a secret or anything made
/// from one. The closed console is the second line of defence, not the
/// first.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    out!("PANIC: {}", info);
    stack::wipe_and_halt(wipe::SCRUB_FLOOR_MARGIN, unit::quiesce, wiped)
}

/// What the wipe cleared, said once it is done.
fn wiped(bytes: usize) {
    out!("stacks cleared, {bytes} bytes; halted");
}
