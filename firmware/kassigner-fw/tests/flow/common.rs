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

//! What the flow's tests share: the unit on the host, its memory and entropy,
//! the test seed, hand-built requests, a card in RAM, and the taps and keys
//! that drive the flow.

use super::*;

pub(crate) const P: Profile = Profile::ESP32S3;
pub(crate) const CAP: Capacity = Capacity {
    transaction_bytes: 16_384,
    bytes_per_frame: 256,
    frames: 64,
    display_bytes_per_frame: 225,
};
pub(crate) const SIZE: Size = Size {
    width: 320,
    height: 240,
};
pub(crate) const SIZES: Sizes = Sizes::new(&CAP, &P);
pub(crate) const SCALE: Scale = Scale::for_panel(SIZE);

/// A tap in the middle of a zone.
pub(crate) fn tap_in(z: Zone) -> Event<'static> {
    Event::Tap {
        x: z.x + z.width / 2,
        y: z.y + z.height / 2,
    }
}

/// A tap on a home grid card: Scan, Seeds, Tools, Settings.
pub(crate) fn card(i: usize) -> Event<'static> {
    tap_in(brand::zone(SCALE, brand::Target::Card(i)))
}

/// A tap on the Scan card.
pub(crate) fn scan() -> Event<'static> {
    card(0)
}

/// A tap on a dialog's answer.
pub(crate) fn answer(t: dialog::Target) -> Event<'static> {
    tap_in(dialog::zone(SCALE, t).expect("a dialog answer"))
}

/// A tap on the back button.
pub(crate) fn back_button() -> Event<'static> {
    tap_in(chrome::corner(SCALE, Nav::Back))
}

/// A tap on the home button.
pub(crate) fn home_button() -> Event<'static> {
    tap_in(chrome::corner(SCALE, Nav::Home))
}

/// A tap on a menu's item `i`, on the page it is on.
pub(crate) fn item(m: &menu::Menu, i: usize) -> Event<'static> {
    tap_in(menu::zone(SCALE, m, i / 4, menu::Target::Item(i)).expect("an item"))
}

/// Taps in the left and right side columns: a review page's arrows.
pub(crate) const LEFT: Event<'static> = Event::Tap { x: 40, y: 120 };
pub(crate) const RIGHT: Event<'static> = Event::Tap { x: 280, y: 120 };

/// A tap on one of CONFIRM SEND?'s targets.
pub(crate) fn on_confirm(t: review::Target) -> Event<'static> {
    tap_in(review::zone(SCALE, true, t).expect("on CONFIRM SEND?"))
}

/// A finger down and up at one point, as the loop reports it: the press,
/// then the tap. The review and the dialogs take a tap only on the target
/// pressed.
pub(crate) trait Touch {
    fn touch(&mut self, e: Event<'static>) -> kassigner_fw::flow::Output;
}

impl<const N: usize> Touch for Flow<'_, N> {
    fn touch(&mut self, e: Event<'static>) -> kassigner_fw::flow::Output {
        let Event::Tap { x, y } = e else {
            panic!("{e:?} is not a tap");
        };
        self.step(Event::Press { x, y }, &mut Live);
        self.step(e, &mut Live)
    }
}

/// A finger down at `from` that slides and lifts at `to`.
pub(crate) fn slide<const N: usize>(
    f: &mut Flow<'_, N>,
    (x, y): (u16, u16),
    to: (u16, u16),
) -> kassigner_fw::flow::Output {
    f.step(Event::Press { x, y }, &mut Live);
    f.step(Event::Drag { x: to.0, y: to.1 }, &mut Live);
    f.step(Event::Tap { x: to.0, y: to.1 }, &mut Live)
}

/// The clock past [`SETTLE_US`], as SIGN MESSAGE? and IMPORT KEY? wait.
pub(crate) fn read<const N: usize>(f: &mut Flow<'_, N>) {
    let now_us = f.now_us() + SETTLE_US;
    f.step(Event::Tick { now_us }, &mut Live);
}

/// The tick after a tap answered with [`Command::Deferred`], which does its
/// work; the clock stays.
pub(crate) fn settled<const N: usize>(
    f: &mut Flow<'_, N>,
    out: kassigner_fw::flow::Output,
) -> kassigner_fw::flow::Output {
    assert_eq!(
        out.command,
        Some(Command::Deferred),
        "a tap whose work waits"
    );
    let now_us = f.now_us();
    f.step(Event::Tick { now_us }, &mut Live)
}

/// A review arrow, pressed and lifted: the page it was taken on, then on
/// the next tick ([`settled`]) the page it turns to.
pub(crate) fn arrow<const N: usize>(
    f: &mut Flow<'_, N>,
    e: Event<'static>,
) -> kassigner_fw::flow::Output {
    let (x, y) = point(e);
    let before = f.step(Event::Press { x, y }, &mut Live).screen;
    let out = f.step(e, &mut Live);
    assert_eq!(
        out.screen, before,
        "the page it was taken on, until the tick"
    );
    settled(f, out)
}

/// Where a tap is, as a point.
pub(crate) fn point(e: Event<'static>) -> (u16, u16) {
    let Event::Tap { x, y } = e else {
        panic!("{e:?} is not a tap");
    };
    (x, y)
}

/// From the last page to CONFIRM SEND?, then CONFIRM, which signs on the
/// next tick.
pub(crate) fn confirmed<const N: usize>(f: &mut Flow<'_, N>) -> kassigner_fw::flow::Output {
    let out = arrow(f, RIGHT);
    assert_eq!(
        f.state(),
        State::Confirming,
        "CONFIRM SEND? past the last page"
    );
    assert_eq!(out.screen, Screen::Confirm);
    let out = f.touch(on_confirm(review::Target::Confirm));
    assert_eq!(f.state(), State::Signing, "the tap puts up SIGNING");
    assert_eq!(out.screen, Screen::Signing);
    assert!(f.reply().is_empty(), "nothing signed on the tap's own step");
    f.step(Event::Tick { now_us: 1 }, &mut Live)
}

pub(crate) struct Live;

impl Entropy for Live {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), entropy::Error> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        Ok(())
    }
}

pub(crate) struct Memory {
    pub(crate) request: Vec<u8>,
    pub(crate) reply: Vec<u8>,
    pub(crate) signatures: Vec<InputSignature>,
    pub(crate) document: Vec<u8>,
    pub(crate) scripts: Vec<u8>,
    pub(crate) redeem: Vec<u8>,
    pub(crate) text: Vec<u8>,
    pub(crate) edited: Vec<u8>,
    pub(crate) pump: Vec<[u8; 32]>,
    /// Argon2id's working memory: none lent, as on an S3.
    pub(crate) kdf: Vec<kassigner_crypto::container::Argon2Block>,
    /// Steganography's photo, its copy with the backup in it, and the
    /// Picture carrier's window.
    pub(crate) photo: Vec<u8>,
    pub(crate) photo_out: Vec<u8>,
    pub(crate) window: Vec<i16>,
    pub(crate) window_bits: Vec<u8>,
    pub(crate) app1: Vec<u8>,
    /// The photo's Huffman tables, off the stack as on the unit.
    pub(crate) jpeg: Box<kassigner_protocol::stego::picture::Tables>,
}

impl Memory {
    pub(crate) fn new() -> Self {
        Self {
            request: vec![0; SIZES.payload],
            reply: vec![0; SIZES.reply],
            signatures: vec![InputSignature::EMPTY; SIZES.inputs],
            document: vec![0; SIZES.pskb_document],
            scripts: vec![0; SIZES.pskb_bytes],
            redeem: vec![0; SIZES.redeem],
            text: vec![0; SIZES.edited_document],
            edited: vec![0; SIZES.edited_document],
            pump: vec![[0; 32]; kassigner_fw::keyring::SWEEP],
            kdf: Vec::new(),
            photo: vec![0; kassigner_fw::limits::PHOTO_MAX],
            photo_out: vec![0; kassigner_fw::limits::PHOTO_OUT],
            window: vec![0; kassigner_fw::limits::WINDOW_RANKS],
            window_bits: vec![0; kassigner_fw::limits::WINDOW_BITS],
            app1: vec![0; kassigner_fw::limits::APP1_SCRATCH],
            jpeg: Box::new(kassigner_protocol::stego::picture::Tables::EMPTY),
        }
    }

    pub(crate) fn lend(&mut self) -> Buffers<'_> {
        Buffers {
            request: &mut self.request,
            reply: &mut self.reply,
            signatures: &mut self.signatures,
            document: &mut self.document,
            scripts: &mut self.scripts,
            redeem: &mut self.redeem,
            text: &mut self.text,
            edited: &mut self.edited,
            pump: &mut self.pump,
            kdf: (!self.kdf.is_empty()).then_some(&mut self.kdf[..]),
            photo: &mut self.photo,
            photo_out: &mut self.photo_out,
            window: &mut self.window,
            window_bits: &mut self.window_bits,
            app1: &mut self.app1,
            jpeg: &mut self.jpeg,
        }
    }
}

pub(crate) fn flow<'b, const N: usize>(memory: &'b mut Memory, sources: &[Source]) -> Flow<'b, N> {
    Flow::new(
        memory.lend(),
        Config {
            profile: P,
            capacity: CAP,
            size: SIZE,
            // A stand-in for a board's stack, of a real one's size: every
            // test that stores a seed scrubs it to its floor, so a larger
            // one would slow them all.
            stack: Stack::below(Mark::here(), 64 * 1024),
            sources,
            words: Words::Twelve,
            settings: &menu::SETTINGS,
            backlight: 128,
            volume: 18,
            knobs: &KNOBS,
            tune_auto: true,
        },
    )
}

pub(crate) const GOOD: Event<'static> = Event::Booted {
    provisioning: Verdict::Provisioned,
    image_read: true,
    checks_ok: true,
};

/// What [`GOOD`] makes the verification screen: teal.
pub(crate) const CLEAN: brand::Check = brand::Check {
    verdict: Verdict::Provisioned,
    image_read: true,
};

/// Boot a provisioned unit and let the verification screen pass.
pub(crate) fn booted<'b, const N: usize>(
    memory: &'b mut Memory,
    sources: &[Source],
) -> Flow<'b, N> {
    let mut f = flow(memory, sources);
    f.step(Event::Tick { now_us: 0 }, &mut Live);
    f.step(GOOD, &mut Live);
    assert_eq!(f.state(), State::Verified(CLEAN));
    f.step(
        Event::Tick {
            now_us: VERIFIED_US,
        },
        &mut Live,
    );
    f
}

// ── The seed used throughout ────────────────────────────────────────────────

pub(crate) fn mnemonic() -> bip39::Mnemonic {
    bip39::from_entropy(&[7u8; 16]).unwrap()
}

pub(crate) fn seedqr() -> Vec<u8> {
    let mut out = [0u8; slot::SEEDQR_MAX];
    let n = slot::to_seedqr(&mnemonic(), &mut out);
    out[..n].to_vec()
}

pub(crate) fn wallet() -> Wallet {
    let mut scratch = vec![0u8; bip39::scratch_for(0)];
    Wallet::open(&Slot::mnemonic(mnemonic(), b"").unwrap(), &mut scratch).unwrap()
}

pub(crate) fn x_only(w: &Wallet) -> [u8; 32] {
    w.signing_key(Path::receive(0)).unwrap().x_only()
}

/// Scan a SeedQR from home and load it, ending on the seeds screen with it
/// in use.
pub(crate) fn load<const N: usize>(f: &mut Flow<'_, N>, digits: &[u8]) {
    assert_eq!(f.state(), State::Home);
    let out = f.step(scan(), &mut Live);
    assert_eq!(f.state(), State::Scanning);
    assert_eq!(out.command, Some(Command::CameraOn));
    let out = f.step(Event::Code(digits), &mut Live);
    assert_eq!(f.state(), State::Loading, "read, and waiting for Load");
    assert_eq!(out.command, Some(Command::CameraOff));
    // A standard SeedQR is four digits a word.
    let words = digits.len() / 4;
    assert_eq!(out.screen, Screen::Loading { words });
    f.touch(answer(dialog::Target::Accept));
    f.step(no_passphrase(), &mut Live);
    opened(f);
}

/// Tick a wallet open a step at a time, checking the screen's count.
pub(crate) fn opened<const N: usize>(f: &mut Flow<'_, N>) {
    assert!(
        matches!(f.state(), State::Opening { .. }),
        "{:?}",
        f.state()
    );
    for step in 0..OPEN_STEPS {
        let out = f.step(
            Event::Tick {
                now_us: VERIFIED_US,
            },
            &mut Live,
        );
        if step + 1 < OPEN_STEPS {
            assert_eq!(
                out.screen,
                Screen::Opening {
                    done: step + 1,
                    total: OPEN_STEPS
                }
            );
        }
    }
    let out = f.step(
        Event::Tick {
            now_us: VERIFIED_US,
        },
        &mut Live,
    );
    assert!(
        matches!(out.screen, Screen::Seeds { .. }),
        "{:?}",
        out.screen
    );
}

/// A unit with the seed in its slot, back on the home grid.
pub(crate) fn seeded<const N: usize>(memory: &mut Memory) -> Flow<'_, N> {
    let mut f = booted(memory, &[]);
    load(&mut f, &seedqr());
    assert!(matches!(f.state(), State::Seeds { .. }), "{:?}", f.state());
    assert_eq!(f.fingerprint(), Some(wallet().fingerprint()));
    f.step(home_button(), &mut Live);
    assert_eq!(f.state(), State::Home);
    f
}

// ── A request built by hand ─────────────────────────────────────────────────

/// One input of `amount` locked to `spk`, and these outputs.
pub(crate) fn request(amount: u64, spk: &[u8], outputs: &[(u64, &[u8])]) -> Vec<u8> {
    // Canonical: no signatures, then a `u16` redeem length of zero.
    request_as(VERSION, 0, &[0, 0, 0], amount, spk, outputs)
}

/// The same request under another version's header and input tail, the
/// bytes after the input's script, where the versions differ.
pub(crate) fn request_as(
    version: u8,
    flags: u8,
    input_tail: &[u8],
    amount: u64,
    spk: &[u8],
    outputs: &[(u64, &[u8])],
) -> Vec<u8> {
    request_of(version, flags, input_tail, &[(amount, spk)], outputs)
}

/// A request of several inputs, input `i` of `amount` locked to its script,
/// spending output `i` of one transaction, followed by `input_tail`.
pub(crate) fn request_of(
    version: u8,
    flags: u8,
    input_tail: &[u8],
    inputs: &[(u64, &[u8])],
    outputs: &[(u64, &[u8])],
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&MAGIC);
    b.push(version);
    b.push(flags);
    b.extend_from_slice(&1u16.to_le_bytes());
    b.push(inputs.len() as u8);
    b.push(outputs.len() as u8);
    b.extend_from_slice(&0u64.to_le_bytes());
    b.extend_from_slice(&[0u8; 20]);
    b.extend_from_slice(&0u64.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    for (i, (amount, spk)) in inputs.iter().enumerate() {
        b.extend_from_slice(&[0x11u8; 32]);
        b.extend_from_slice(&(i as u32).to_le_bytes());
        b.extend_from_slice(&amount.to_le_bytes());
        b.extend_from_slice(&0u64.to_le_bytes());
        b.push(1);
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&spk_len(spk.len()));
        b.extend_from_slice(spk);
        b.extend_from_slice(input_tail);
    }
    for (value, spk) in outputs {
        b.extend_from_slice(&value.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&spk_len(spk.len()));
        b.extend_from_slice(spk);
    }
    b
}

/// A request ours to sign, with two outputs so the review has two pages or
/// more.
pub(crate) fn ours() -> Vec<u8> {
    let spk = p2pk(&x_only(&wallet()));
    request(
        100_000 * KAS,
        &spk,
        &[(60_000 * KAS, &spk), (30_000 * KAS, &spk)],
    )
}

/// The digest the reply's signature must verify over, as the `reply` tests
/// compute it.
pub(crate) fn digest(req: &[u8]) -> [u8; 32] {
    let k = kspt::legacy::parse_any(req, &P).expect("parse");
    kspt_spent(&k)[0].digest
}

/// A tap on one of SIGNED TX QR's cards.
pub(crate) fn reply_card(card: Card) -> Event<'static> {
    tap_in(kassigner_fw::ui::kpub::zone(SCALE, card).expect("a card"))
}

/// The reply after the confirming tap: Wallet on SIGNED TX QR, Auto Cycle
/// on QR DISPLAY MODE if in frames, then its first frame.
pub(crate) fn reply_shown(f: &mut Flow<'_, 1>) {
    assert_eq!(f.state(), State::ReplyFormat, "Wallet or KasSigner first");
    f.step(reply_card(Card::Wallet), &mut Live);
    if f.reply_frames() > 1 {
        assert_eq!(f.state(), State::ReplyMode, "frames ask first");
        f.touch(answer(dialog::Target::Cancel));
    }
    assert_eq!(f.state(), State::Showing { frame: 0 });
}

/// A request read whole by the scan: CHECKING at once with the camera off,
/// then the next tick plans it. Gives the tick's answer, or, for a code
/// refused or taken on arrival (never CHECKING), the arrival's.
pub(crate) fn deliver<const N: usize>(f: &mut Flow<'_, N>, bytes: &[u8]) -> Output {
    let out = f.step(Event::Payload(bytes), &mut Live);
    if out.screen != Screen::Checking {
        return out;
    }
    assert_eq!(out.command, Some(Command::CameraOff), "the camera off");
    assert_eq!(
        f.state(),
        State::Checking {
            len: bytes.len(),
            card: false
        }
    );
    f.step(Event::Tick { now_us: f.now_us() }, &mut Live)
}

/// Scan `req` into a seeded unit and reach the review.
pub(crate) fn reviewing<'b>(memory: &'b mut Memory, req: &[u8]) -> Flow<'b, 1> {
    let mut f = seeded(memory);
    let out = f.step(scan(), &mut Live);
    assert_eq!(f.state(), State::Scanning);
    assert_eq!(out.command, Some(Command::CameraOn));
    let out = f.step(
        Event::Progress {
            have: 1,
            total: 3,
            received: 0b1,
        },
        &mut Live,
    );
    assert_eq!(
        out.screen,
        Screen::Scanning {
            have: 1,
            total: 3,
            received: 0b1,
            hint: false
        }
    );
    deliver(&mut f, req);
    assert_eq!(f.state(), State::Reviewing);
    f
}

/// A board's seven camera settings, as a unit names them; the exposure
/// loop's switch is separate.
pub(crate) static KNOBS: [Knob; 7] = [
    Knob::new("AEC-Y", 0xFF, 8).in_auto().lead(),
    Knob::new("EXPO-H", 0x0F, 1).in_manual(),
    Knob::new("EXPO-L", 0xFF, 8).in_manual(),
    Knob::new("GAIN", 0x3F, 2).in_manual(),
    Knob::new("PREGN", 0xFF, 8).in_manual(),
    Knob::new("CONTR", 0xFF, 8),
    Knob::new("SHARP", 0xFF, 8),
];

/// A tap on a key of the keyboard at `page`.
pub(crate) fn key(page: u8, k: keyboard::Key) -> Event<'static> {
    tap_in(keyboard::zone(SCALE, page, keyboard::Target::Key(k)).expect("a key on the page"))
}

/// OK on the passphrase's keyboard with nothing typed.
pub(crate) fn no_passphrase() -> Event<'static> {
    key(0, keyboard::Key::Ok)
}

/// Type `text` on the restore password's keyboard, turning pages as
/// needed.
pub(crate) fn restore_type(f: &mut Flow<'_, 6>, text: &[u8]) {
    for &c in text {
        let page = (0..keyboard::PAGES)
            .find(|&p| {
                keyboard::zone(SCALE, p, keyboard::Target::Key(keyboard::Key::Char(c))).is_some()
            })
            .unwrap();
        loop {
            let State::RestorePassword { page: at } = f.state() else {
                panic!("{:?}", f.state())
            };
            if at == page {
                break;
            }
            f.step(key(at, keyboard::Key::Page), &mut Live);
        }
        f.step(key(page, keyboard::Key::Char(c)), &mut Live);
    }
}

/// OK on the restore password's keyboard.
pub(crate) fn restore_ok(f: &mut Flow<'_, 6>) -> kassigner_fw::flow::Output {
    let State::RestorePassword { page } = f.state() else {
        panic!("{:?}", f.state())
    };
    f.step(key(page, keyboard::Key::Ok), &mut Live)
}

// ── Writing over a file ─────────────────────────────────────────────────────

pub(crate) type Sd = kassigner_fat32::block::Memory<Vec<[u8; kassigner_fat32::block::BLOCK_SIZE]>>;

/// A card in memory, formatted, holding `files`.
pub(crate) fn card_with(files: &[(&[u8; 11], &[u8])]) -> Sd {
    use kassigner_fat32::fat32::{create_file, do_format_fat32, mount_fat32};
    let mut sd = Sd::new(vec![[0u8; kassigner_fat32::block::BLOCK_SIZE]; 128 * 1024]);
    do_format_fat32(&mut sd).unwrap();
    let info = mount_fat32(&mut sd).unwrap();
    for (name, bytes) in files {
        create_file(&mut sd, &info, name, bytes).unwrap();
    }
    sd
}

/// What the card holds as `name`.
pub(crate) fn on_card(sd: &mut Sd, name: &[u8; 11]) -> Vec<u8> {
    use kassigner_fat32::fat32::{find_file_in_root, mount_fat32, read_file};
    let info = mount_fat32(sd).unwrap();
    let (entry, _, _) = find_file_in_root(sd, &info, name).unwrap();
    let mut out = vec![0u8; entry.file_size as usize];
    let n = read_file(sd, &info, &entry, &mut out).unwrap();
    out.truncate(n);
    out
}

/// The job the flow asked for, done on the card as the binary would.
pub(crate) fn run_job<const N: usize>(
    f: &mut Flow<'_, N>,
    sd: &mut Sd,
    job: Job,
) -> kassigner_fw::flow::Output {
    let outcome = card::run(job, Kind::SdV2High, sd, &mut f.card_request());
    f.step(Event::Card(outcome), &mut Live)
}

/// The page of whichever keyboard is up.
pub(crate) fn keyboard_page<const N: usize>(f: &Flow<'_, N>) -> u8 {
    match f.state() {
        State::BackupName { page }
        | State::BackupPassword { page, .. }
        | State::RestorePassword { page }
        | State::OverwritePassword { page } => page,
        other => panic!("no keyboard: {other:?}"),
    }
}

/// `k` on whichever keyboard is up.
pub(crate) fn press<const N: usize>(
    f: &mut Flow<'_, N>,
    k: keyboard::Key,
) -> kassigner_fw::flow::Output {
    let page = keyboard_page(f);
    f.step(key(page, k), &mut Live)
}

/// Type `text` on whichever keyboard is up, turning pages as needed.
pub(crate) fn type_on<const N: usize>(f: &mut Flow<'_, N>, text: &[u8]) {
    for &c in text {
        let page = (0..keyboard::PAGES)
            .find(|&p| {
                keyboard::zone(SCALE, p, keyboard::Target::Key(keyboard::Key::Char(c))).is_some()
            })
            .expect("a key for it");
        while keyboard_page(f) != page {
            press(f, keyboard::Key::Page);
        }
        f.step(key(page, keyboard::Key::Char(c)), &mut Live);
    }
}

/// Replace the offered name with `name`, press OK, and run the card's
/// check for the file.
pub(crate) fn name_as<const N: usize>(f: &mut Flow<'_, N>, sd: &mut Sd, name: &[u8]) {
    for _ in 0..f.typed().0.len() {
        press(f, keyboard::Key::Delete);
    }
    type_on(f, name);
    assert_eq!(f.typed().0.as_bytes(), name);
    assert_eq!(
        press(f, keyboard::Key::Ok).command,
        Some(Command::Card(Job::Exists))
    );
    run_job(f, sd, Job::Exists);
}

/// Answer Overwrite and run the card's read of the file; the screen that
/// follows.
pub(crate) fn overwrite<const N: usize>(f: &mut Flow<'_, N>, sd: &mut Sd) -> Screen {
    assert_eq!(f.state(), State::BackupOverwrite);
    assert_eq!(
        f.touch(answer(dialog::Target::Accept)).command,
        Some(Command::Card(Job::Read)),
        "the file is read before anything is written"
    );
    run_job(f, sd, Job::Read).screen
}

/// Tick from `t`, a millisecond apart, until the bar is done; the screen
/// it ends on.
pub(crate) fn opened_at<const N: usize>(f: &mut Flow<'_, N>, t: &mut u64) -> Screen {
    loop {
        *t += 1_000;
        let out = f.step(Event::Tick { now_us: *t }, &mut Live);
        if !matches!(out.screen, Screen::RestoreOpening { .. }) {
            return out.screen;
        }
    }
}

/// Seed Tools' row `row`, from the home grid, turning to its page.
pub(crate) fn seed_tool<const N: usize>(f: &mut Flow<'_, N>, row: usize) {
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 0), &mut Live);
    for page in 0..row / 4 {
        let down = menu::zone(
            SCALE,
            &menu::SEED_TOOLS,
            page,
            menu::Target::Nav(Nav::PageDown),
        );
        f.step(tap_in(down.expect("a page that way")), &mut Live);
    }
    f.step(item(&menu::SEED_TOOLS, row), &mut Live);
}

/// The address at `path` of the test seed, as text.
pub(crate) fn address_of(path: Path) -> String {
    use kassigner_kaspa::address::{encode, Prefix, Version, MAX_ADDRESS_LEN};
    let key = wallet().signing_key(path).unwrap().x_only();
    let mut out = [0u8; MAX_ADDRESS_LEN];
    let n = encode(Prefix::Mainnet, Version::PubKey, &key, &mut out).unwrap();
    String::from_utf8(out[..n].to_vec()).unwrap()
}

/// Read `code` back with the camera's decoder, drawn with a quiet zone at
/// 6 pixels a module.
pub(crate) fn read_back(code: &kassigner_qr::encode::QrMatrix) -> Vec<u8> {
    let n = usize::from(code.size);
    let (q, s) = (4usize, 6usize);
    let side = (n + 2 * q) * s;
    let mut pixels = vec![255u8; side * side];
    for y in 0..n {
        for x in 0..n {
            if code.get(x as u8, y as u8) {
                for dy in 0..s {
                    for dx in 0..s {
                        pixels[((y + q) * s + dy) * side + (x + q) * s + dx] = 0;
                    }
                }
            }
        }
    }
    let mut scratch = kassigner_qr::Scratch::new();
    let mut decoder = kassigner_qr::Decoder::new(&mut scratch);
    let mut out = [0u8; 512];
    let got = decoder
        .decode(side, side, 8, &mut pixels, &mut out)
        .expect("the code reads back");
    out[..got.len].to_vec()
}

/// From home to Watch-Only's `row`.
pub(crate) fn watch_only<const N: usize>(
    f: &mut Flow<'_, N>,
    row: usize,
) -> kassigner_fw::flow::Output {
    f.touch(home_button());
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(
        tap_in(
            kassigner_fw::ui::backup::zone(SCALE, kassigner_fw::ui::backup::Target::Export)
                .unwrap(),
        ),
        &mut Live,
    );
    f.step(item(&menu::EXPORT, 1), &mut Live);
    // The row clicks at once, Watch-Only still up; the kpub comes on the
    // next tick.
    let out = f.step(item(&menu::WATCH_ONLY, row), &mut Live);
    assert_eq!(
        out.screen,
        Screen::Menu {
            menu: MenuId::WatchOnly,
            page: 0
        }
    );
    settled(f, out)
}

/// Type `password` on the backup password's keyboard, the first time or
/// `again`, and press OK.
pub(crate) fn restore_type_password<const N: usize>(
    f: &mut Flow<'_, N>,
    password: &[u8],
    again: bool,
) {
    for &c in password {
        let page = (0..keyboard::PAGES)
            .find(|&p| {
                keyboard::zone(SCALE, p, keyboard::Target::Key(keyboard::Key::Char(c))).is_some()
            })
            .unwrap();
        loop {
            let State::BackupPassword { page: at, .. } = f.state() else {
                panic!("{:?}", f.state())
            };
            if at == page {
                break;
            }
            f.step(key(at, keyboard::Key::Page), &mut Live);
        }
        f.step(key(page, keyboard::Key::Char(c)), &mut Live);
    }
    let State::BackupPassword { page, again: now } = f.state() else {
        panic!()
    };
    assert_eq!(now, again);
    f.step(key(page, keyboard::Key::Ok), &mut Live);
}

/// Seed Tools' New Seed, from the home grid.
pub(crate) fn new_seed<const N: usize>(
    f: &mut Flow<'_, N>,
    rng: &mut impl Entropy,
) -> Option<Command> {
    f.step(card(2), rng);
    f.step(item(&menu::TOOLS, 0), rng);
    f.step(item(&menu::SEED_TOOLS, 0), rng).command
}

/// A live camera delta for the seed: 512 bytes, as a unit's sample is, of
/// varied, mostly non-zero values.
pub(crate) fn camera_sample(salt: u8) -> Vec<u8> {
    (0..512u32)
        .map(|i| (i.wrapping_mul(61).wrapping_add(u32::from(salt) * 7) % 251) as u8)
        .collect()
}

/// Tick a search to its end, answering Search to every batch; gives the
/// number of batches asked about.
pub(crate) fn swept<const N: usize>(f: &mut Flow<'_, N>) -> usize {
    let (mut ticks, mut asked) = (0, 0);
    loop {
        match f.state() {
            State::Searching { .. } => {
                f.step(
                    Event::Tick {
                        now_us: VERIFIED_US,
                    },
                    &mut Live,
                );
            }
            State::Asking { .. } => {
                asked += 1;
                f.touch(answer(dialog::Target::Accept));
            }
            _ => return asked,
        }
        ticks += 1;
        assert!(ticks < 100_000, "the search ends");
    }
}

// ── A bundle, as rusty-kaspa writes it ──────────────────────────────────────

/// One transaction with one input of `amount` locked to `spk` and these
/// outputs, as rusty-kaspa's PSKB: `PSKB` and the JSON's hex.
pub(crate) fn bundle_request(amount: u64, spk: &[u8], outputs: &[(u64, &[u8])]) -> Vec<u8> {
    let input = format!(
        "{{\"utxoEntry\":{{\"amount\":{amount},\"scriptPublicKey\":\"0000{}\",\"blockDaaScore\":0,\
         \"isCoinbase\":false}},\"previousOutpoint\":{{\"transactionId\":\"{}\",\"index\":0}},\
         \"sequence\":null,\"minTime\":null,\"partialSigs\":{{}},\"sighashType\":1,\
         \"redeemScript\":null,\"sigOpCount\":1,\"bip32Derivations\":{{}},\"finalScriptSig\":null,\
         \"proprietaries\":{{}}}}",
        hex(spk),
        "11".repeat(32),
    );
    let outs: Vec<String> = outputs
        .iter()
        .map(|(v, spk)| {
            format!(
                "{{\"amount\":{v},\"scriptPublicKey\":\"0000{}\",\"covenant\":null,\
                 \"redeemScript\":null,\"bip32Derivations\":{{}},\"proprietaries\":{{}}}}",
                hex(spk)
            )
        })
        .collect();
    let doc = format!(
        "[{{\"global\":{{\"version\":0,\"txVersion\":0,\"fallbackLockTime\":null,\
         \"inputsModifiable\":false,\"outputsModifiable\":false,\"inputCount\":1,\
         \"outputCount\":{},\"xpubs\":{{}},\"id\":null,\"proprietaries\":{{}},\"payload\":null}},\
         \"inputs\":[{input}],\"outputs\":[{}]}}]",
        outputs.len(),
        outs.join(",")
    );
    format!("PSKB{}", hex(doc.as_bytes())).into_bytes()
}

/// The master key of `m` with no passphrase.
pub(crate) fn master_of(m: &bip39::Mnemonic) -> kassigner_crypto::bip32::ExtendedPrivateKey {
    let mut scratch = vec![0u8; bip39::scratch_for(0)];
    let seed = bip39::to_seed(m, "", &mut scratch).unwrap();
    kassigner_crypto::bip32::ExtendedPrivateKey::from_seed(seed.as_bytes()).unwrap()
}

/// The private key at `path`, in lower-case hex.
pub(crate) fn private_hex(w: &Wallet, path: Path) -> String {
    hex(w.signing_key(path).unwrap().private_key())
}

/// Restore the xprv `k` from a card in memory, ending home with it in use.
pub(crate) fn restore_xprv(f: &mut Flow<'_, 6>, k: kassigner_crypto::bip32::ExtendedPrivateKey) {
    use kassigner_crypto::backup::{seal_slot, FILE_MAX};
    use kassigner_crypto::container::SealKdf;
    use kassigner_fat32::block::{Memory as Ram, BLOCK_SIZE};
    use kassigner_fat32::fat32::{create_file, do_format_fat32, mount_fat32};
    let password = b"Correct-Horse-9";
    let mut sd = Ram::new(vec![[0u8; BLOCK_SIZE]; 128 * 1024]);
    do_format_fat32(&mut sd).unwrap();
    let info = mount_fat32(&mut sd).unwrap();
    let mut out = [0u8; FILE_MAX];
    let n = seal_slot(
        &Slot::Xprv(k),
        password,
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut out,
    )
    .unwrap();
    create_file(&mut sd, &info, b"SD0001  KAS", &out[..n]).unwrap();
    let mut job = |f: &mut Flow<'_, 6>, job: Job| {
        let outcome = card::run(job, Kind::SdV2High, &mut sd, &mut f.card_request());
        f.step(Event::Card(outcome), &mut Live)
    };
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(
        tap_in(
            kassigner_fw::ui::backup::zone(SCALE, kassigner_fw::ui::backup::Target::Import)
                .unwrap(),
        ),
        &mut Live,
    );
    f.step(item(&menu::IMPORT, 0), &mut Live);
    f.step(item(&menu::IMPORT_SD, 0), &mut Live);
    job(f, Job::List);
    f.step(
        tap_in(
            kassigner_fw::ui::backup::pick_zone(
                SCALE,
                f.backups().len(),
                0,
                kassigner_fw::ui::backup::Pick::Row(0),
            )
            .unwrap(),
        ),
        &mut Live,
    );
    restore_type(f, password);
    restore_ok(f);
    job(f, Job::Read);
    let mut t = 1_000_000;
    while matches!(f.state(), State::RestoreOpening { .. }) {
        t += 1000;
        f.step(Event::Tick { now_us: t }, &mut Live);
    }
    opened(f);
    f.step(home_button(), &mut Live);
    assert_eq!(f.state(), State::Home);
}

// ── Import Raw Key ──────────────────────────────────────────────────────────

/// Import, Import Raw Key, from the home grid.
pub(crate) fn raw_key_keyboard<const N: usize>(f: &mut Flow<'_, N>) -> kassigner_fw::flow::Output {
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 1), &mut Live);
    f.step(
        tap_in(
            kassigner_fw::ui::backup::zone(SCALE, kassigner_fw::ui::backup::Target::Import)
                .unwrap(),
        ),
        &mut Live,
    );
    f.step(item(&menu::IMPORT, 2), &mut Live)
}

/// A tap on `key` of the hex keyboard, as it stands.
pub(crate) fn hex_key<const N: usize>(f: &Flow<'_, N>, key: keyboard::Key) -> Event<'static> {
    use kassigner_fw::flow::Typing;
    let mode = Typing::RawKey.mode(f.typed().0.len());
    tap_in(keyboard::zone_in(SCALE, keyboard::HEX_PAGE, mode, keyboard::Target::Key(key)).unwrap())
}

/// Type `hex` on the hex keyboard's upper-case keys.
pub(crate) fn type_hex<const N: usize>(f: &mut Flow<'_, N>, hex: &str) {
    for c in hex.bytes() {
        let tap = hex_key(f, keyboard::Key::Char(c.to_ascii_uppercase()));
        f.step(tap, &mut Live);
    }
}

// ── Sign Message ────────────────────────────────────────────────────────────

/// Tools, Sign Message, row `row`, from the home grid.
pub(crate) fn sign_message<const N: usize>(
    f: &mut Flow<'_, N>,
    row: usize,
) -> kassigner_fw::flow::Output {
    f.step(card(2), &mut Live);
    f.step(item(&menu::TOOLS, 2), &mut Live);
    assert_eq!(
        f.state(),
        State::Menu {
            menu: MenuId::SignMessage,
            page: 0
        }
    );
    f.step(item(&menu::SIGN_MESSAGE, row), &mut Live)
}

/// Type `text` on Sign Message's keyboard, a page at a time, and press OK.
pub(crate) fn type_message<const N: usize>(
    f: &mut Flow<'_, N>,
    text: &str,
) -> kassigner_fw::flow::Output {
    for c in text.bytes() {
        let k = if c == b' ' {
            keyboard::Key::Space
        } else {
            keyboard::Key::Char(c)
        };
        let page = (0..keyboard::PAGES)
            .find(|&p| keyboard::zone(SCALE, p, keyboard::Target::Key(k)).is_some())
            .unwrap();
        while let State::MessageType { page: at } = f.state() {
            if at == page {
                break;
            }
            f.step(key(at, keyboard::Key::Page), &mut Live);
        }
        f.step(key(page, k), &mut Live);
    }
    let State::MessageType { page } = f.state() else {
        panic!("{:?}", f.state())
    };
    f.step(key(page, keyboard::Key::Ok), &mut Live)
}

/// SIGN on SIGN MESSAGE?: the tap puts up SIGNING, which ignores taps, and
/// the next tick signs.
pub(crate) fn message_signed<const N: usize>(f: &mut Flow<'_, N>) -> kassigner_fw::flow::Output {
    read(f);
    let out = f.touch(answer(dialog::Target::Accept));
    assert_eq!(f.state(), State::MessageSigning, "the tap puts up SIGNING");
    assert_eq!(out.screen, Screen::MessageSigning);
    assert!(
        f.signature_text().is_empty(),
        "nothing signed on the tap's own step"
    );
    let out = f.step(back_button(), &mut Live);
    assert_eq!(
        out.screen,
        Screen::MessageSigning,
        "taps do nothing while it signs"
    );
    f.step(Event::Tick { now_us: 1 }, &mut Live)
}

// ── The v1.0.7 corpus ───────────────────────────────────────────────────────
//
// SeedQRs a v1.0.7 unit shows and requests kassigner.org 1.0.7 sends, from
// `spec/vectors/v107`, whose `MANIFEST.md` says how each was made. The
// requests spend abandon 12's coins and a 2-of-3 of abandon 12, abandon 24
// and zoo 12.

/// A corpus file, built into the test.
macro_rules! corpus {
    ($path:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/v107/",
            $path
        ))
    };
}
pub(crate) use corpus;

/// The corpus's seeds, as v1.0.7 was given them.
pub(crate) const ABANDON12: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
/// The 2-of-3's cosigner kpubs, `m/45'/111111'/0'`, as v1.0.7 exports
/// them.
pub(crate) const ABANDON12_KPUB45: &str = "kpub2JKepGqGb3usUsEfD7JgwbFZav8Nu2z4dBZQ42hg8JUGnCbLUb9phbpZW2TQuk2DmayefGMiVzCK7EL9hPbr2K2vVzSk8SpuUwwqTLq8y14";
pub(crate) const ABANDON24_KPUB45: &str = "kpub2JG8myov28wfetFRquaJtuTJpL3jhYnBhu2V6ZuwHnDqPBAoyqgJKkQiba4wLfU9JcsNBBoBTm7zPtk1Nv4Nn36tUkoZWGUXjWn1aJCajdW";
pub(crate) const ZOO12_KPUB45: &str = "kpub2HgQUMVzkWe8YCDJDEg5zdMAiKnFE3inHgrv7VRUCxKanfXpGnPpSut8MQUHYBcSFKxDhNJKCFJTy6BSdUhXKd1VbrFdFRrJ2thq3ZJfPUU";

/// The fingerprint of the wallet `words` open.
pub(crate) fn fingerprint_of(words: &str) -> [u8; 4] {
    let m = bip39::from_words(words.split(' ')).expect("words");
    let mut scratch = vec![0u8; bip39::scratch_for(0)];
    Wallet::open(&Slot::mnemonic(m, b"").expect("slot"), &mut scratch)
        .expect("wallet")
        .fingerprint()
}

/// One input of a request or reply: its signature hash, script and redeem
/// script.
pub(crate) struct Spent {
    pub(crate) digest: [u8; 32],
    pub(crate) script: Vec<u8>,
    pub(crate) redeem: Vec<u8>,
}

pub(crate) fn blank_in() -> TransactionInput<'static> {
    TransactionInput {
        previous_outpoint: Outpoint {
            transaction_id: [0u8; 32],
            index: 0,
        },
        sequence: 0,
        sig_op_count: 0,
        compute_budget: 0,
        signature_script: &[],
        utxo_entry: UtxoEntry {
            amount: 0,
            script_public_key: ScriptPublicKey {
                version: 0,
                script: &[],
            },
        },
    }
}

pub(crate) fn blank_out() -> TransactionOutput<'static> {
    TransactionOutput {
        value: 0,
        script_public_key: ScriptPublicKey {
            version: 0,
            script: &[],
        },
        covenant: None,
    }
}

/// The inputs of a KSPT, in any version.
pub(crate) fn kspt_spent(k: &kspt::Kspt<'_>) -> Vec<Spent> {
    let mut ins = vec![blank_in(); 8];
    let mut outs = vec![blank_out(); 8];
    let (ni, no) = kspt_tx::fill(k, &mut ins, &mut outs).expect("fill");
    let tx = kspt_tx::build(k, &ins[..ni], &outs[..no]);
    k.inputs()
        .enumerate()
        .map(|(i, input)| Spent {
            digest: schnorr_signature_hash(&tx, i, SIG_HASH_ALL).expect("an input"),
            script: tx.inputs[i].utxo_entry.script_public_key.script.to_vec(),
            redeem: input.redeem.to_vec(),
        })
        .collect()
}

/// Step through the words of a seed being made or shown, checking each
/// against `phrase`.
pub(crate) fn words_through<const N: usize>(f: &mut Flow<'_, N>, phrase: &bip39::Mnemonic) {
    for i in 0..phrase.len() {
        assert_eq!(f.state(), State::ShowWords { pos: i as u8 });
        assert_eq!(f.shown_word(), phrase.word(i), "word {i}");
        f.step(
            tap_in(
                kassigner_fw::ui::words::count_zone(
                    SCALE,
                    kassigner_fw::ui::words::Target::Words(12),
                )
                .unwrap(),
            ),
            &mut Live,
        );
    }
}

/// A word on CHECK, the `k`th offered.
pub(crate) fn on_choice(k: usize) -> Event<'static> {
    use kassigner_fw::ui::words::{check_zone, CheckTarget};
    tap_in(check_zone(SCALE, CheckTarget::Choice(k)).expect("a word offered"))
}

/// CHECK through its rounds, picking each word from `phrase`, then tick
/// past BACKUP CHECKED.
pub(crate) fn pass_check<const N: usize>(f: &mut Flow<'_, N>, phrase: &bip39::Mnemonic) {
    for round in 0..CHECK_ROUNDS {
        assert_eq!(f.state(), State::WordCheck { round });
        let (place, offered) = f.check_words().expect("words offered");
        let right = phrase
            .word(usize::from(place))
            .expect("a place in the phrase");
        let k = offered
            .iter()
            .position(|w| *w == right)
            .expect("the right word offered");
        assert_eq!(
            offered.iter().filter(|w| **w == right).count(),
            1,
            "offered once"
        );
        f.touch(on_choice(k));
    }
    assert!(
        matches!(f.state(), State::BackupChecked { .. }),
        "{:?}",
        f.state()
    );
    f.step(
        Event::Tick {
            now_us: f.now_us() + ERROR_US,
        },
        &mut Live,
    );
}

/// Whether the seed in use's row says it has a backup.
pub(crate) fn in_use_backed<const N: usize>(f: &Flow<'_, N>) -> bool {
    (0..f.seed_count())
        .filter_map(|r| f.seed(r))
        .find(|s| s.active)
        .expect("a seed in use")
        .backed
}
