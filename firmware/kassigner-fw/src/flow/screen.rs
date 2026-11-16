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

//! What the loop should draw, and the numbers it needs.

use super::*;

/// Backups SELECT BACKUP lists at most.
pub const RESTORE_MAX: usize = 64;

/// What the loop should draw, and the numbers it needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    /// The logo and the unit's information, while the checks run.
    Booting,
    /// The red screen.
    Halted(Halt),
    /// The verification screen.
    Verified(brand::Check),
    /// The home grid.
    Home,
    /// Everything a seed left was wiped.
    Wiped,
    /// A list menu, at a page.
    Menu { menu: MenuId, page: usize },
    /// The seeds, at a page: each read through [`Flow::seed`].
    Seeds { page: usize },
    /// The viewfinder and the frames collected so far, bit `i` of `received`
    /// for frame `i`. With `hint`, a line says how else to load a seed the
    /// scan takes for a frame ([`Event::LastFrameOrSeed`]).
    Scanning {
        have: usize,
        total: usize,
        received: u64,
        hint: bool,
    },
    /// CHECKING: a request read whole, planned on the next step.
    Checking,
    /// Review page `index` of `pages`, read through [`Flow::review`].
    Page { index: usize, pages: usize },
    /// CONFIRM SEND?, its totals read through [`Flow::totals`].
    Confirm,
    /// SIGNING: the next step signs.
    Signing,
    /// SIGNED TX QR: Wallet or KasSigner, each hinted from
    /// [`Flow::reply_codes`].
    ReplyFormat,
    /// QR DISPLAY MODE for the reply's frames.
    ReplyMode,
    /// SIGNED TX: Save to SD, or Back to QR.
    ReplyDone,
    /// MESSAGE EXPORTED: Save to SD, or Back to QR.
    MessageDone,
    /// ADDRESS EXPORTED: Save to SD, or Back to QR.
    AddressDone,
    /// SEED EXPORTED: Save to SD, or Back to QR.
    SeedDone,
    /// The reply, frame `frame` of `frames`, its code from
    /// [`Flow::reply_code`]. Reached only once every signature on it is read
    /// back and verified.
    Reply { frame: u8, frames: u8 },
    /// A refusal.
    Refused(Refusal),
    /// The seed being collected: bits so far, bits each source must reach,
    /// and the source still short, if any.
    Generating {
        credited: u32,
        share: u32,
        short: Option<Source>,
    },
    /// Search on for a request's keys, or not, after `checked` addresses.
    Asking { checked: usize },
    /// The search: `done` keys of `total`.
    Searching { done: usize, total: usize },
    /// Load a SeedQR of this many words, or not.
    Loading { words: usize },
    /// A wallet being opened: `done` steps of `total`.
    Opening { done: usize, total: usize },
    /// Delete this slot ([`Flow::seed`]), or not. `hold` is `None` until
    /// Delete is tapped, then how far a finger has held it, 0 to 100.
    Deleting { slot: usize, hold: Option<u8> },
    /// The backlight's level, 0 to 255.
    Display { level: u8 },
    /// The volume, 0 to 255.
    Audio { level: u8 },
    /// Settings' About: the verification screen with the unit's name, so the
    /// hash can be compared without a reboot.
    About(brand::Check),
    /// The tuning screen: the knob picked ([`Flow::knobs`]) and its value,
    /// and the exposure loop's switch if the unit has one.
    CameraTune {
        knob: usize,
        value: u8,
        auto: Option<bool>,
    },
    /// Settings' SD Card, with what the slot holds.
    Card { status: card::Status },
    /// The keyboard for `typing`, at `page`. The text is not here:
    /// [`Flow::typed`] gives it for drawing; `field` says only that it
    /// changed.
    Keyboard {
        typing: Typing,
        page: u8,
        field: Field,
    },
    /// Format the card, or not. `hold` as [`Screen::Deleting`]'s.
    CardFormat { hold: Option<u8> },
    /// A card job running.
    CardBusy(Job),
    /// How it went.
    CardDone { job: Job, outcome: Outcome },
    /// Tools' Import / Export.
    ImportExport,
    /// Backup to SD's warning.
    BackupWarning,
    /// Overwrite `name`, or not.
    BackupOverwrite { name: card::FileName },
    /// The seed being sealed: `done` of `total` rounds.
    BackupSealing { done: u32, total: u32 },
    /// SELECT BACKUP: `count` backups named by [`Flow::backups`], and
    /// `extra` more files than the list holds.
    RestoreList {
        page: usize,
        count: usize,
        extra: u16,
    },
    /// A backup being opened: `done` of `total`.
    RestoreOpening { done: u32, total: u32 },
    /// A Seed Tools row's 12 or 24.
    WordCount { action: CountFor },
    /// A word being typed, its letters not here: `pos` of `of`, `filled`
    /// entered; `invalid` once the phrase failed its checksum.
    Words {
        action: WordsFor,
        pos: u8,
        of: u8,
        filled: u8,
        field: Field,
        invalid: bool,
    },
    /// Calc Last Word's last word of `of`, `choices` valid; which is shown
    /// is a seed's bits, hidden from the console.
    LastWord { of: u8, choices: u16, at: Hidden },
    /// The address at `index`, change chain or not; `single` for a raw
    /// key's one address. Public: the console may print it.
    Address {
        change: bool,
        index: u32,
        single: bool,
    },
    /// The address as a code.
    AddressQr { change: bool, index: u32 },
    /// Private Key: the address screen showing the key of the address at
    /// `index`, or a raw key's one key when `single`. The key is never here:
    /// [`Flow::key_text`] gives it for drawing.
    PrivateKey {
        change: bool,
        index: u32,
        single: bool,
    },
    /// The private key as a code, drawn from `Flow::key_code`.
    PrivateKeyQr { change: bool, index: u32 },
    /// kprv Master, or kprv Account, as text from [`Flow::key_text`].
    Kprv { master: bool },
    /// The kprv as a code, drawn from `Flow::key_code`.
    KprvQr { master: bool },
    /// The master key being derived.
    KprvDeriving,
    /// Private Key's key being derived.
    KeyDeriving,
    /// Multisig Address's keys being derived: `done` key-branch pairs of
    /// `total`.
    GroupDeriving { done: usize, total: usize },
    /// Import Raw Key's check: the key's address ([`Flow::address_text`]),
    /// confirmed or not.
    RawKeyConfirm,
    /// Sign Message's camera: frames received, as [`Screen::Scanning`]'s.
    MessageScan {
        have: usize,
        total: usize,
        received: u64,
    },
    /// Sign Message's text ([`Flow::message_text`]), `page` of `pages`;
    /// `signed` when read back with its signature, to be checked. `live`
    /// when the middle button acts: CHECK always, SIGN once the last page
    /// has been shown.
    MessagePreview {
        page: usize,
        pages: usize,
        signed: bool,
        live: bool,
    },
    /// A signed message checked: valid, not, or `None` for an address with
    /// no key to check against.
    MessageCheck { valid: Option<bool> },
    /// The Address screen choosing the address that signs.
    SignWith { change: bool, index: u32 },
    /// Sign Message's question, the address from [`Flow::address_text`].
    MessageConfirm,
    /// SIGNING a message: the next step signs.
    MessageSigning,
    /// The signature ([`Flow::signature_text`]), or the signing address.
    MessageResult { page: u8 },
    /// The signed message's code: Wallet or KasSigner.
    MessageFormat,
    /// Its frames: Auto Cycle or Manual.
    MessageMode,
    /// The signed message as a code ([`Flow::message_frame`]), `frame` of
    /// `frames`.
    MessageFrames { frame: u8, frames: u8 },
    /// The keypad, `len` digits of `typed` so far.
    AddressIndex {
        typed: Hidden<[u8; INDEX_DIGITS]>,
        len: u8,
    },
    /// Dice Seed: `rolled` of `target` rolls; the faces are not here.
    Dice { rolled: u16, target: u16 },
    /// The rolls did not look like dice.
    DiceRefused,
    /// UNEVEN ROLLS, the face and its count read through
    /// [`Flow::dice_uneven`], never here.
    DiceUneven,
    /// BIP85 Child: a `words`-word child at `index`.
    Bip85 { words: u8, index: Hidden<u32> },
    /// The keypad, for the child's index.
    Bip85Index {
        typed: Hidden<[u8; INDEX_DIGITS]>,
        len: u8,
    },
    /// The child being derived.
    Bip85Deriving,
    /// A new seed's word at `pos` of `of`, the word not here.
    ShowWords { pos: u8, of: u8 },
    /// BACKUP CHECK, for the words or a code (`qr`): CHECK or LATER.
    BackupAsk { qr: bool },
    /// CHECK `round`/3: which word is at `place`; the four offered are read
    /// through [`Flow::check_words`], never here.
    WordCheck { round: u8, place: u8 },
    /// A wrong word, or a scanned copy that is not this seed (`qr`).
    CheckFailed { qr: bool },
    /// The camera up for a code's copy, as [`Screen::Scanning`].
    BackupScan {
        have: usize,
        total: usize,
        received: u64,
    },
    /// BACKUP CHECKED.
    BackupChecked,
    /// The seed in use as a SeedQR, drawn from the flow, never here.
    SeedQr { compact: bool },
    /// The SeedQR's grid view from module `x`, `y`.
    SeedQrGrid { compact: bool, x: u8, y: u8 },
    /// The words as plain text in a code.
    PlainQr,
    /// The words' code: Wallet or KasSigner.
    PlainFormat,
    /// Its frames: Auto Cycle or Manual.
    PlainMode,
    /// The words in frames ([`Flow::plain_frame`]), `frame` of `frames`: a
    /// secret, drawn from the flow, never here.
    PlainFrames { frame: u8, frames: u8 },
    /// KPUB EXPORT QR.
    KpubFormat,
    /// QR DISPLAY MODE.
    KpubMode,
    /// The kpub, frame `frame` of `frames`; public, but drawn from the flow
    /// too.
    KpubQr { frame: u8, frames: u8 },
    /// KPUB EXPORTED.
    KpubExported,
    /// ENCRYPT FILE?
    KpubEncrypt,
    /// KPUB SCANNED.
    KpubScanned,
    /// CREATE MULTISIG: `m` of `n`.
    CreateMultisig { m: u8, n: u8 },
    /// KEY `key`/`of`.
    AddKey { key: u8, of: u8 },
    /// COSIGNER KEY.
    CosignerKey,
    /// DESCRIPTOR: the held group ([`Flow::group`],
    /// [`Flow::group_key_text`]), the seed in use's key at `own`.
    Descriptor { own: Option<u8> },
    /// DESCRIPTOR QR: Wallet or KasSigner, their codes from
    /// [`Flow::descriptor_codes`].
    DescriptorFormat,
    /// Its frames: Auto Cycle or Manual.
    DescriptorMode,
    /// The descriptor as a code ([`Flow::descriptor_frame`]), `frame` of
    /// `frames`.
    DescriptorFrames { frame: u8, frames: u8 },
    /// LOAD MULTISIG?: the `m`-of-`n` group read, the seed in use's place in
    /// it, and what it does to the group held.
    LoadGroup {
        m: usize,
        n: usize,
        seed: multisig_screen::SeedIn,
        held: multisig_screen::Held,
    },
    /// MULTISIG ADDRESS: the address read from the file `name`, through
    /// [`Flow::file_address`].
    FileAddress { name: card::FileName },
    /// Its code, alone.
    FileAddressQr,
    /// SAVINGS CARD at `page`, through [`Flow::savings_shown`].
    Savings { page: u8 },
    /// SAVINGS CARD at `page`, searching at receive key `at`; only the
    /// search's button changes.
    SavingsSearching { page: u8, at: u32 },
    /// SAVINGS CARD QR: Wallet or KasSigner, their codes from
    /// [`Flow::savings_codes`].
    SavingsFormat,
    /// Its frames: Auto Cycle or Manual.
    SavingsMode,
    /// The backup line as a code ([`Flow::savings_frame`]), `frame` of
    /// `frames`.
    SavingsFrames { frame: u8, frames: u8 },
    /// Its address's code alone ([`Flow::savings_address_code`]).
    SavingsAddressQr,
    /// SELECT SEED at `page`, for key `key`/`of`; rows through
    /// [`Flow::seed`].
    SelectSeed { page: usize, key: u8, of: u8 },
    /// KCC-3 Address: the seed's KCC-3 address at `index`, change chain or
    /// not, `<P> OP_CHECKSIG` behind its hash ([`Flow::address_text`]).
    Kcc3Address { change: bool, index: u32 },
    /// Multisig Address: the held group's address at `index`, change chain
    /// or not, on cosigner `cosigner`'s branch ([`Flow::address_text`]); the
    /// M of N through [`Flow::group`].
    GroupAddress {
        change: bool,
        index: u32,
        cosigner: u8,
    },
    /// Delete `name` from the card, or not; `hold` as [`Screen::Deleting`]'s.
    RestoreDelete {
        name: card::FileName,
        hold: Option<u8>,
    },
    /// STEGANOGRAPHY: the three carrier cards.
    StegoCarrier,
    /// IMAGE DESCRIPTOR's preview ([`Flow::descriptor`]): EDIT or USE.
    StegoPreview,
    /// ADD HINT?
    StegoHintAsk,
    /// RECOVERY HINT: the presets and Custom.
    StegoHint,
    /// HIDE BACKUP?: the photo ([`Flow::photo_name`]), the carrier
    /// ([`Flow::carrier`]), the descriptor, and whether a hint goes too.
    StegoConfirm { hint: bool },
    /// EMBEDDING: the payload going into the photo.
    StegoEmbedding,
    /// BACKUP HIDDEN: the photo and the carrier.
    StegoDone,
    /// READING: both carriers being read from the photo.
    StegoReading,
    /// LOAD SEED?: a `words`-word seed found in `carrier`; `two` when the
    /// photo held a second, different backup.
    StegoFound {
        words: u8,
        carrier: Carrier,
        two: bool,
    },
    /// RECOVERY HINT: the hint from [`Flow::hint`].
    StegoHintShown,
    /// OVERWRITE?: the photo holds a backup.
    StegoOverwrite,
}

impl Screen {
    /// Whether drawing this screen puts a secret on the panel: a seed's
    /// words (shown, checked or typed), a SeedQR or the words as text, a
    /// kprv or private key, a steganography descriptor or hint, or a
    /// keyboard typing a secret.
    ///
    /// Drawing one leaves the secret below the caller's frame, as pixels in
    /// the band it was composed in and in the encoder's scratch, so the loop
    /// scrubs the stack after it.
    ///
    /// No wildcard: a new screen does not compile here until someone says
    /// whether it shows a secret.
    pub const fn shows_secret(&self) -> bool {
        match self {
            Screen::ShowWords { .. }
            | Screen::WordCheck { .. }
            | Screen::Words { .. }
            | Screen::LastWord { .. }
            | Screen::SeedQr { .. }
            | Screen::SeedQrGrid { .. }
            | Screen::PlainQr
            | Screen::PlainFrames { .. }
            | Screen::Kprv { .. }
            | Screen::KprvQr { .. }
            | Screen::PrivateKey { .. }
            | Screen::PrivateKeyQr { .. }
            | Screen::StegoPreview
            | Screen::StegoConfirm { .. }
            | Screen::StegoHintShown => true,
            Screen::Keyboard { typing, .. } => typing.secret(),
            Screen::Booting
            | Screen::Halted(_)
            | Screen::Verified(_)
            | Screen::Home
            | Screen::Wiped
            | Screen::Menu { .. }
            | Screen::Seeds { .. }
            | Screen::Scanning { .. }
            | Screen::Checking
            | Screen::Page { .. }
            | Screen::Confirm
            | Screen::Signing
            | Screen::ReplyFormat
            | Screen::ReplyMode
            | Screen::ReplyDone
            | Screen::MessageDone
            | Screen::AddressDone
            | Screen::SeedDone
            | Screen::Reply { .. }
            | Screen::Refused(_)
            | Screen::Generating { .. }
            | Screen::Asking { .. }
            | Screen::Searching { .. }
            | Screen::Loading { .. }
            | Screen::Opening { .. }
            | Screen::Deleting { .. }
            | Screen::Display { .. }
            | Screen::Audio { .. }
            | Screen::About(_)
            | Screen::CameraTune { .. }
            | Screen::Card { .. }
            | Screen::CardFormat { .. }
            | Screen::CardBusy(_)
            | Screen::CardDone { .. }
            | Screen::ImportExport
            | Screen::StegoCarrier
            | Screen::StegoHintAsk
            | Screen::StegoHint
            | Screen::StegoEmbedding
            | Screen::StegoDone
            | Screen::StegoReading
            | Screen::StegoFound { .. }
            | Screen::StegoOverwrite
            | Screen::BackupWarning
            | Screen::BackupOverwrite { .. }
            | Screen::BackupSealing { .. }
            | Screen::RestoreList { .. }
            | Screen::RestoreOpening { .. }
            | Screen::WordCount { .. }
            | Screen::Address { .. }
            | Screen::AddressQr { .. }
            | Screen::KprvDeriving
            | Screen::KeyDeriving
            | Screen::GroupDeriving { .. }
            | Screen::RawKeyConfirm
            | Screen::MessageScan { .. }
            | Screen::MessagePreview { .. }
            | Screen::MessageCheck { .. }
            | Screen::SignWith { .. }
            | Screen::MessageConfirm
            | Screen::MessageSigning
            | Screen::MessageResult { .. }
            | Screen::MessageFormat
            | Screen::MessageMode
            | Screen::MessageFrames { .. }
            | Screen::AddressIndex { .. }
            | Screen::Dice { .. }
            | Screen::DiceRefused
            | Screen::DiceUneven
            | Screen::BackupAsk { .. }
            | Screen::CheckFailed { .. }
            | Screen::BackupScan { .. }
            | Screen::BackupChecked
            | Screen::Bip85 { .. }
            | Screen::Bip85Index { .. }
            | Screen::Bip85Deriving
            | Screen::PlainFormat
            | Screen::PlainMode
            | Screen::KpubFormat
            | Screen::KpubMode
            | Screen::KpubQr { .. }
            | Screen::KpubExported
            | Screen::KpubEncrypt
            | Screen::KpubScanned
            | Screen::CreateMultisig { .. }
            | Screen::AddKey { .. }
            | Screen::CosignerKey
            | Screen::Descriptor { .. }
            | Screen::DescriptorFormat
            | Screen::DescriptorMode
            | Screen::DescriptorFrames { .. }
            | Screen::LoadGroup { .. }
            | Screen::FileAddress { .. }
            | Screen::FileAddressQr
            | Screen::Savings { .. }
            | Screen::SavingsSearching { .. }
            | Screen::SavingsFormat
            | Screen::SavingsMode
            | Screen::SavingsFrames { .. }
            | Screen::SavingsAddressQr
            | Screen::SelectSeed { .. }
            | Screen::GroupAddress { .. }
            | Screen::Kcc3Address { .. }
            | Screen::RestoreDelete { .. } => false,
        }
    }
}
