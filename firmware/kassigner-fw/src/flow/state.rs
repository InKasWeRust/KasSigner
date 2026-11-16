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

//! The flow's states and menus, and the menu states screens go back to.

use super::*;

// ── What the flow answers ───────────────────────────────────────────────────

/// Where the flow is. Public so a loop can log it and a test assert it;
/// only the flow moves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Waiting for [`Event::Booted`].
    Boot,
    /// A fault the unit cannot run with. Never left.
    Halted(Halt),
    /// The verification screen: for [`VERIFIED_US`], or until a tap with
    /// anything in red ([`brand::Check::red`]).
    Verified(brand::Check),
    /// The home grid.
    Home,
    /// Home's logo was held for [`WIPE_HOLD_US`] and everything a seed left
    /// wiped: said for [`WIPED_US`], then home.
    Wiped,
    /// A list menu, at a page.
    Menu { menu: MenuId, page: usize },
    /// The seeds, at a page.
    Seeds { page: usize },
    /// The camera is up, reading a request or a SeedQR.
    Scanning,
    /// A request read whole, from the camera or the card (`card`), in the
    /// request buffer's first `len` bytes: CHECKING is up and the next tick
    /// plans it, so a large request's scan does not look frozen.
    Checking { len: usize, card: bool },
    /// No address checked so far signs the request: search the next batch,
    /// or not. `next` is where the sweep got to; `kcc3` for the KCC-3 sweep.
    Asking { next: usize, kcc3: bool },
    /// Searching the seed's addresses for a request's keys: the sweep's next
    /// key, where this batch stops, and whether to ask before going past it.
    /// `kcc3` for the KCC-3 sweep, whose keys no pump derives ahead.
    Searching {
        next: usize,
        stop: usize,
        ask: bool,
        kcc3: bool,
    },
    /// A request's pages being shown.
    Reviewing,
    /// CONFIRM SEND?: every page has been shown, and CONFIRM signs.
    Confirming,
    /// CONFIRM was tapped: SIGNING is up and the next tick signs, so the
    /// tap clicks and SIGNING is drawn before the signing holds the unit.
    Signing,
    /// The reply at `frame` of [`Flow::reply_frames`]; frames turn by Auto
    /// Cycle or a tap per frame.
    Showing { frame: u8 },
    /// SIGNED TX QR, first after signing: the reply for a wallet or another
    /// unit.
    ReplyFormat,
    /// QR DISPLAY MODE for a reply in frames: Auto Cycle or Manual.
    ReplyMode,
    /// SIGNED TX: after the reply's codes, Save to SD or Back to QR.
    ReplyDone,
    /// MESSAGE EXPORTED: after the signed message's codes, the same.
    MessageDone,
    /// ADDRESS EXPORTED: after an address's code, the same.
    AddressDone,
    /// SEED EXPORTED: after a SeedQR's grid, or Plain Text QR (`plain`),
    /// the same; Save to SD is the seed's sealed backup.
    SeedDone { plain: bool, compact: bool },
    /// A refusal, shown for [`REFUSED_US`].
    Refused(Refusal),
    /// A seed is being collected from this unit's sources.
    Generating,
    /// A SeedQR was read and waits for Load or Cancel. Nothing is stored.
    Loading,
    /// Load was tapped: the passphrase on the keyboard at this page. OK with
    /// nothing typed stores the seed with none; typed, OK asks for it again.
    /// Nothing is stored before.
    Passphrase { page: u8 },
    /// The passphrase typed again, the keyboard at this page: OK stores the
    /// seed only if both match; a mismatch starts both again.
    PassphraseAgain { page: u8 },
    /// Slot `slot`'s wallet being opened, a step per tick so the screen can
    /// say how far.
    Opening { slot: usize },
    /// Asking before slot `slot` is wiped. Delete arms the answer, and the
    /// slot goes only once a finger holds it for [`HOLD_US`]; `held_since`
    /// is when the finger went down on it.
    Deleting {
        slot: usize,
        armed: bool,
        held_since: Option<u64>,
    },
    /// Settings' Display: the backlight's level.
    Display,
    /// Settings' Audio: the volume.
    Audio,
    /// Settings' About: the logo screen, until a tap.
    About,
    /// Settings' Camera: the tuning screen, `knob` picked.
    CameraTune { knob: usize },
    /// Settings' SD Card: what the slot holds, and Format and Test.
    Card,
    /// Asking before the card is formatted, as a seed's delete does: armed
    /// by Format, then held for [`HOLD_US`].
    CardFormat {
        armed: bool,
        held_since: Option<u64>,
    },
    /// A job on the card, until the binary says how it went.
    CardBusy(Job),
    /// How a job went, for [`card_done_us`], then back to the SD Card
    /// screen or Seed Backup, where it started.
    CardDone { job: Job, outcome: Outcome },
    /// Tools' Import / Export: two buttons.
    ImportExport,
    /// Backup to SD's warning, until I understand.
    BackupWarning,
    /// The backup's file name on the keyboard.
    BackupName { page: u8 },
    /// The name is on the card already: overwrite it, or not.
    BackupOverwrite,
    /// The file under the name is sealed: its own password on the keyboard
    /// at this page before it is written over, as a delete asks.
    OverwritePassword { page: u8 },
    /// That file being opened, as a restore does: in batches under PBKDF2,
    /// at half under Argon2id.
    OverwriteOpening { done: u32 },
    /// The backup's password on the keyboard, and `again` the second time.
    BackupPassword { page: u8, again: bool },
    /// Sealing the seed under the password: under PBKDF2 a batch of rounds
    /// a tick, `done` so far; under Argon2id one tick, the bar at half.
    BackupSealing { done: u32 },
    /// SELECT BACKUP, at this page.
    RestoreList { page: usize },
    /// The chosen backup's password on the keyboard.
    RestorePassword { page: u8 },
    /// Delete the chosen backup from the card, or not: armed by DELETE, then
    /// held for [`HOLD_US`]. The list was at `page`.
    RestoreDelete {
        page: usize,
        armed: bool,
        held_since: Option<u64>,
    },
    /// Opening it: in batches under PBKDF2, at half under Argon2id.
    RestoreOpening { done: u32 },
    /// A Seed Tools row's 12 or 24 words.
    WordCount { action: CountFor },
    /// Words typed one at a time, the arrows moving between them.
    Words { action: WordsFor },
    /// Calc Last Word's last word, the `choice`th valid one.
    LastWord { choice: u16 },
    /// Seed Tools' Address, its chain and index kept in the flow. Signing
    /// Keys' Private Key is this screen showing the address's private key
    /// (`Flow::addr_key`).
    Address,
    /// The address, or its private key, alone as a code.
    AddressQr,
    /// The keypad, for the index to go to.
    AddressIndex,
    /// Signing Keys' kprv Master, or kprv Account: the key as text.
    Kprv { master: bool },
    /// The kprv alone, as a code.
    KprvQr { master: bool },
    /// The master key being derived on the next tick.
    KprvDeriving,
    /// Private Key's key being derived on the next tick, on opening and
    /// after each change of chain or index, so the screen does not look stuck.
    KeyDeriving,
    /// Multisig Address opening for a group the first time: its keys derived
    /// to every branch and chain ([`Branches`]), a key and branch a tick,
    /// under DERIVING. Its address follows the tick after.
    GroupDeriving,
    /// Import Raw Key: a private key typed in hex, on the hex keyboard.
    RawKey,
    /// The typed key's address, to confirm before it is stored.
    RawKeyConfirm,
    /// Sign Message: the text typed.
    MessageType { page: u8 },
    /// Sign Message: the text scanned, in one code or in frames.
    MessageScan,
    /// Sign Message: the text, a page at a time.
    MessagePreview { page: usize },
    /// Sign Message: the address that signs, asked.
    MessageConfirm,
    /// SIGN was tapped on SIGN MESSAGE?: SIGNING is up and the next tick
    /// signs, as in [`State::Signing`].
    MessageSigning,
    /// A signed message read back, checked.
    MessageCheck { valid: Option<bool> },
    /// Sign Message's result: the signature, then the signing address.
    MessageResult { page: u8 },
    /// How the signed message's code is shown: Wallet (one code) or
    /// KasSigner (frames another unit reads).
    MessageFormat,
    /// Its frames: Auto Cycle or Manual.
    MessageMode,
    /// The signed message shown: `frame` of [`Flow::message_frames`].
    MessageFrames { frame: u8 },
    /// Dice Seed: rolls tapped in, `Flow::rolls` holding them.
    Dice,
    /// The rolls did not look like dice: said, then Seed Tools.
    DiceRefused,
    /// UNEVEN ROLLS: a face came up under [`DICE_UNEVEN_PERCENT`] of the
    /// rolls; the seed is made and waits. ROLL AGAIN or USE THEM: a warning,
    /// not a refusal.
    DiceUneven,
    /// BIP85 Child: the index to derive at.
    Bip85,
    /// The keypad, for the child's index.
    Bip85Index,
    /// The child being derived, on the next tick.
    Bip85Deriving,
    /// A new seed's words, one at a time, at `pos`, to write down before the
    /// seed goes on (a dice seed to its passphrase, a new seed or BIP85 child
    /// stored); or Show Seed Words' for the seed in use.
    ShowWords { pos: u8 },
    /// BACKUP CHECK: a seed made here, its words or code just shown, checked
    /// now or LATER. Until it is checked, it can only be backed up.
    BackupAsk { by: Check },
    /// CHECK n/3: the word at a random place, chosen out of four; `round`
    /// of [`CHECK_ROUNDS`].
    WordCheck { round: u8 },
    /// A wrong word, or a scanned copy that is not this seed: said for
    /// [`ERROR_US`], then the words from the first, or BACKUP CHECK for a
    /// code.
    CheckFailed { by: Check },
    /// The camera up to read back the copy made of a code shown, which must
    /// be the seed in use.
    BackupScan { plain: bool, compact: bool },
    /// BACKUP CHECKED: said for [`CHECKED_US`], then on, as checked `by`.
    BackupChecked { by: Check },
    /// QR Export: the seed in use as a SeedQR, full screen.
    SeedQr { compact: bool },
    /// The SeedQR's grid view from module `x`, `y`.
    SeedQrGrid { compact: bool, x: u8, y: u8 },
    /// The seed in use's words as plain text in one code: Wallet's, or
    /// KasSigner's when they fit one.
    PlainQr,
    /// How the words' code is shown: Wallet (one code up to version 9) or
    /// KasSigner (version-3 frames every unit reads).
    PlainFormat,
    /// Its frames: Auto Cycle or Manual.
    PlainMode,
    /// The words in frames: `frame` of [`Flow::plain_codes`].
    PlainFrames { frame: u8 },
    /// KPUB EXPORT QR: one code, or two frames.
    KpubFormat,
    /// QR DISPLAY MODE: the two frames cycling, or a tap each.
    KpubMode,
    /// The kpub shown, at `frame`.
    KpubQr { frame: u8 },
    /// KPUB EXPORTED: save to the card, or show again.
    KpubExported,
    /// ENCRYPT FILE? for the kpub to be written.
    KpubEncrypt,
    /// KPUB SCANNED: a kpub read by the camera.
    KpubScanned,
    /// CREATE MULTISIG: `m` signatures required of `n` keys, set with "-"
    /// and "+" before NEXT.
    CreateMultisig { m: u8, n: u8 },
    /// KEY k/N: where the group's next key comes from, `k` one past those
    /// [`Flow::forming`] holds.
    AddKey,
    /// COSIGNER KEY: the warning before a cosigner's key is scanned.
    CosignerKey,
    /// SELECT SEED, at a page: a seed held here, whose cosigner key is the
    /// group's next.
    SelectSeed { page: usize },
    /// DESCRIPTOR: the held group's keys, and the seed in use's place among
    /// them.
    Descriptor,
    /// DESCRIPTOR QR: Wallet (one code or version-9 frames) or KasSigner
    /// (version-3 frames another unit reads).
    DescriptorFormat,
    /// Its frames: Auto Cycle or Manual.
    DescriptorMode,
    /// The descriptor at `frame` of [`Flow::descriptor_codes`].
    DescriptorFrames { frame: u8 },
    /// LOAD MULTISIG?: a group read from a descriptor file, to replace the
    /// group held if accepted.
    LoadGroup,
    /// MULTISIG ADDRESS: an address read from a file, as written there.
    FileAddress,
    /// Its code.
    FileAddressQr,
    /// SAVINGS CARD at this page: a Time-Locked Savings card from its backup
    /// line, scanned or from a file ([`Flow::savings_shown`]).
    Savings { page: u8 },
    /// SAVINGS CARD at this page, searching the seed in use's receive keys
    /// for the page's key: the next, and where this batch stops.
    SavingsSearching { page: u8, next: u32, stop: u32 },
    /// SAVINGS CARD QR: its backup line for a Wallet (one code or version-9
    /// frames) or a KasSigner (version-3 frames); Back goes to `page`.
    SavingsFormat { page: u8 },
    /// Its frames: Auto Cycle or Manual.
    SavingsMode { page: u8 },
    /// The line at `frame` of [`Flow::savings_codes`]; a tap past the last
    /// goes back to `page`.
    SavingsFrames { page: u8, frame: u8 },
    /// Its address as a code; a tap goes back to its first page.
    SavingsAddressQr,
    /// STEGANOGRAPHY: which carrier hides the backup, Descriptor, Picture or
    /// Both, before the photos are listed.
    StegoCarrier,
    /// IMAGE DESCRIPTOR on the keyboard at this page: the caption that is
    /// the password, at most 64 printable characters.
    StegoDescriptor { page: u8 },
    /// The descriptor as typed, to USE or to EDIT.
    StegoPreview,
    /// ADD HINT?: a recovery hint with the seed, or not.
    StegoHintAsk,
    /// RECOVERY HINT: three presets, and Custom.
    StegoHint,
    /// CUSTOM HINT on the keyboard, at this page.
    StegoHintType { page: u8 },
    /// HIDE BACKUP?: the photo, carrier, descriptor and hint.
    StegoConfirm,
    /// The seed and hint being sealed under the descriptor: PBKDF2 in
    /// batches, `done` rounds so far, under ENCRYPTING.
    StegoSealing { done: u32 },
    /// The photo is read: the next tick hides the payload and reads it
    /// back, under EMBEDDING.
    StegoEmbedding,
    /// BACKUP HIDDEN: the photo written; DONE or MORE.
    StegoDone,
    /// Stego Import's IMAGE DESCRIPTOR on the keyboard at this page, typed
    /// into the descriptor itself, up to 128 characters, so a v1.0.7 caption
    /// longer than the 64 a unit now writes still opens. A line read from a
    /// `.TXT` is already in it, to look over.
    StegoKey { page: u8 },
    /// The photo is read: the next tick reads both carriers out of it,
    /// under READING.
    StegoReading,
    /// A carrier's payload being opened under the descriptor: PBKDF2 in
    /// batches, `done` rounds so far, under DECRYPTING; for a v1.0.7
    /// payload, its hint after its seed, under its own salt.
    StegoOpening { done: u32 },
    /// LOAD SEED?: the seed the photo held, where, and whether it held
    /// another backup.
    StegoFound,
    /// RECOVERY HINT: the hint found with the seed, before its passphrase.
    StegoHintShown,
    /// OVERWRITE?: the photo already holds a backup in its metadata, which
    /// Descriptor and Both would replace. Asked like a file's overwrite, then
    /// that backup's own descriptor. A backup in the picture is never asked
    /// about: no unit can find it without its descriptor, which is that
    /// carrier's point.
    StegoOverwrite,
    /// That backup's descriptor on the keyboard at this page, up to 128 as
    /// an import's: the backup is opened under it before being written over.
    StegoOldKey { page: u8 },
}

/// How a seed's backup is checked: three of its words picked, or the copy
/// of its code scanned back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Check {
    Words,
    Code { plain: bool, compact: bool },
}

/// Which list menu.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MenuId {
    Tools,
    /// Under Tools.
    SeedTools,
    /// Under Tools' Import / Export.
    Import,
    /// Under Import.
    ImportSd,
    /// Under Tools' Import / Export.
    Export,
    /// Under Export.
    SeedBackup,
    /// Under Seed Backup.
    QrExport,
    /// Under Export.
    WatchOnly,
    /// Under Export.
    SigningKeys,
    /// Under Tools.
    SignMessage,
    /// Under Tools.
    Multisig,
    /// IMAGE DESCRIPTOR's source, under Steganography's photo list.
    StegoSource,
    /// The unit's own, from [`Config::settings`].
    Settings,
}

/// Export's Seed Backup, where Show Seed Words goes back to.
pub(super) const fn seed_backup() -> State {
    State::Menu {
        menu: MenuId::SeedBackup,
        page: 0,
    }
}

/// The MULTISIG menu, where its screens go back to.
pub(super) const MULTISIG_MENU: State = State::Menu {
    menu: MenuId::Multisig,
    page: 0,
};

/// Seed Tools at the page `tool`'s row is on, where the tools go back to.
pub(super) const fn seed_tools(tool: CountFor) -> State {
    State::Menu {
        menu: MenuId::SeedTools,
        page: match tool {
            CountFor::Words(WordsFor::Import) | CountFor::Dice => 0,
            CountFor::Words(WordsFor::LastWord) | CountFor::Bip85 => 1,
        },
    }
}

/// Sign Message, under Tools.
pub(super) const fn sign_message() -> State {
    State::Menu {
        menu: MenuId::SignMessage,
        page: 0,
    }
}
