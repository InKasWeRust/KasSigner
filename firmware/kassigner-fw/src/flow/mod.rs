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

//! What the device does, from power on to power off: a machine that
//! answers "this happened, what now?".
//!
//! A [`Flow`] holds where it is and what it has collected. The binary's loop
//! owns the camera, decoder, display and touch panel, reports each
//! [`Event`], and draws the [`Screen`] that comes back. No step waits, so
//! every path is tested on the host with fake entropy and hand-built
//! requests.
//!
//! The loop reports where a tap landed and whether a code carried a frame
//! header, and reassembles frames; what a tap, a payload or a bare code
//! means is decided here. A scan ignores bare codes and a seed read ignores
//! payloads, so a SeedQR sheet in view does not cost a scan.
//!
//! # Rules
//!
//! 1. Only [`State::Signing`] signs, through [`Session::decide`]. Only
//!    CONFIRM in [`State::Confirming`] leads there, and CONFIRM SEND? only
//!    follows the last page of [`State::Reviewing`] once every page has
//!    been shown. `Session` enforces this from the pages drawn, which the
//!    flow replays into a session rebuilt from the request.
//! 2. [`State::Halted`] is absorbing. Only a failed start-up check halts,
//!    never the fuses: a blank unit runs, and a provisioned one with a hole
//!    open runs once its red verification screen is tapped through
//!    ([`brand::Check`]).
//! 3. The flow touches no driver. It is handed only the entropy source and
//!    draws from it only to sign or make a seed, randomness a caller must
//!    not be able to replace with a constant. Driver actions, closing the
//!    console included, are asked as a [`Command`], so the policy that a
//!    provisioned unit goes quiet before it can hold a seed is decided and
//!    tested here.
//! 4. A state that holds a secret clears it however it is left: the
//!    collector and the mnemonic wipe on drop, the request and the reply
//!    are wiped when done with, and the seed path's stack is scrubbed once
//!    the seed is in its slot.
//!
//! A [`Screen`] carries no page and no word: the loop reads those through
//! [`Flow::review`], [`Flow::seed`] and [`Flow::shown_word`] while it
//! draws, so the console, which prints every screen, never sees a word.
//! How anything looks is [`crate::ui`]'s.
//!
//! # Taps
//!
//! A tap is a release: [`Event::Tap`] where a finger lifts, after the
//! [`Event::Press`] where it went down, as [`Decision::Confirm`] asks, so a
//! finger that lands wrong can slide away. On the review's pages, CONFIRM
//! SEND? and every dialog, a tap counts only on the target it went down
//! on, and a question held for [`HOLD_US`] starts its hold only on a press
//! on its answer. Keyboards and menus take the key or row a finger lifts
//! on: sliding fixes a near miss, and a row decides nothing.
//!
//! Where a tap lands is found by the function that lays out the screen:
//! [`crate::ui::brand::target`], [`crate::ui::menu::target`],
//! [`crate::ui::review::target`] and the rest.
//!
//! The Scan card opens one camera for everything: a request goes to the
//! review, a SeedQR to a confirmation that stores nothing until Load is
//! tapped, so a SeedQR in view cannot load itself.
//!
//! # The session is rebuilt, not held
//!
//! A [`Session`] borrows the transaction, which borrows the request and two
//! arrays of parsed inputs and outputs, and a struct cannot borrow its own
//! field. So the flow holds the request, a bit per page drawn and the page
//! up, and each step that needs a session parses the request again on its
//! stack and replays the bits. Parsing is deterministic over bytes nobody
//! else can write, so `Session::decide` sees exactly the pages a person saw.

use core::mem::{discriminant, Discriminant};

use crate::kpub::{RAW_LEN as KPUB_RAW_LEN, RAW_MARK as KPUB_RAW_MARK};
use kassigner_crypto::backup::{
    backup_kdf, open_slot, open_slot_with_key, passphrase_guards, seal_slot, seal_slot_with_key,
    sealing_steps, BackupError, BackupKdf, FILE_MAX,
};
use kassigner_crypto::bip39::Mnemonic;
use kassigner_crypto::container::OpenError;
use kassigner_crypto::container::{Argon2Block, Pbkdf2Steps, SealKdf, PBKDF2_ITERATIONS};
use kassigner_crypto::password;
use kassigner_crypto::seed::Words;
use kassigner_crypto::slot::{RawKey, Slot, SlotError, Slots, PASSPHRASE_MAX};
use kassigner_crypto::stego::{self as stego_seal, HINT_MAX};
use kassigner_crypto::wallet::{Wallet, WalletError};
use kassigner_hal::display::Size;
use kassigner_hal::entropy::Entropy;
use kassigner_hal::provisioning::Verdict;
use kassigner_hal::tune::{Knob, MAX_KNOBS};
use kassigner_kaspa::bip32_public::{ChildNumber, ExtendedPublicKey};
use kassigner_kaspa::bip32_public::{Prefix as KeyPrefix, TEXT_MAX as KPUB_MAX};
use kassigner_kaspa::derivation::Path;
use kassigner_kaspa::pskb::signature::{Derivation, PartialSig};
use kassigner_kaspa::pskb::transaction as pskb_tx;
use kassigner_kaspa::pskb::{self, Splice};
use kassigner_kaspa::script::kcc3_script_hash;
use kassigner_kaspa::script::recognize::{address_payload, classify, ScriptClass};
use kassigner_kaspa::tx::{
    NonStandardError, Outpoint, ScriptPublicKey, TransactionInput, TransactionOutput, TxRuleError,
    UtxoEntry,
};
use kassigner_protocol::bundle;
use kassigner_protocol::card::savings::{Savings, PROGRAM_LEN};
use kassigner_protocol::check;
use kassigner_protocol::container::ContainerError;
use kassigner_protocol::container::{NONCE_SIZE, SALT_SIZE};
use kassigner_protocol::frame::{self, Format};
use kassigner_protocol::group::Group;
use kassigner_protocol::kspt::{self, InputSignature, Kspt, KsptError, SIGNATURE_LEN};
use kassigner_protocol::profile::{Capacity, Profile};
use kassigner_protocol::stego::picture::{Tables, Window};
use kassigner_protocol::stego::StegoError;
use kassigner_protocol::stego::{self as stego_wire, Carrier};

use crate::branches::Branches;
use crate::card::{self, Job, Outcome, Request};
use crate::keyring::{self, Keyring};
use crate::limits;
use crate::reply;
use crate::review::Page;
use crate::seed::{self, Collector, Source};
use crate::session::{self, Decision, Session, Stage};
use crate::sizes::Sizes;
use crate::text::{Field, Hidden, Typed};
use crate::ui::chrome::Nav;
use crate::ui::menu::Setting;
use crate::ui::refusal;
use crate::ui::review::{self as review_screen, Change, Counted, Shown, Totals};
use crate::ui::scale::Scale;
use crate::ui::seeds::{Kind, Seed};
use crate::ui::{
    address as address_screen, backup, bip85 as bip85_screen, brand, camera, camtune, dialog,
    dice as dice_screen, keyboard, keypad, kpub as kpub_screen, menu, multisig as multisig_screen,
    sd_card, seedqr, seeds as seed_rows, settings, stego as stego_screen, words as word_screens,
};
use crate::wipe;
use crate::words::{lookup, PREFIX_MAX};
use kassigner_crypto::bip32::{ExtendedPrivateKey, PrivatePrefix, PRIVATE_KEY_SIZE, XPRV_TEXT_MAX};
use kassigner_crypto::bip39::{self, index_to_word};
use kassigner_crypto::bip85;
use kassigner_kaspa::address::{self as kaspa_address, Prefix, Version, MAX_ADDRESS_LEN};
use zeroize::Zeroize;

// What the flow takes and answers, public here.
mod command;
mod event;
mod refusals;
mod screen;
mod state;
mod typing;

pub use command::{Command, Output};
pub use event::Event;
pub use refusals::{CardLock, Halt, Refusal, Unshown};
pub use screen::{Screen, RESTORE_MAX};
pub use state::{Check, MenuId, State};
pub use typing::{CountFor, Typing, WordsFor, INDEX_DIGITS, NAME_MAX, RAW_KEY_HEX};

use event::tapped;
use refusals::{planned, unchanged};
use state::{seed_backup, seed_tools, sign_message, MULTISIG_MENU};

// The machine's parts, each an `impl` block of `Flow`; what one calls in
// another is `pub(super)`.
mod addresses;
mod backup_check;
mod card_jobs;
mod drawing;
mod exports;
mod groups;
mod holding;
mod home;
mod levels;
mod messages;
mod replying;
mod reviewing;
mod savings;
mod scanning;
mod sd_files;
mod sealing;
mod seed_tools;
mod signing_keys;
mod slots;
mod stego;
mod word_entry;

use backup_check::WordChecks;
pub use backup_check::{CHECKED_US, CHECK_ROUNDS};
use holding::Hold;
use reviewing::{build, build_pskb};
use savings::HeldCard;

/// Which account's kpub Watch-Only shows: the single-signature one, `44'`,
/// or the multisig cosigner's, `45'`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KpubKey {
    Single,
    Cosigner,
}

/// What a card's file list holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Listing {
    /// `.KAS` backups, opened into a slot.
    Backups,
    /// `.TXT` kpub files, to be shown; a password is asked either way, left
    /// empty for a plain file.
    Kpubs,
    /// `.TXT` files, read whole to be signed as messages.
    Messages,
    /// `.K45` cosigner kpubs, taken as the group's next key. Only those: a
    /// watch-only kpub would make a group no one can spend from.
    Cosigners,
    /// `.TXT` multisig descriptors, plain or sealed, offered to replace the
    /// group held.
    Groups,
    /// `MSnnnn.TXT` group addresses, plain or sealed, shown as the file
    /// holds them.
    Addresses,
    /// `.JPG` and `.JPE` photos that fit the photo buffer, for
    /// steganography. SELECT PHOTO has no delete: a photo is the user's, not
    /// a backup.
    Photos,
    /// `.TXT` files whose first line is an image descriptor, for
    /// Steganography's Load .TXT from SD: plain, no password, as v1.0.7 read
    /// them.
    Captions,
    /// `CVnnnn.TXT` covenant card backup lines, plain or sealed, read whole
    /// into the request's buffer for SAVINGS CARD. Both Covenant Restore
    /// rows list them.
    Cards,
    /// `.KSP` requests as SIGNED TX's Save to SD writes them, plain or sealed
    /// under the KSPT purpose, read whole into the request's buffer and
    /// reviewed as a scanned one: how a card carries a transaction between a
    /// group's signers.
    Transactions,
}

/// v1.0.7's comment line over a descriptor in its file, before its M-of-N.
const DESCRIPTOR_COMMENT: &str = "# KasSigner multisig, 45' coordinated, ";
/// The comment line at its longest: `5-of-5` and the line break after it.
const DESCRIPTOR_HEAD_MAX: usize = DESCRIPTOR_COMMENT.len() + "5-of-5".len() + 1;
/// The longest descriptor file: the comment line and the descriptor of the
/// most keys a group holds.
const DESCRIPTOR_FILE_MAX: usize =
    DESCRIPTOR_HEAD_MAX + kassigner_protocol::descriptor::max_len(limits::MAX_MULTISIG_KEYS);

/// The largest descriptor file Import from SD reads: two card blocks, room
/// for the longest the unit writes, sealed, and line ends a computer adds.
const GROUP_FILE_MAX: usize = 1024;
const _: () = assert!(
    kassigner_protocol::container::file_size(DESCRIPTOR_FILE_MAX) <= GROUP_FILE_MAX,
    "the longest descriptor file, sealed, is read"
);

/// Seed Tools' KCC-3 Address row, beside Address.
const KCC3_ROW: usize = 4;

/// Import from SD's Transaction row.
const TRANSACTIONS_ROW: usize = 1;
/// Import from SD's Multisig Address row.
const ADDRESSES_ROW: usize = 3;
/// Import from SD's Multisig Descriptor row.
const GROUPS_ROW: usize = 4;
/// Import's Covenant Restore row.
const COVENANT_ROW: usize = 3;
/// Import from SD's Covenant Restore row.
const SD_COVENANT_ROW: usize = 5;
/// What the file name, the password and the write are saving.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Saving {
    /// The seed in use, sealed: `SDnnnn.KAS`.
    Backup,
    /// A kpub, plain or sealed: `KPnnnn.TXT`, or the cosigner's `KMnnnn.K45`
    /// with fingerprint and path in front, sealed under its own purpose: a
    /// kpub's bytes cannot tell the two apart, so the file says.
    Kpub(KpubKey),
    /// A signed message, [`crate::message`]'s record: `SGnnnn.TXT`.
    Signature,
    /// The reply as shown, KSPT or PSKB, plain or sealed: `TXnnnn.KSP`.
    Reply,
    /// An address, plain or sealed: `ADnnnn.TXT`.
    Address,
    /// A group's address, plain or sealed: `MSnnnn.TXT`.
    GroupAddress,
    /// The held group's descriptor under v1.0.7's comment line, plain or
    /// sealed: `MDnnnn.TXT`. Written from the request's buffer, as it may
    /// not fit the flow's own file.
    Descriptor,
    /// A photo with the seed hidden in it, written over itself from the
    /// photo output buffer.
    Stego,
    /// A covenant card's backup line, plain or sealed: `CVnnnn.TXT`.
    /// Written from the request's buffer: sealed, it may not fit the flow's
    /// own file.
    Card,
}

impl Saving {
    /// The name's two letters and extension, to find the next free number.
    const fn pattern(self) -> ([u8; 2], [u8; 3]) {
        match self {
            Saving::Backup => (*b"SD", card::BACKUP_EXT),
            Saving::Kpub(KpubKey::Single) => (*b"KP", *b"TXT"),
            Saving::Kpub(KpubKey::Cosigner) => (*b"KM", card::COSIGNER_EXT),
            Saving::Signature => (*b"SG", *b"TXT"),
            Saving::Reply => (*b"TX", *b"KSP"),
            Saving::Address => (*b"AD", *b"TXT"),
            Saving::GroupAddress => (*b"MS", *b"TXT"),
            Saving::Descriptor => (*b"MD", *b"TXT"),
            Saving::Card => (*b"CV", *b"TXT"),
            // A photo keeps its own name; no number is ever asked for one.
            Saving::Stego => (*b"ST", *b"JPG"),
        }
    }
}

/// Bytes a frame carries for another unit (a signed message's, Plain Text
/// QR's, a reply's), so that with its header it fills a version-3 code, the
/// largest one unit reads off another's screen: 48 of 53. Frame 0 carries
/// 45, giving three to the payload's digest.
const UNIT_FRAME_BYTES: usize = 48;
const _: () = assert!(matches!(
    kassigner_qr::capacity::byte_capacity(3),
    Some(n) if n == UNIT_FRAME_BYTES + kassigner_protocol::frame::HEADER_LEN
));
/// Bytes a frame carries for a wallet: a version-9 code with the header,
/// the largest the encoder makes; anything longer goes in frames.
const MESSAGE_WALLET_BYTES: usize = limits::FRAME_PAYLOAD;

/// Modules a side of a SeedQR for `words` words at error correction L
/// (standard: version 2 or 3; compact: 1 or 2), so the grid view knows its
/// edge without encoding the seed.
pub const fn seedqr_size(compact: bool, words: usize) -> u8 {
    match (compact, words) {
        (false, 24) => 29,
        (false, _) | (true, 24) => 25,
        (true, _) => 21,
    }
}

/// The last index the Address tool goes to: five digits' worth.
const INDEX_MAX: u32 = 99_999;

/// Rolls Dice Seed asks for: 99 for 12 words and 198 for 24, both past the
/// seed crate's least (50 and 99).
pub const DICE_ROLLS_12: usize = 99;
pub const DICE_ROLLS_24: usize = 198;
/// A face seen under this percentage of the rolls is warned of: fair dice
/// do that about once in 40 seeds of 99 rolls, once in 1,200 of 198. The
/// seed crate refuses only what was plainly never rolled.
pub const DICE_UNEVEN_PERCENT: usize = 8;
const DICE_MAX: usize = DICE_ROLLS_24;

/// Where a new seed goes once its words have been shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AfterWords {
    /// A dice seed: its passphrase, then stored, as a scanned one.
    Passphrase,
    /// A BIP85 child: stored with no passphrase.
    Store,
    /// New Seed's: stored with no passphrase.
    NewSeed,
    /// Show Seed Words: the seed in use's words, read from its slot, then
    /// back to Seed Backup.
    SeedBackup,
}

/// How long the dice refusal is shown.
const SAID_US: u64 = ERROR_US;

/// The flow's own file, in internal RAM: the larger of the largest backup
/// and a sealed cosigner's kpub file. Every file a key is opened from fits.
const FLOW_FILE: usize = {
    let cosigner = kassigner_protocol::container::file_size(crate::kpub::COSIGNER_MAX);
    if cosigner > FILE_MAX {
        cosigner
    } else {
        FILE_MAX
    }
};

/// The multisig group a unit holds: one at a time, the last made. Never in a
/// seed slot, and wiped with everything a seed left.
pub type HeldGroup = Group<{ limits::MAX_MULTISIG_KEYS }>;

/// Where an address is: chain, index, and for a group's, the cosigner
/// whose branch it is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AddressAt {
    change: bool,
    index: u32,
    cosigner: u8,
}

/// Slow work a tap asked for (a key derived, a signature checked, a request
/// read again): the tap answers [`Command::Deferred`] and clicks at once,
/// and the work is done on the next tick ([`Flow::settle`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Work {
    /// The Address screen at another chain, index or group cosigner.
    Address(AddressAt),
    /// Multisig Address opening: the seed in use's place in the group, then
    /// its branch's address, or DERIVING the first time.
    GroupAddress,
    /// Multisig Descriptor opening: the seed in use's place in the group.
    Descriptor,
    /// Watch-Only's row `row`: its kpub from the seed in use.
    Kpub { row: usize },
    /// SELECT SEED on the seed in use: its own cosigner key.
    OwnCosigner,
    /// Import Raw Key's OK: the typed key's address.
    RawKey,
    /// SIGNED MESSAGE's CHECK: the signature verified.
    CheckMessage,
    /// A review arrow: the request read again for its pages.
    Review(review_screen::Target),
}

/// A group being made: CREATE MULTISIG's M of N and the public keys added
/// so far, in order of arrival; [`HeldGroup`] orders them once all are in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Forming {
    required: u8,
    total: u8,
    added: u8,
    /// The first `added`; the rest never read.
    keys: [ExtendedPublicKey; limits::MAX_MULTISIG_KEYS],
    /// Beside each key, the fingerprint of its seed if the unit holds it.
    from: [Option<[u8; 4]>; limits::MAX_MULTISIG_KEYS],
}

impl Forming {
    const fn new(required: u8, total: u8) -> Self {
        const NONE: ExtendedPublicKey = ExtendedPublicKey {
            public_key: [0; 33],
            chain_code: [0; 32],
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: ChildNumber(0),
        };
        Self {
            required,
            total,
            added: 0,
            keys: [NONE; limits::MAX_MULTISIG_KEYS],
            from: [None; limits::MAX_MULTISIG_KEYS],
        }
    }

    /// Signatures the group will need.
    pub const fn required(&self) -> usize {
        self.required as usize
    }

    /// Keys it will have.
    pub const fn total(&self) -> usize {
        self.total as usize
    }

    /// The keys added, in order.
    pub fn keys(&self) -> &[ExtendedPublicKey] {
        &self.keys[..usize::from(self.added)]
    }

    /// Whether every key is in.
    pub const fn complete(&self) -> bool {
        self.added >= self.total
    }

    /// Whether `key`'s public key was added.
    fn holds(&self, key: &ExtendedPublicKey) -> bool {
        self.keys().iter().any(|k| k.public_key == key.public_key)
    }

    /// Add `key`, from the seed `from` names if any; ignored once full.
    fn add(&mut self, key: ExtendedPublicKey, from: Option<[u8; 4]>) {
        if self.complete() {
            return;
        }
        let at = usize::from(self.added);
        if let (Some(slot), Some(seed)) = (self.keys.get_mut(at), self.from.get_mut(at)) {
            *slot = key;
            *seed = from;
            self.added += 1;
        }
    }

    /// The seed `key` came from, if one the unit holds.
    fn seed_of(&self, key: &ExtendedPublicKey) -> Option<[u8; 4]> {
        let i = self
            .keys()
            .iter()
            .position(|k| k.public_key == key.public_key)?;
        self.from.get(i).copied().flatten()
    }

    /// Remove the last key added.
    fn drop_last(&mut self) {
        self.added = self.added.saturating_sub(1);
    }
}

// ── Buffers ─────────────────────────────────────────────────────────────────

/// The memory a flow works in. This crate allocates nothing, so the loop
/// sizes these from [`Sizes`] and lends them for the flow's lifetime.
pub struct Buffers<'b> {
    /// The request under review, [`Sizes::payload`] bytes.
    pub request: &'b mut [u8],
    /// The reply, [`Sizes::reply`] bytes.
    pub reply: &'b mut [u8],
    /// One per input, [`Sizes::inputs`].
    pub signatures: &'b mut [InputSignature],
    /// A bundle request's document decoded from its envelope, or a bundle
    /// reply decoded to be read back, [`Sizes::pskb_document`] bytes.
    pub document: &'b mut [u8],
    /// The scripts decoded out of a bundle's document, [`Sizes::pskb_bytes`].
    pub scripts: &'b mut [u8],
    /// A redeem script, [`Sizes::redeem`].
    pub redeem: &'b mut [u8],
    /// A bundle reply's generated members, [`Sizes::edited_document`].
    pub text: &'b mut [u8],
    /// A bundle reply's edited document, [`Sizes::edited_document`].
    pub edited: &'b mut [u8],
    /// The pump's [`keyring::SWEEP`] keys: the seed's public keys past its
    /// first addresses, in the sweep's order. Public: PSRAM will do.
    pub pump: &'b mut [[u8; 32]],
    /// Argon2id's working memory on a board with room, the P4. `None` seals
    /// under PBKDF2, which every board opens.
    pub kdf: Option<&'b mut [Argon2Block]>,
    /// A photo read from the card, [`limits::PHOTO_MAX`] bytes, and the
    /// photo with the backup in it, [`limits::PHOTO_OUT`]. PSRAM will do.
    pub photo: &'b mut [u8],
    pub photo_out: &'b mut [u8],
    /// The Picture carrier's window, [`limits::WINDOW_RANKS`] coefficients,
    /// and its two bitmaps, [`limits::WINDOW_BITS`] bytes in all.
    pub window: &'b mut [i16],
    pub window_bits: &'b mut [u8],
    /// Scratch for the photo's EXIF block with the backup in it,
    /// [`limits::APP1_SCRATCH`].
    pub app1: &'b mut [u8],
    /// The photo's Huffman tables while the Picture carrier walks it: about
    /// 9.6 KB, which on the stack made the stego export the M5's deepest
    /// path. Public: PSRAM will do.
    pub jpeg: &'b mut Tables,
}

// ── The machine ─────────────────────────────────────────────────────────────

/// How long the verification screen stays when nothing on it is red.
pub const VERIFIED_US: u64 = 3_000_000;

/// How long a finger holds Home's logo, nothing shown, for the duress wipe
/// of everything a seed left: six seconds, as long as a board's reset
/// button is held.
pub const WIPE_HOLD_US: u64 = 6_000_000;

/// How long the unit sits untouched, holding a seed, before everything a
/// seed left is wiped.
pub const IDLE_WIPE_US: u64 = 240_000_000;

/// How long SIGN MESSAGE? and IMPORT KEY? are up before a touch counts.
/// Each opens from a button over its answer (the message's SIGN, the hex
/// keyboard's OK), so a double tap's second touch would answer it; half a
/// second is enough to read the question.
pub const SETTLE_US: u64 = 500_000;

/// How long WIPED is said.
pub const WIPED_US: u64 = 1_500_000;

/// The least an error stays up, so it can be read: every refusal, the
/// dice's, and a failed card job.
pub const ERROR_US: u64 = 5_000_000;

/// How long a refusal stays.
pub const REFUSED_US: u64 = ERROR_US;

/// How long the scan reads only a code that could be a v1.0.7 last frame
/// before saying it may be a compact SeedQR: longer than the two seconds a
/// v1.0.7 unit shows each frame, so its frame zero would have come round.
pub const SEED_HINT_US: u64 = 5_000_000;

/// The longest gap between two reads of that code still counted as the
/// camera staying on it; past it, [`SEED_HINT_US`] starts again.
pub const SEED_GAP_US: u64 = 2_000_000;

/// PBKDF2 rounds a tick while a backup is sealed: twenty steps of the bar.
pub const SEAL_ROUNDS: u32 = kassigner_crypto::container::PBKDF2_ITERATIONS / 20;

/// Where the encrypting and decrypting bars stand during Argon2id, one
/// call with nothing drawn: half. PBKDF2 fills the bar in [`SEAL_ROUNDS`]
/// steps from 1 and never stops on this value.
pub const ARGON2_HELD: u32 = kassigner_crypto::container::PBKDF2_ITERATIONS / 2;

/// How long Delete, or Format, must be held.
pub const HOLD_US: u64 = 4_000_000;

/// How long a card job's outcome stays; a failed job's at least
/// [`ERROR_US`].
pub const fn card_done_us(job: Job, outcome: Outcome) -> u64 {
    let shown = match job {
        Job::Format | Job::Write => 3_000_000,
        _ => 5_000_000,
    };
    if !outcome.ok() && shown < ERROR_US {
        ERROR_US
    } else {
        shown
    }
}

/// The steps of opening a wallet: the seed, then each key of the bank,
/// with the KCC-3 bank's key of the same number.
pub const OPEN_STEPS: usize = keyring::BANK + 1;

/// Addresses a search batch derives before asking to go on.
pub const BATCH: usize = 200;

/// Keys a search derives a tick where none are at hand: about a tenth of a
/// second on an S3, so taps are answered between ticks.
const SEARCH_PER_TICK: usize = 2;

/// The lowest backlight Display sets, so the screen that raises it stays
/// visible: on the Waveshare a level of zero is a duty of zero, dark.
pub const BACKLIGHT_FLOOR: u8 = 10;

/// The seen mask is a `u32`, one bit per page.
const _: () = assert!(limits::MAX_PAGES <= 32);

const BLANK_IN: TransactionInput<'static> = TransactionInput {
    previous_outpoint: Outpoint {
        transaction_id: [0; 32],
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
};

const BLANK_OUT: TransactionOutput<'static> = TransactionOutput {
    value: 0,
    script_public_key: ScriptPublicKey {
        version: 0,
        script: &[],
    },
    covenant: None,
};

/// Why storing a seed failed. The screen says [`Refusal::NoWallet`]; the
/// detail is for a test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreError {
    Slot(SlotError),
    Wallet(WalletError),
    Keyring(keyring::Error),
}

/// The unit a flow is built for, as the binary states it.
#[derive(Clone, Copy, Debug)]
pub struct Config<'c> {
    /// The envelope the unit accepts.
    pub profile: Profile,
    /// What the unit can carry and show.
    pub capacity: Capacity,
    /// The display, for the tap zones.
    pub size: Size,
    /// The main stack, for the seed path's scrub.
    pub stack: wipe::Stack,
    /// The entropy sources this unit has. At most four are kept.
    pub sources: &'c [Source],
    /// The unit's settings menu.
    pub settings: &'static menu::Menu,
    /// The backlight's level as the board brought it up, 0 to 255.
    pub backlight: u8,
    /// The volume as the board brought it up, 0 to 255.
    pub volume: u8,
    /// The camera settings the tuning screen moves: at most [`MAX_KNOBS`],
    /// one fewer with the switch, the rest left off. With none, Settings'
    /// Camera leads nowhere.
    pub knobs: &'static [Knob],
    /// Whether the unit has a switch for the exposure loop.
    pub tune_auto: bool,
}

/// The device, between events. `N` is how many seed slots it holds.
pub struct Flow<'b, const N: usize> {
    state: State,
    buffers: Buffers<'b>,
    profile: Profile,
    capacity: Capacity,
    scale: Scale,
    settings: &'static menu::Menu,
    stack: wipe::Stack,
    /// The word count of the seed New Seed is making, chosen on its count
    /// screen.
    words: Words,
    /// What boot found, for the verification screen and About.
    check: brand::Check,
    sources: [Option<Source>; 4],
    slots: Slots<N>,
    keys: Option<Keyring>,
    /// The request's length in `buffers.request`, while one is held.
    request_len: usize,
    /// A bundle's document length in `buffers.document`, decoded on arrival.
    document_len: Option<usize>,
    /// The SHA-256 of the bytes the review is built from, taken as it starts
    /// and kept in the flow's own memory. The bytes sit in the lent buffers
    /// (PSRAM on a board) and are parsed again for every page, so CONFIRM
    /// SEND? and the signing go on only while they still hash to it
    /// ([`Flow::unchanged`]). `None` while no review is held.
    request_digest: Option<[u8; frame::SHA256_LEN]>,
    /// The reply's length in `buffers.reply`, while one is shown.
    reply_len: usize,
    /// Its signature count, if it has one.
    reply_signers: Option<reply::Signers>,
    /// The same reply in v1.0.7's form, its length in `buffers.edited`,
    /// which a KSPT leaves free: what SIGNED TX QR's Wallet shows for a
    /// single-key `0x01` request, sent by a wallet built on that release.
    /// Zero for every other request.
    reply_v107: usize,
    /// SIGNED TX QR's choice: version-9 frames for a wallet, or version-3
    /// for another unit.
    reply_wallet: bool,
    /// One bit per page drawn, and the page on the screen.
    seen: u32,
    page: usize,
    /// Frames received, for the scanning screen: how many of how many, and
    /// which, bit `i` for frame `i`.
    progress: (usize, usize),
    received: u64,
    /// When a code that could be a v1.0.7 last frame or a compact SeedQR was
    /// first and last read, with no frame between.
    seed_or_frame: Option<(u64, u64)>,
    /// Whether the scanning screen says how else to load a seed.
    seed_hint: bool,
    /// When a timed screen was entered, and the last clock reported.
    since_us: u64,
    now_us: u64,
    collector: Option<Collector>,
    /// A SeedQR read and not yet loaded.
    pending: Option<Mnemonic>,
    /// What the keyboard has typed: wiped when it is used or abandoned.
    typed: Typed<PASSPHRASE_MAX>,
    /// A backup's password the first time, while it is typed again.
    first: Typed<PASSPHRASE_MAX>,
    /// The second password did not match the first.
    mismatch: bool,
    /// The backup's 8.3 name.
    backup_name: [u8; 11],
    /// The sealed backup until written, or the file read until opened, and
    /// its length. A read is sliced at its length capped to this buffer, so
    /// no slice relies on [`crate::card::read`] refusing a longer file.
    file: [u8; FLOW_FILE],
    file_len: usize,
    /// The chosen backup is to be deleted once its password opens it, not
    /// restored.
    deleting: bool,
    /// The card is reading the file a save would overwrite, to open it under
    /// its own password first: set as the read is asked, taken as it answers.
    replacing: bool,
    /// The words typed so far, by place: a seed, wiped when the tool is left
    /// or done.
    phrase: [u16; 24],
    /// The phrase's length, the place being typed, and how many are filled.
    word_count: usize,
    word_pos: usize,
    word_filled: usize,
    /// The phrase failed its checksum: said until a key is pressed.
    word_invalid: bool,
    /// The Address tool: the chain, the index, where Back goes, the address
    /// as text, and the keypad's digits.
    addr_change: bool,
    addr_index: u32,
    addr_from: State,
    addr_text: [u8; MAX_ADDRESS_LEN],
    addr_len: usize,
    pad: [u8; INDEX_DIGITS],
    pad_len: usize,
    /// The Address tool shows the address's private key (Signing Keys'
    /// Private Key), not the address.
    addr_key: bool,
    /// Signing Keys' key as text, a kprv or a private key in hex: held only
    /// while one of its screens is up, wiped as the last is left
    /// (`Flow::keep_key`).
    key_text: [u8; XPRV_TEXT_MAX],
    key_len: usize,
    /// Import Raw Key's key, between OK and the answer to its address.
    raw_key: Option<RawKey>,
    /// The Address screen chooses the address that signs a message.
    addr_sign: bool,
    /// The Address screen shows the held group's address on cosigner
    /// `addr_cosigner`'s branch, not the seed's.
    addr_group: bool,
    addr_cosigner: u8,
    /// The Address screen shows the seed's KCC-3 addresses, not its
    /// single-signature ones.
    addr_kcc3: bool,
    /// Sign Message's text, in [`Buffers::request`], and its signature as
    /// hex, in [`Buffers::reply`].
    msg_len: usize,
    sig_len: usize,
    /// Bytes of [`Buffers::request`] the message came in, a signed record's
    /// whole, wiped with it.
    msg_held: usize,
    /// The message was read back with its signature: checked, not signed.
    msg_signed: bool,
    /// The furthest page of the message shown. SIGN does nothing until it is
    /// the last; pages turn one at a time, so all were shown.
    msg_read: usize,
    /// The length of a signed message's file, as written.
    record_len: usize,
    /// Where the message's screens go back to: Sign Message, or home for a
    /// signed message scanned.
    msg_from: State,
    /// The signed message's code: the record in [`Buffers::document`], and
    /// the frames it is shown in.
    shown_len: usize,
    msg_frames: u8,
    /// Dice Seed's rolls, '1' to '6', and how many: a seed, wiped once it is
    /// made or the tool left.
    rolls: [u8; DICE_MAX],
    rolled: usize,
    /// BIP85 Child's index.
    bip85_index: u32,
    /// Set by CREATE MULTISIG's NEXT.
    forming: Option<Forming>,
    group: Option<HeldGroup>,
    /// Its keys at every branch and chain, for Multisig Address: derived as
    /// that first opens, cleared whenever the group changes.
    branches: Branches,
    /// The seed in use's place in the group, found as DESCRIPTOR opened, for
    /// coming back from its codes.
    desc_own: Option<u8>,
    /// The codes the descriptor is shown in: one, or frames.
    desc_frames: u8,
    /// A group read from a descriptor file, waiting on LOAD MULTISIG?.
    loading: Option<HeldGroup>,
    /// The seed in use's place among its keys, found as it was read.
    load_seed: multisig_screen::SeedIn,
    /// Where LOAD MULTISIG?'s CANCEL goes: the card's list, or home for a
    /// descriptor scanned.
    load_from: State,
    /// An address read from a file, for MULTISIG ADDRESS: its text.
    file_addr: [u8; MAX_ADDRESS_LEN],
    file_addr_len: usize,
    /// The covenant card SAVINGS CARD shows.
    savings: Option<HeldCard>,
    /// The codes its backup line is shown in: one, or frames.
    card_frames: u8,
    /// Where Covenant Restore's list goes back to: Import or Import from SD.
    cards_from: State,
    /// For TX REVIEW, the M of N of the multisig every signed input is in;
    /// `None` for any other request.
    review_group: Option<(u8, u8)>,
    /// The inputs signed at their script's second key, a bit each
    /// ([`reply::Plan::second`]): a Time-Locked Savings card's page says
    /// recover, not claim, for one.
    review_second: u32,
    /// Inputs the last plan signs, and inputs the request has: the review
    /// starts only when they are equal ([`Flow::review_or_refuse`]).
    review_signs: (usize, usize),
    /// How the request's inputs stand against the group held, once read
    /// ([`Flow::inputs_held`]).
    review_inputs: Option<reviewing::Inputs>,
    /// The request is a transaction this seed already signed, reopened from
    /// the card, with its signers: its review ends in SIGNED TX QR, not
    /// CONFIRM SEND?, and nothing is signed. `None` for a request to sign.
    reopened: Option<Option<reply::Signers>>,
    /// By output, where it pays the seed's own address at a place the
    /// request named and the unit checked: change (the seed's or the held
    /// group's) at that index on the change chain, or one of the seed's
    /// receive addresses.
    hinted: [Option<Change>; limits::MAX_OUTPUTS],
    deferred: Option<Work>,
    /// The screen the last step answered, given again by a tap whose work
    /// waits.
    last_screen: Screen,
    /// Beside each of the held group's keys, its seed's fingerprint if the
    /// unit holds it.
    group_from: [Option<[u8; 4]>; limits::MAX_MULTISIG_KEYS],
    /// A seed is being opened for SELECT SEED, its cosigner key to be the
    /// group's next.
    open_for_group: bool,
    after_words: AfterWords,
    /// UNEVEN ROLLS': the face seen least, 1 to 6, and how many times.
    uneven: (u8, usize),
    /// By slot, a seed made on this unit whose backup is not checked: until
    /// it is, it can only be shown and backed up. A seed loaded from outside
    /// came from a backup.
    unbacked: [bool; N],
    /// The seed in [`Flow::pending`] was made here and its check put off
    /// (LATER).
    made_later: bool,
    /// The word check under way: its places and the words offered.
    checks: WordChecks,
    saving: Saving,
    listing: Listing,
    /// Steganography's carrier, chosen or where an import found the backup,
    /// and descriptor, the caption that is the password, wiped when the
    /// screens are left. Stego Import types into the descriptor itself, past
    /// the keyboard's 64.
    carrier: Carrier,
    desc: Typed<{ stego_wire::DESCRIPTOR_READ_MAX }>,
    /// Stego Import, not Steganography, for where the photo list, the
    /// descriptor's source and a refusal go back to.
    stego_import: bool,
    unhide: Unhide,
    /// The photo's 8.3 name, kept apart from the card's other names since a
    /// caption file may be listed and read after it.
    photo_name: [u8; 11],
    /// Its long name as listed, for the dialogs after the list.
    photo_shown: [u8; kassigner_fat32::fat32::MAX_LONG_NAME],
    photo_shown_len: usize,
    /// Bytes of [`Buffers::photo`] the photo holds, until the embedding or
    /// until its carriers are read. Apart from `file_len`, which a caption
    /// file read in between sets.
    photo_len: usize,
    /// Where a refusal goes back to while [`Flow::stego_live`] holds: the
    /// carriers, the import's keyboard, or the photo list.
    stego_rest: State,
    /// The recovery hint, a preset or typed, or none; wiped with the
    /// descriptor.
    hint: [u8; HINT_MAX],
    hint_len: usize,
    /// The sealed seed and hint, stripped for the photo, held from sealing
    /// to the write and wiped after.
    payload: [u8; stego_wire::PAYLOAD_MAX],
    payload_len: usize,
    /// A stego export (from CONFIRM to its result), or an import or
    /// overwrite check (from OK), is under way: a refusal goes back to
    /// [`Flow::stego_rest`], not home.
    stego_live: bool,
    /// Watch-Only's kpub: which, as text, in v1.0.7's raw form, and in one
    /// code or two frames.
    kpub_key: KpubKey,
    kpub: [u8; KPUB_MAX],
    kpub_len: usize,
    kpub_raw: [u8; KPUB_RAW_LEN],
    kpub_frames: u8,
    /// QR DISPLAY MODE's answer for every code in frames: Manual, a tap
    /// each, or Auto Cycle.
    manual: bool,
    /// The codes Plain Text QR's KasSigner frames take.
    plain_frames: u8,
    /// When the cycling code's frame came up.
    frame_since: u64,
    /// How long each frame stays in Auto Cycle, by reader:
    /// [`limits::WALLET_FRAME_US`] or [`limits::KASSIGNER_FRAME_US`].
    frame_us: u64,
    /// Wallet was chosen for the descriptor's, signed message's or card's
    /// frames, all drawn at version 9 ([`frame_code`]). The reply keeps its
    /// own.
    wallet_frames: bool,
    /// Where the kpub's screens go back to: Watch-Only, or Home for one
    /// scanned.
    kpub_exit: State,
    /// Where a save's keyboards' Back and its result go: the screen that
    /// asked for it.
    save_back: State,
    /// Where the backup's warning and its save go back to: Seed Backup, or
    /// SEED EXPORTED.
    backup_back: State,
    /// The backups on the card, and how many more files it had.
    backups: [[u8; 11]; RESTORE_MAX],
    listed: usize,
    extra: u16,
    /// PBKDF2 part-way between ticks, and the salt and nonce it seals under.
    steps: Option<Pbkdf2Steps>,
    salt: [u8; SALT_SIZE],
    nonce: [u8; NONCE_SIZE],
    /// Where a card job's result goes after it has been shown.
    card_exit: State,
    /// Where Export was opened from, for its Back.
    export_from: State,
    opening: Option<Opening>,
    /// The screen the finger now down went down on.
    pressed_in: Option<Discriminant<State>>,
    /// Where it went down, for the screens whose taps count only on the
    /// target pressed.
    pressed_at: Option<(u16, u16)>,
    /// When it went down, for the questions that wait [`SETTLE_US`].
    pressed_us: u64,
    /// When the screen now up went up: the state's last change of kind.
    shown_us: u64,
    /// When a finger last went down, moved or lifted, for the idle wipe.
    touched_us: u64,
    /// When a finger went down on Home's logo and stayed, for the wipe.
    logo_since: Option<u64>,
    /// How many of the pump's keys are derived, for the seed in use.
    pumped: usize,
    /// The backlight's level and the volume, as last set.
    backlight: u8,
    volume: u8,
    /// The camera's settings, as last read or set, and the exposure loop's
    /// switch.
    knobs: &'static [Knob],
    tune: [u8; MAX_KNOBS],
    has_auto: bool,
    auto: bool,
    /// What the SD Card screen last found in the slot.
    card: card::Status,
}

/// A wallet part-way open, held in [`Flow`] between ticks and moved whole
/// into the keyring once its bank is full. A move copies and leaves the
/// source bytes, so the holder is then cleared, every byte of the `Option`,
/// leaving the keyring's the only copy of the wallet.
struct Opening {
    wallet: Wallet,
    chains: Option<[ExtendedPublicKey; 2]>,
    bank: [(Path, [u8; 32]); keyring::BANK],
    /// The KCC-3 chains' public keys, `None` without a `22'` tree, and their
    /// bank, filled in step with the first.
    kcc3_chains: Option<[ExtendedPublicKey; 2]>,
    kcc3: [[u8; 32]; keyring::KCC3_BANK],
    done: usize,
}

/// For `Option::zeroize`: the banks' keys cleared. The wallet clears itself
/// as the holder drops it, and every byte the holder had is cleared after.
impl Zeroize for Opening {
    fn zeroize(&mut self) {
        for (_, key) in self.bank.iter_mut() {
            key.zeroize();
        }
        self.kcc3.zeroize();
        self.done = 0;
    }
}

/// Stego Import part-way: the payloads the photo gave up, in
/// [`Buffers::photo_out`] (the picture's at its start, the metadata's at
/// [`stego_wire::PAYLOAD_MAX`]), which is being opened, and how the ones
/// tried went.
///
/// The picture's is tried first: its walk is keyed by the descriptor, so a
/// payload there already says the descriptor is right, where the
/// metadata's is there for anyone. The other is tried only if the first
/// does not open.
#[derive(Clone, Copy, Debug)]
struct Unhide {
    /// Each carrier's payload length, `None` if it held none.
    picture: Option<u16>,
    metadata: Option<u16>,
    /// Both carriers held the same bytes, as the Both carrier writes: one
    /// backup, opened once.
    same: bool,
    /// The payload being opened: [`Carrier::Picture`] or
    /// [`Carrier::Descriptor`].
    at: Carrier,
    /// A v1.0.7 payload's seed is open, and the key for its hint, sealed
    /// apart under its own salt, is being derived.
    hint_next: bool,
    /// OTHER was tapped on LOAD SEED?: the other carrier's backup is being
    /// opened, the seed found waiting.
    other: bool,
    /// A payload tried did not open under the descriptor.
    wrong: bool,
    /// A payload tried was in a layout this unit does not open.
    unknown: bool,
}

impl Unhide {
    const NONE: Unhide = Unhide {
        picture: None,
        metadata: None,
        same: false,
        at: Carrier::Picture,
        hint_next: false,
        other: false,
        wrong: false,
        unknown: false,
    };

    /// Whether the photo held two different backups, one in each carrier.
    const fn two(&self) -> bool {
        self.picture.is_some() && self.metadata.is_some()
    }
}

/// Where in [`Buffers::photo_out`] the photo list keeps the long names: past
/// the two payloads an import or an overwrite's check puts first. An
/// embedding writes over them, so the photos are listed again after one.
const LONG_AT: usize = 2 * stego_wire::PAYLOAD_MAX;
/// Bytes the long names take: a [`card::LONG_SLOT`] a row.
const LONG_BYTES: usize = RESTORE_MAX * card::LONG_SLOT;
const _: () = assert!(
    LONG_AT + LONG_BYTES <= limits::PHOTO_OUT,
    "the long names fit the photo output buffer"
);

impl<'b, const N: usize> Flow<'b, N> {
    /// A flow at boot.
    ///
    /// `buffers` must be at least [`Sizes`] for the config, and the profile
    /// must fit [`limits::MAX_INPUTS`] and [`limits::MAX_OUTPUTS`]. Either
    /// failing is a bug in the binary, so it panics here, once, rather than
    /// being checked at each use.
    pub fn new(buffers: Buffers<'b>, config: Config<'_>) -> Self {
        let sizes = Sizes::new(&config.capacity, &config.profile);
        assert!(buffers.request.len() >= sizes.payload, "request buffer");
        assert!(buffers.reply.len() >= sizes.reply, "reply buffer");
        assert!(
            buffers.signatures.len() >= sizes.inputs,
            "signature scratch"
        );
        assert!(
            buffers.document.len() >= sizes.pskb_document,
            "bundle document"
        );
        assert!(buffers.scripts.len() >= sizes.pskb_bytes, "bundle scripts");
        assert!(buffers.redeem.len() >= sizes.redeem, "redeem scratch");
        assert!(buffers.text.len() >= sizes.edited_document, "bundle text");
        assert!(buffers.edited.len() >= sizes.edited_document, "bundle edit");
        assert!(buffers.pump.len() >= keyring::SWEEP, "pump");
        assert!(buffers.photo.len() >= limits::PHOTO_MAX, "photo");
        assert!(buffers.photo_out.len() >= limits::PHOTO_OUT, "photo out");
        assert!(buffers.window.len() >= limits::WINDOW_RANKS, "window");
        assert!(
            buffers.window_bits.len() >= limits::WINDOW_BITS,
            "window bitmaps"
        );
        assert!(buffers.app1.len() >= limits::APP1_SCRATCH, "exif scratch");
        assert!(
            sizes.pskb_bytes <= limits::MAX_PSKB_BYTES,
            "profile bundle scripts"
        );
        assert!(
            config.profile.max_inputs <= limits::MAX_INPUTS,
            "profile inputs"
        );
        assert!(
            config.profile.max_outputs <= limits::MAX_OUTPUTS,
            "profile outputs"
        );
        let mut have = [None; 4];
        for (slot, &s) in have.iter_mut().zip(config.sources.iter().take(4)) {
            *slot = Some(s);
        }
        Self {
            state: State::Boot,
            buffers,
            profile: config.profile,
            capacity: config.capacity,
            scale: Scale::for_panel(config.size),
            settings: config.settings,
            stack: config.stack,
            words: Words::Twelve,
            check: brand::Check {
                verdict: Verdict::Blank,
                image_read: false,
            },
            sources: have,
            slots: Slots::new(),
            keys: None,
            request_len: 0,
            request_digest: None,
            document_len: None,
            reply_len: 0,
            reply_signers: None,
            reply_v107: 0,
            reply_wallet: true,
            seen: 0,
            page: 0,
            progress: (0, 0),
            received: 0,
            seed_or_frame: None,
            seed_hint: false,
            since_us: 0,
            now_us: 0,
            collector: None,
            pending: None,
            typed: Typed::new(),
            first: Typed::new(),
            mismatch: false,
            backup_name: [b' '; 11],
            file: [0; FLOW_FILE],
            file_len: 0,
            deleting: false,
            replacing: false,
            phrase: [0; 24],
            word_count: 12,
            word_pos: 0,
            word_filled: 0,
            word_invalid: false,
            addr_change: false,
            addr_index: 0,
            addr_from: State::Home,
            addr_text: [0; MAX_ADDRESS_LEN],
            addr_len: 0,
            addr_key: false,
            key_text: [0; XPRV_TEXT_MAX],
            key_len: 0,
            raw_key: None,
            addr_sign: false,
            addr_group: false,
            addr_cosigner: 0,
            addr_kcc3: false,
            msg_len: 0,
            sig_len: 0,
            msg_held: 0,
            msg_signed: false,
            msg_read: 0,
            record_len: 0,
            msg_from: State::Home,
            shown_len: 0,
            msg_frames: 1,
            pad: [0; INDEX_DIGITS],
            pad_len: 0,
            rolls: [0; DICE_MAX],
            rolled: 0,
            bip85_index: 0,
            forming: None,
            group: None,
            branches: Branches::new(),
            desc_own: None,
            desc_frames: 1,
            loading: None,
            load_seed: multisig_screen::SeedIn::NoSeed,
            load_from: State::Home,
            file_addr: [0; MAX_ADDRESS_LEN],
            file_addr_len: 0,
            savings: None,
            card_frames: 1,
            cards_from: State::Home,
            review_group: None,
            review_second: 0,
            review_signs: (0, 0),
            review_inputs: None,
            reopened: None,
            hinted: [None; limits::MAX_OUTPUTS],
            deferred: None,
            last_screen: Screen::Booting,
            group_from: [None; limits::MAX_MULTISIG_KEYS],
            open_for_group: false,
            after_words: AfterWords::Passphrase,
            uneven: (0, 0),
            unbacked: [false; N],
            made_later: false,
            checks: WordChecks::EMPTY,
            saving: Saving::Backup,
            listing: Listing::Backups,
            carrier: Carrier::Descriptor,
            desc: Typed::new(),
            stego_import: false,
            unhide: Unhide::NONE,
            photo_name: [b' '; 11],
            photo_shown: [0; kassigner_fat32::fat32::MAX_LONG_NAME],
            photo_shown_len: 0,
            photo_len: 0,
            stego_rest: State::StegoCarrier,
            hint: [0; HINT_MAX],
            hint_len: 0,
            payload: [0; stego_wire::PAYLOAD_MAX],
            payload_len: 0,
            stego_live: false,
            kpub_key: KpubKey::Single,
            kpub: [0; KPUB_MAX],
            kpub_len: 0,
            kpub_raw: [0; KPUB_RAW_LEN],
            kpub_frames: 1,
            manual: false,
            plain_frames: 1,
            frame_since: 0,
            frame_us: limits::KASSIGNER_FRAME_US,
            wallet_frames: false,
            kpub_exit: State::Home,
            save_back: seed_backup(),
            backup_back: seed_backup(),
            backups: [[b' '; 11]; RESTORE_MAX],
            listed: 0,
            extra: 0,
            steps: None,
            salt: [0; SALT_SIZE],
            nonce: [0; NONCE_SIZE],
            card_exit: State::Card,
            export_from: State::ImportExport,
            opening: None,
            pressed_in: None,
            pressed_at: None,
            pressed_us: 0,
            shown_us: 0,
            touched_us: 0,
            logo_since: None,
            pumped: 0,
            backlight: config.backlight,
            volume: config.volume,
            knobs: &config.knobs[..config
                .knobs
                .len()
                .min(MAX_KNOBS - usize::from(config.tune_auto))],
            tune: [0; MAX_KNOBS],
            has_auto: config.tune_auto,
            auto: true,
            card: card::Status::Checking,
        }
    }

    /// Where the flow is.
    pub const fn state(&self) -> State {
        self.state
    }

    /// Whether the encrypting or decrypting screen is Argon2id's (about 25 s
    /// on the P4, bar at [`ARGON2_HELD`]) and says to wait: a seal when the
    /// unit lends Argon2id memory, an open when the file used it.
    pub fn kdf_wait(&self) -> bool {
        match self.state {
            State::BackupSealing { .. } => self.buffers.kdf.is_some(),
            State::RestoreOpening { done } | State::OverwriteOpening { done } => {
                done == ARGON2_HELD
            }
            _ => false,
        }
    }

    /// The active seed's fingerprint, if a wallet is open.
    pub fn fingerprint(&self) -> Option<[u8; 4]> {
        self.keys.as_ref().map(|k| k.wallet().fingerprint())
    }

    /// Answer an event. `rng` is drawn from only to sign or make a seed.
    pub fn step<E: Entropy + ?Sized>(&mut self, event: Event<'_>, rng: &mut E) -> Output {
        let out = self.answer(event, rng);
        self.last_screen = out.screen;
        out
    }

    /// [`Flow::step`]'s answer, before the screen it gives is kept.
    fn answer<E: Entropy + ?Sized>(&mut self, event: Event<'_>, rng: &mut E) -> Output {
        if let Event::Tick { now_us } = event {
            self.now_us = now_us;
        }
        if let Event::Press { .. } | Event::Drag { .. } | Event::Tap { .. } = event {
            self.touched_us = self.now_us;
        }
        let kind = discriminant(&self.state);
        // Untouched for IDLE_WIPE_US while a seed, or anything secret typed
        // or rolled, is held: wipe it all and go home, turning off a camera,
        // the generator's sources or the tuning first. A job holding the
        // unit may finish; a halt is never left.
        if let Event::Tick { now_us } = event {
            if self.holds_secret()
                && !self.busy()
                && !matches!(self.state, State::Halted(_))
                && now_us.saturating_sub(self.touched_us) >= IDLE_WIPE_US
            {
                let command = match self.state {
                    State::Scanning | State::MessageScan | State::BackupScan { .. } => {
                        Some(Command::CameraOff)
                    }
                    State::Generating => Some(Command::SamplesOff),
                    State::CameraTune { .. } => Some(Command::TuneOff),
                    _ => None,
                };
                self.wipe_everything();
                self.state = State::Home;
                self.shown_us = now_us;
                return Output {
                    screen: self.screen(),
                    command,
                };
            }
        }
        // The last tap's work, done on the next tick, or first on any other
        // event so nothing acts on a stale screen. A group's address waits
        // until its branches are derived.
        if let Some(work) = self.deferred.filter(|&w| self.can_settle(w)) {
            self.deferred = None;
            let command = self.settle(work);
            if command.is_some() || matches!(event, Event::Tick { .. }) {
                return Output {
                    screen: self.screen(),
                    command,
                };
            }
        }
        // A finger that went down on one screen and lifts on another did not
        // tap the second: the screen changed under it.
        let (pressed_in, pressed_at) = match event {
            Event::Tap { .. } => (self.pressed_in.take(), self.pressed_at.take()),
            _ => (None, None),
        };
        if pressed_in.is_some_and(|s| s != discriminant(&self.state)) {
            return Output {
                screen: self.screen(),
                command: None,
            };
        }
        // The idle pump: while nothing else wants the unit, a key a tick.
        if let Event::Tick { .. } = event {
            if matches!(
                self.state,
                State::Home
                    | State::Menu { .. }
                    | State::Seeds { .. }
                    | State::Display
                    | State::Audio
                    | State::About
                    | State::Card
            ) {
                let _ = self.pump_one();
            }
        }
        let command = match self.state {
            State::Boot => self.on_boot(event),
            State::Halted(_) => None,
            State::Verified(check) => {
                // Red waits for a tap; anything else passes on its own.
                let done = if check.red() {
                    let tapped = matches!(event, Event::Tap { .. });
                    if tapped {
                        self.state = self.home();
                    }
                    tapped
                } else {
                    self.on_timed(event, VERIFIED_US)
                };
                // A provisioned unit closes its port on the way out, holes or
                // not; a blank one, as its owner chose, keeps it.
                (done && check.verdict.is_provisioned()).then_some(Command::CloseConsole)
            }
            State::Home => self.on_home(event),
            State::Wiped => {
                self.on_timed(event, WIPED_US);
                None
            }
            State::Menu { menu, page } => self.on_menu(event, menu, page),
            State::Seeds { page } => self.on_seeds(event, page),
            State::Scanning => self.on_scanning(event),
            State::Asking { next, kcc3 } => self.on_asking(event, next, kcc3, pressed_at),
            State::Searching {
                next,
                stop,
                ask,
                kcc3,
            } => self.on_searching(event, next, stop, ask, kcc3),
            State::Reviewing => self.on_reviewing(event, pressed_at),
            State::Confirming => self.on_confirming(event, pressed_at),
            State::Signing => {
                if let Event::Tick { .. } = event {
                    self.sign(rng);
                }
                None
            }
            State::Checking { len, card } => {
                if let Event::Tick { .. } = event {
                    self.start_request(len, card);
                }
                None
            }
            State::Showing { frame } => self.on_showing(event, frame),
            State::ReplyFormat => self.on_reply_format(event),
            State::ReplyMode => self.on_reply_mode(event, pressed_at),
            State::ReplyDone => self.on_reply_done(event, pressed_at),
            State::MessageDone => self.on_message_done(event, pressed_at),
            State::AddressDone => self.on_address_done(event, pressed_at),
            State::SeedDone { plain, compact } => {
                self.on_seed_done(event, plain, compact, pressed_at)
            }
            State::Refused(_) => {
                self.on_timed(event, REFUSED_US);
                None
            }
            State::Generating => self.on_generating(event, rng),
            State::Loading => self.on_loading(event, pressed_at),
            State::Passphrase { page } => self.on_passphrase(event, page, false),
            State::PassphraseAgain { page } => self.on_passphrase(event, page, true),
            State::Opening { slot } => self.on_opening(event, slot),
            State::Deleting {
                slot,
                armed,
                held_since,
            } => self.on_deleting(event, slot, armed, held_since),
            State::Display => self.on_level(event, Setting::Display),
            State::Audio => self.on_level(event, Setting::Audio),
            State::About => {
                if let Event::Tap { .. } = event {
                    self.state = self.settings_at(Setting::About);
                }
                None
            }
            State::CameraTune { knob } => self.on_camera_tune(event, knob),
            State::Card => self.on_card(event),
            State::CardFormat { armed, held_since } => {
                self.on_card_format(event, armed, held_since)
            }
            State::CardBusy(job) => match event {
                Event::Card(outcome) => self.on_card_job(job, outcome),
                _ => None,
            },
            State::CardDone { job, outcome } => {
                if let Event::Tick { now_us } = event {
                    if now_us.saturating_sub(self.since_us) >= card_done_us(job, outcome) {
                        self.state = self.card_exit;
                    }
                }
                None
            }
            State::ImportExport => self.on_import_export(event),
            State::BackupWarning => self.on_backup_warning(event),
            State::BackupName { page } => self.on_backup_name(event, page),
            State::BackupOverwrite => self.on_backup_overwrite(event, pressed_at),
            State::OverwritePassword { page } => self.on_overwrite_password(event, page),
            State::OverwriteOpening { done } => self.on_overwrite_opening(event, done),
            State::BackupPassword { page, again } => self.on_backup_password(event, page, again),
            State::BackupSealing { done } => self.on_backup_sealing(event, done, rng),
            State::RestoreList { page } => self.on_restore_list(event, page),
            State::RestorePassword { page } => self.on_restore_password(event, page),
            State::RestoreDelete {
                page,
                armed,
                held_since,
            } => self.on_restore_delete(event, page, armed, held_since),
            State::RestoreOpening { done } => self.on_restore_opening(event, done),
            State::WordCount { action } => self.on_word_count(event, action),
            State::Words { action } => self.on_words(event, action),
            State::LastWord { choice } => self.on_last_word(event, choice),
            State::Address => self.on_address(event),
            // A tap from a key's code goes back to its text, never to the
            // card; from an address's, to ADDRESS EXPORTED.
            State::AddressQr => {
                if let Event::Tap { .. } = event {
                    self.state = if self.addr_key {
                        State::Address
                    } else {
                        State::AddressDone
                    };
                }
                None
            }
            State::AddressIndex => self.on_address_index(event),
            State::Kprv { master } => self.on_kprv(event, master),
            // The code: a tap back to the text.
            State::KprvQr { master } => {
                if let Event::Tap { .. } = event {
                    self.state = State::Kprv { master };
                }
                None
            }
            State::KprvDeriving => self.on_kprv_deriving(event),
            State::KeyDeriving => self.on_key_deriving(event),
            State::GroupDeriving => self.on_group_deriving(event),
            State::RawKey => self.on_raw_key(event),
            State::RawKeyConfirm => self.on_raw_key_confirm(event, pressed_at),
            State::MessageType { page } => self.on_message_type(event, page),
            State::MessageScan => self.on_message_scan(event),
            State::MessagePreview { page } => self.on_message_preview(event, page),
            State::MessageConfirm => self.on_message_confirm(event, pressed_at),
            State::MessageSigning => {
                if let Event::Tick { .. } = event {
                    self.sign_message(rng);
                }
                None
            }
            State::MessageCheck { .. } => self.on_message_check(event, pressed_at),
            State::MessageResult { page } => self.on_message_result(event, page),
            State::MessageFormat => self.on_message_format(event),
            State::MessageMode => self.on_message_mode(event, pressed_at),
            State::MessageFrames { frame } => self.on_message_frames(event, frame),
            State::Dice => self.on_dice(event),
            State::DiceRefused => {
                if let Event::Tick { now_us } = event {
                    if now_us.saturating_sub(self.since_us) >= SAID_US {
                        self.state = seed_tools(CountFor::Dice);
                    }
                }
                None
            }
            State::Bip85 => self.on_bip85(event),
            State::Bip85Index => self.on_bip85_index(event),
            State::Bip85Deriving => self.on_bip85_deriving(event),
            State::DiceUneven => self.on_dice_uneven(event, pressed_at),
            State::ShowWords { pos } => self.on_show_words(event, pos, rng),
            State::BackupAsk { by } => self.on_backup_ask(event, by, pressed_at, rng),
            State::WordCheck { round } => self.on_word_check(event, round, pressed_at),
            State::CheckFailed { by } => self.on_check_failed(event, by),
            State::BackupChecked { by } => self.on_backup_checked(event, by),
            State::BackupScan { plain, compact } => self.on_backup_scan(event, plain, compact),
            // The code full screen: a tap for the grid view.
            State::SeedQr { compact } => {
                if let Event::Tap { .. } = event {
                    self.state = State::SeedQrGrid {
                        compact,
                        x: 0,
                        y: 0,
                    };
                }
                None
            }
            State::SeedQrGrid { compact, x, y } => self.on_seedqr_grid(event, compact, (x, y)),
            State::KpubFormat => self.on_kpub_format(event),
            State::KpubMode => self.on_kpub_mode(event, pressed_at),
            State::KpubQr { frame } => self.on_kpub_qr(event, frame),
            State::KpubExported => self.on_kpub_exported(event, pressed_at),
            State::KpubEncrypt => self.on_kpub_encrypt(event, pressed_at),
            State::BackupNoPassword { armed, held_since } => {
                self.on_backup_no_password(event, armed, held_since)
            }
            State::KpubScanned => self.on_kpub_scanned(event, pressed_at),
            State::CreateMultisig { m, n } => self.on_create_multisig(event, m, n),
            State::AddKey => self.on_add_key(event),
            State::CosignerKey => self.on_cosigner_key(event, pressed_at),
            State::Descriptor => self.on_descriptor(event),
            State::DescriptorFormat => self.on_descriptor_format(event),
            State::DescriptorMode => self.on_descriptor_mode(event, pressed_at),
            State::DescriptorFrames { frame } => self.on_descriptor_frames(event, frame),
            State::LoadGroup => self.on_load_group(event, pressed_at),
            State::FileAddress => self.on_file_address(event),
            // Its code: a tap back to its text.
            State::FileAddressQr => {
                if let Event::Tap { .. } = event {
                    self.state = State::FileAddress;
                }
                None
            }
            State::Savings { page } => self.on_savings(event, page, pressed_at),
            State::SavingsSearching { page, next, stop } => {
                self.on_savings_searching(event, (page, next, stop), pressed_at)
            }
            State::SavingsFormat { page } => self.on_savings_format(event, page),
            State::SavingsMode { page } => self.on_savings_mode(event, page, pressed_at),
            State::SavingsFrames { page, frame } => self.on_savings_frames(event, page, frame),
            // Its address's code: a tap back to the first page.
            State::SavingsAddressQr => {
                if let Event::Tap { .. } = event {
                    self.state = State::Savings { page: 0 };
                }
                None
            }
            State::SelectSeed { page } => self.on_select_seed(event, page),
            State::StegoCarrier => self.on_stego_carrier(event),
            State::StegoDescriptor { page } => self.on_stego_descriptor(event, page),
            State::StegoPreview => self.on_stego_preview(event, pressed_at),
            State::StegoHintAsk => self.on_stego_hint_ask(event, pressed_at),
            State::StegoHint => self.on_stego_hint(event),
            State::StegoHintType { page } => self.on_stego_hint_type(event, page),
            State::StegoConfirm => self.on_stego_confirm(event, pressed_at),
            State::StegoSealing { done } => self.on_stego_sealing(event, done, rng),
            State::StegoEmbedding => self.on_stego_embedding(event, rng),
            State::StegoDone => self.on_stego_done(event, pressed_at),
            State::StegoKey { page } => self.on_stego_key(event, page),
            State::StegoReading => self.on_stego_reading(event),
            State::StegoOpening { .. } => self.on_stego_opening(event),
            State::StegoFound => self.on_stego_found(event, pressed_at),
            State::StegoHintShown => self.on_stego_hint_shown(event, pressed_at),
            State::StegoOverwrite => self.on_stego_overwrite(event, pressed_at),
            State::StegoOldKey { page } => self.on_stego_key(event, page),
            // The plain text's code: a tap back to QR Export.
            State::PlainQr => {
                if let Event::Tap { .. } = event {
                    self.seed_shown(true, false);
                }
                None
            }
            State::PlainFormat => self.on_plain_format(event),
            State::PlainMode => self.on_plain_mode(event, pressed_at),
            State::PlainFrames { frame } => self.on_plain_frames(event, frame),
        };
        self.keep_key();
        self.keep_reply();
        self.keep_message();
        self.keep_forming();
        if discriminant(&self.state) != kind {
            self.shown_us = self.now_us;
        }
        // Note the screen a finger goes down on by kind, not by its numbers,
        // which (a search's count, a hold's start) change under a finger
        // that stays.
        if let Event::Press { x, y } = event {
            self.pressed_in = Some(discriminant(&self.state));
            self.pressed_at = Some((x, y));
            self.pressed_us = self.now_us;
        }
        // A tap whose work waits has changed nothing yet: give the screen it
        // was taken on, not rebuilt, since building a review's page reads the
        // request again.
        let screen = if command == Some(Command::Deferred) {
            self.last_screen
        } else {
            self.screen()
        };
        Output { screen, command }
    }

    /// Leave `work` for the next tick ([`Flow::settle`]); the command clicks
    /// the tap now, its screen unchanged until then.
    fn defer(&mut self, work: Work) -> Option<Command> {
        self.deferred = Some(work);
        Some(Command::Deferred)
    }

    /// Whether `work` can be done now: a group's address once its keys are
    /// derived at every branch, anything else at once.
    fn can_settle(&self, work: Work) -> bool {
        !matches!(work, Work::Address(_)) || !self.addr_group || self.branches.ready()
    }

    /// Do the work a tap left ([`Flow::defer`]), giving the tap's command.
    fn settle(&mut self, work: Work) -> Option<Command> {
        match work {
            Work::Address(at) => self.settle_address(at),
            Work::GroupAddress => self.settle_group_address(),
            Work::Descriptor => {
                self.desc_own = self.group_position().and_then(|p| u8::try_from(p).ok());
                self.state = State::Descriptor;
            }
            Work::Kpub { row } => return self.kpub_row(row),
            Work::OwnCosigner => self.add_own_cosigner(),
            Work::RawKey => self.import_raw_key(),
            Work::CheckMessage => {
                self.state = State::MessageCheck {
                    valid: self.check_message(),
                }
            }
            Work::Review(target) => self.review_arrow(target),
        }
        None
    }

    /// The board's time at the last tick, in microseconds: every wait's
    /// clock.
    pub const fn now_us(&self) -> u64 {
        self.now_us
    }

    /// A password's derivation is over, done or failed: drop the steps,
    /// which wipes what they hold, and scrub the stack the rounds ran on, as
    /// after opening a wallet: HMAC's key setup over the password, each
    /// round's block and Argon2's work leave bytes in frames no type
    /// reaches. Every end of an opening or a sealing comes here; those
    /// screens take no tap, so none is abandoned.
    fn derivation_over(&mut self) {
        self.steps = None;
        wipe::begin_depth(self.stack);
        wipe::scrub_flow();
    }

    /// A key that edits the line or turns the page, alike on every keyboard;
    /// `at` gives the state at another page.
    fn edit(&mut self, key: keyboard::Key, page: u8, at: impl Fn(u8) -> State) {
        match key {
            keyboard::Key::Delete => self.typed.backspace(),
            keyboard::Key::Left => self.typed.left(),
            keyboard::Key::Right => self.typed.right(),
            keyboard::Key::Page => self.state = at(keyboard::next_page(page)),
            keyboard::Key::Char(_) | keyboard::Key::Space | keyboard::Key::Ok => {}
        }
    }

    /// The frame after `frame` of `frames` once `frame_us` has passed since
    /// the last turn, for every cycling code; none for a single code.
    fn turn(&mut self, now_us: u64, frame: u8, frames: u8) -> Option<u8> {
        if frames <= 1 || now_us.saturating_sub(self.frame_since) < self.frame_us {
            return None;
        }
        self.frame_since = now_us;
        Some((frame + 1) % frames)
    }

    fn refuse(&mut self, why: Refusal) {
        // A failed save of a signed transaction keeps it: its request, which
        // says the reply's format, goes when the reply does.
        if self.reply_len == 0 {
            self.drop_request();
        }
        self.since_us = self.now_us;
        self.state = State::Refused(why);
    }
}

/// An account's public half, from its private key: the curve multiplication,
/// in a frame of its own for the scrub after it.
#[inline(never)]
fn public_of(account: &ExtendedPrivateKey) -> ExtendedPublicKey {
    account.to_extended_public_key()
}

/// The master key `m` of a seed's words and passphrase: the BIP39 stretch,
/// then BIP32's root. The caller gives it a frame of its own.
fn master_of(mnemonic: &Mnemonic, passphrase: &str) -> Result<ExtendedPrivateKey, Refusal> {
    let mut scratch = [0u8; bip39::scratch_for(PASSPHRASE_MAX)];
    let seed = bip39::to_seed(mnemonic, passphrase, &mut scratch);
    wipe::wipe(&mut scratch);
    let seed = seed.map_err(|_| Refusal::NotDerived)?;
    ExtendedPrivateKey::from_seed(seed.as_bytes()).map_err(|_| Refusal::NotDerived)
}

/// A frame's code: version 9 for a wallet's, the version they are cut for,
/// whatever a frame carries; the smallest that holds it for another unit's.
fn frame_code(bytes: &[u8], wallet: bool) -> Option<kassigner_qr::encode::QrMatrix> {
    if wallet {
        kassigner_qr::encode_at(bytes, kassigner_qr::MAX_VERSION).ok()
    } else {
        kassigner_qr::encode::encode(bytes).ok()
    }
}

/// The codes `len` bytes of a signed message take for a wallet (version 9)
/// or another unit (version 3): one if they fit with room for a frame
/// header, else frames.
const fn message_codes(len: usize, wallet: bool) -> usize {
    let per = if wallet {
        MESSAGE_WALLET_BYTES
    } else {
        UNIT_FRAME_BYTES
    };
    if len <= per {
        1
    } else {
        kassigner_protocol::frame::frames_needed(len, per)
    }
}

/// Whether text for Sign Message holds a seed the home Scan would read, by
/// its own readers: a standard SeedQR's 48 or 96 digits, valid or not, or
/// twelve or more words of the list. A compact SeedQR's 16 or 32 bytes, as
/// text, cannot be told from a message of that length, so they are taken as
/// a message.
fn holds_seed(text: &[u8]) -> bool {
    let standard = match seed::read_qr(text) {
        Ok((_, seed::Encoding::Standard)) | Err(seed::ReadError::Slot(_)) => true,
        Ok((_, seed::Encoding::Compact)) | Err(seed::ReadError::NotSeedQr) => false,
    };
    standard || !matches!(seed::read_words(text), seed::Text::NotWords)
}

#[cfg(test)]
mod tests {
    use super::{frame, unchanged, Refusal};

    /// A request is held to the digest its review started on: the same
    /// bytes pass; one byte changed, added or gone does not; no digest is no
    /// review to sign. Nothing a request or a person does can change the
    /// bytes between the review's start and the signing, so the test changes
    /// them directly.
    #[test]
    fn a_request_is_held_to_its_review_digest() {
        let request: [u8; 300] = core::array::from_fn(|i| i as u8);
        let taken = Some(frame::sha256(&request));
        assert_eq!(unchanged(taken, &request), Ok(()));
        for at in [0, 150, 299] {
            let mut changed = request;
            changed[at] ^= 0x01;
            assert_eq!(
                unchanged(taken, &changed),
                Err(Refusal::RequestChanged),
                "{at}"
            );
        }
        assert_eq!(
            unchanged(taken, &request[..299]),
            Err(Refusal::RequestChanged)
        );
        let longer: [u8; 301] = core::array::from_fn(|i| if i < 300 { i as u8 } else { 0 });
        assert_eq!(unchanged(taken, &longer), Err(Refusal::RequestChanged));
        assert_eq!(unchanged(None, &request), Err(Refusal::RequestChanged));
    }
}
