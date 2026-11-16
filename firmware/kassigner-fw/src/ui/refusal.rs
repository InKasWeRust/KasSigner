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

//! Errors and refusals: their words, the ERROR screen ([`draw`]) and the
//! PANIC screen of a unit that stops ([`panic()`]).
//!
//! Every word is here, so a failure reads the same wherever it happened. An
//! ERROR screen has no hint to tap: the flow times how long it stays.

use super::band::Band;
use super::chrome::header_in;
use super::color::{DANGER, TEXT, TEXT_DIM};
use super::scale::{Kit, Scale};

/// What a refusal says: a line, and a second one or `""`.
pub type Words = (&'static str, &'static str);

/// A QR that is not a request, SeedQR, seed words, kpub or signed message.
pub const NOT_RECOGNISED: Words = ("Unrecognised QR", "Not a KasSigner code");
/// A request this unit cannot read, or too large to hold.
pub const NOT_A_REQUEST: Words = ("Request not readable", "Not a KSPT or PSKB it reads");
pub const NOT_A_TRANSACTION: Words = ("Request not readable", "It holds no transaction");
/// A transaction that cannot be reviewed; the second line says why.
pub const NOT_REVIEWABLE: &str = "Cannot review";
pub const TOO_MANY_PAGES: &str = "Too many outputs to show";
/// Amounts that do not add up within range.
pub const VALUE_OVERFLOW: &str = "Amounts out of range";
/// A transaction on a non-native subnetwork.
pub const NOT_NATIVE: &str = "Not a native transaction";
pub const GAS: &str = "Gas is not zero";
/// A storage mass over the block limit, which every node refuses.
pub const STORAGE_MASS: &str = "Over the storage mass limit";
pub const ABOVE_SUPPLY: &str = "Above Kaspa's total supply";
pub const ZERO_OUTPUT: &str = "An output of zero KAS";
/// Two inputs spending the same UTXO, which consensus refuses.
pub const DUPLICATE_INPUT: &str = "A UTXO is spent twice";
/// A field consensus does not allow on its version.
pub const CONSENSUS: &str = "Consensus refuses it";
pub const TX_VERSION: &str = "Unknown transaction version";
/// A covenant binding naming an input the transaction does not have.
pub const COVENANT_INPUT: &str = "Covenant input out of range";
/// An output under a script version consensus does not run.
pub const SCRIPT_VERSION: &str = "Unknown script version";
pub const NON_STANDARD_OUTPUT: &str = "Non-standard output";
/// A payload, which no page shows yet.
pub const PAYLOAD_UNSHOWN: &str = "Payloads not shown yet";
/// An input of ours under a redeem script that is not a multisig, which
/// no page shows yet.
pub const SCRIPT_UNSHOWN: &str = "Script inputs not shown yet";
/// An input with a relative lock, which no page shows yet.
pub const RELATIVE_UNSHOWN: &str = "Relative locks not shown yet";
/// A Time-Locked Savings card spent where its program would refuse; the
/// second line says why.
pub const CARD_LOCKED: &str = "Card still locked";
/// The transaction's lock time is not a time at or past the card's.
pub const CARD_EARLY: &str = "Lock time is before it opens";
/// The card's input is final, which turns the lock time off.
pub const CARD_FINAL: &str = "Its input skips the lock";
/// A card's backup line scanned and not taken; the second line says why.
pub const CARD_BACKUP: &str = "Card backup not read";
/// Text that is no card's backup line: no name the unit knows.
pub const BACKUP_NOT_ONE: &str = "Not a card's backup line";
/// The name, but not its four fields, or something after them.
pub const BACKUP_MALFORMED: &str = "Its fields are malformed";
/// A key field that is not a mainnet Schnorr key's address.
pub const BACKUP_BAD_KEY: &str = "A key is not a kaspa:q address";
/// A time not in the calendar, or not written day first with its hour and
/// minute.
pub const BACKUP_BAD_DATE: &str = "Its time is not DD/MM/YYYY HH:MM";
/// A card field that is not a mainnet script's address.
pub const BACKUP_BAD_ADDRESS: &str = "Its card is not a kaspa:p address";
/// An address that is not the card the other fields make.
pub const BACKUP_NOT_THE_CARD: &str = "Its address is not this card's";
/// The card, written another way than its one line.
pub const BACKUP_NOT_CANONICAL: &str = "Not the card's own line";
/// Signing that did not finish; the second line says why.
pub const NOT_SIGNED: &str = "Signing failed";
/// No input is locked to one of the seed's keys.
pub const NOTHING_SIGNED: &str = "No input is this seed's";
/// Some inputs are locked to the seed's keys, and some not.
pub const NOT_EVERY_INPUT: &str = "An input is not this seed's";
/// A signed transaction opened to be shown, with an input no signature
/// covers: its amount is unchecked, so In and Fee are not shown.
pub const INPUT_UNSIGNED: &str = "An input has no signature";
/// A group is held, and an input is not locked to its script at the place
/// the request names for it.
pub const NOT_THE_GROUPS: &str = "An input is not this group's";
/// A reply larger than the unit shows.
pub const TOO_LARGE: &str = "Too much data";
/// A bundle with more than one transaction.
pub const NOT_ONE_TRANSACTION: &str = "One transaction at a time";
pub const SIGHASH_NOT_ALL: &str = "Only SIGHASH_ALL is signed";
pub const ALREADY_SIGNED: &str = "Already signed by this seed";
/// A signature in the request, anyone's, that does not check out.
pub const BAD_SIGNATURE: &str = "Bad signature in request";
/// More keys than [`crate::limits::MAX_MULTISIG_KEYS`] (a test holds the
/// number to it).
pub const MULTISIG_TOO_MANY_KEYS: &str = "More than 5 multisig keys";
pub const MULTISIG_NO_THRESHOLD: &str = "Multisig with no threshold";
pub const MULTISIG_REPEATED_KEY: &str = "Multisig repeats a key";
/// A multisig input committing fewer signature operations than it has keys.
pub const MULTISIG_OP_COUNT: &str = "Multisig op count too low";
/// A single key's input committing no signature operation.
pub const OP_COUNT: &str = "Op count too low";
/// A redeem script that is not the one its input's script locks to.
pub const REDEEM_MISMATCH: &str = "Redeem script doesn't match";
/// A pay-to-script-hash input that carries no redeem script.
pub const NO_REDEEM_SCRIPT: &str = "No redeem script";
/// A reply that did not check out when read back.
pub const NOT_VERIFIED: Words = ("Signing failed", "The reply did not check out");
/// A request whose bytes changed since its review started, found at
/// CONFIRM SEND? or at signing.
pub const REQUEST_CHANGED: Words = ("Signing failed", "Request changed after review");
/// A SeedQR, or seed words, that are not a seed phrase.
pub const NOT_A_SEED: Words = ("Invalid seed phrase", "");
pub const NOT_A_KPUB: Words = ("kpub format error", "");
/// A cosigner's key the group being made has already.
pub const KEY_ADDED: Words = ("Key already added", "");
/// A seed picked for a group that has no cosigner key: a raw key, or an
/// xprv imported at its account, which has no `m/45'` to derive from.
pub const NO_COSIGNER_KEY: Words = ("No cosigner key", "Only seed words or a master xprv");
/// KCC-3 Address for a seed with no `22'` tree: an account xprv or a raw
/// key.
pub const NO_KCC3_KEY: Words = ("No KCC-3 keys", "Only seed words or a master xprv");
/// A multisig group's descriptor, scanned or on the card, whose keys are
/// not kpubs, or a key twice, or more keys than a unit holds.
pub const NOT_A_DESCRIPTOR: Words = ("Not a valid descriptor", "");
/// All of a group's keys in, and the group could not be made.
pub const GROUP_NOT_MADE: Words = ("Multisig not created", "");
/// A typed raw key that is not a private key.
pub const NOT_A_KEY: Words = ("Invalid key", "");
/// Sign Message's camera read something that is not text.
pub const NOT_TEXT: Words = ("Not a text message", "");
/// A text to sign with a space ending any line, or a line break ending the
/// text: those would be signed but show as nothing.
pub const TRAILING_WHITESPACE: Words = ("Trailing spaces or lines", "Not shown, so not signed");
/// A signed message's address not on mainnet.
pub const NOT_MAINNET: Words = ("Not a mainnet address", "KasSigner is mainnet only");
/// A seed given to Sign Message, refused and not kept.
pub const SEED_NOT_MESSAGE: Words = ("Seed, not a message", NOT_DICE.1);
/// Text frames on the home scanner, where only a signed message is read.
pub const PLAIN_TEXT: Words = ("Plain text", "Scan it from Sign Message");
/// The seed in use is a key, where words are needed.
pub const NO_PHRASE: Words = ("Needs mnemonic seed", "");
pub const NO_WALLET: Words = ("Load a seed first", "");
/// A seed that could not be stored or opened.
pub const NOT_OPENED: Words = ("Seed not opened", "");
/// Every slot holds a seed ([`crate::limits::SLOTS`]; a test holds the
/// number to it).
pub const SLOTS_FULL: Words = ("All 6 slots full!", "");
pub const NO_ENTROPY: Words = ("Secure RNG failed", "");
/// The person declined.
pub const DECLINED: Words = ("TX Cancelled", "");
/// The camera stopped giving pictures while it was on.
pub const NO_CAMERA: Words = ("Camera failed", "No picture from the camera");
/// A file that could not be sealed or made.
pub const NOT_SAVED: Words = ("File not saved", "");
/// Steganography's refusals.
pub const NOT_A_JPEG: Words = ("Not a JPEG", "The file is not a photo");
pub const PROGRESSIVE_JPEG: Words = ("Progressive JPEG", "Save it as a baseline JPEG");
pub const PHOTO_TOO_SMALL: Words = ("Photo too small", "Not enough detail to hide in");
pub const PHOTO_TOO_LARGE: Words = ("Photo too large", "Over what the unit holds");
pub const PHOTO_DAMAGED: Words = ("Photo damaged", "The file does not decode");
pub const EXIF_FAILED: Words = ("EXIF failed", "No metadata block could be built");
pub const VERIFY_FAILED: Words = ("Verify failed", "Nothing was written");
/// Stego Import found no payload in either carrier. A wrong descriptor
/// reads the same: it keys the walk that finds the picture's payload.
pub const NO_BACKUP: Words = ("No backup found", "Or the descriptor is wrong");
/// A seed made on this unit used before its backup was checked.
pub const NOT_BACKED_UP: Words = ("No backup yet", "Back it up in Seed Backup");
/// The backup check: a word picked that is not the seed's there.
pub const WRONG_WORD: Words = ("Wrong word", "Check your copy of the words");
/// The backup check: a copy scanned that is not the seed in use.
pub const NOT_THIS_SEED: Words = ("Not this seed", "Scan the copy you made");
/// Stego Import found a payload that did not open under the descriptor.
pub const WRONG_DESCRIPTOR: Words = ("Wrong descriptor", "Or the photo is damaged");
/// Stego Import found a payload in a layout this unit does not open.
pub const UNKNOWN_FORMAT: Words = ("Unknown format", "");
pub const NOT_DERIVED: Words = ("Key derivation failed", "");
/// A message too long to sign, save or show.
pub const TOO_LONG: Words = ("Message too long", "");
/// A message signature that could not be made.
pub const MESSAGE_NOT_SIGNED: Words = ("Signing failed", "");
pub const NOT_DICE: Words = ("Rolls don't look like dice", "Nothing was kept");
/// A start-up check that failed: the unit stops.
pub const SELF_TEST: &str = "Self-test failed";
/// The camera's sensor did not answer, or its buffers could not be set
/// up. The unit stops.
pub const CAMERA_FAILED: &str = "Camera failed";
/// The decoder could not be set up. The unit stops.
pub const DECODER_FAILED: &str = "Decoder failed";
/// The generator would not start. The unit stops.
pub const GENERATOR_FAILED: &str = "Generator failed";
/// Every reason the PANIC screen gives.
pub const HALTS: [&str; 4] = [SELF_TEST, CAMERA_FAILED, DECODER_FAILED, GENERATOR_FAILED];

/// The ERROR screen, saying `words`.
pub fn draw(band: &mut Band<'_>, scale: Scale, kit: &Kit, (first, second): Words) {
    header_in(band, scale, kit, "ERROR", DANGER, DANGER);
    let mid = scale.x(160);
    if second.is_empty() {
        band.text_centered(kit.title, mid, scale.y(120), TEXT_DIM, first);
    } else {
        band.text_centered(kit.title, mid, scale.y(100), TEXT, first);
        band.text_centered(kit.body, mid, scale.y(130), TEXT_DIM, second);
    }
}

/// The PANIC screen, saying `reason`.
pub fn panic(band: &mut Band<'_>, scale: Scale, kit: &Kit, reason: &str) {
    // The whole panel, past the design's edges on a wider one: the band
    // clips the rest.
    band.fill(0, 0, i32::MAX, i32::MAX, DANGER);
    let mid = scale.x(160);
    band.text_centered(kit.header, mid, scale.y(60), TEXT, "!!! PANIC !!!");
    band.text_centered(kit.body, mid, scale.y(120), TEXT, reason);
    band.text_centered(kit.header, mid, scale.y(180), TEXT, "NO BOOT");
}
