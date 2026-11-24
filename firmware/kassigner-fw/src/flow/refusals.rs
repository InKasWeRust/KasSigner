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

//! Why the flow stops or refuses, how it is said, and what a review cannot
//! show yet.

use super::*;

use kassigner_protocol::card::backup::BackupError as CardBackupError;

/// Why the unit stopped. Never the fuses: what they found is the
/// verification screen's to say.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Halt {
    /// A start-up check failed.
    SelfTest,
}

/// Why something was turned away; not a fault, the unit goes back to where
/// it rests. A request with nothing of ours, or a reply too large to show,
/// is refused before any page; a reply that fails to write or verify, after
/// confirming. Each says one thing, for the ERROR screen
/// ([`Refusal::words`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// What the camera read is none of this unit's codes.
    NotRecognised,
    /// Not a KSPT or PSKB this device reads, or too large to hold.
    NotARequest,
    /// The request did not describe a transaction.
    NotATransaction,
    /// The transaction could not be reviewed, or the session refused a
    /// decision.
    NotReviewable(session::Error),
    /// A page the review does not draw yet: refused rather than signed
    /// unseen.
    Unshown(Unshown),
    /// A Time-Locked Savings card spent by a transaction its program would
    /// refuse, as the network would.
    CardLocked(CardLock),
    /// A review page, or CONFIRM SEND?'s totals, could not be shown: refused
    /// rather than counted seen over a black panel with CONFIRM still live.
    /// The flow could not build it, which no request reaches (`Unshown` and
    /// the session's checks keep every page buildable), or the panel did not
    /// take it ([`Event::NotDrawn`]). A message's page or SIGN MESSAGE? the
    /// panel did not take refuses the message under the same words.
    NotDrawn,
    /// The reply could not be planned or written.
    NotSigned(reply::Error),
    /// A group is held and the request spends a multisig input that is not
    /// its: refused, so a held group's inputs and change are always its own.
    NotTheGroups,
    /// The reply did not check out when read back.
    NotVerified(reply::Unverified),
    /// The request's bytes changed since its review started (by SHA-256, at
    /// CONFIRM SEND? and at signing): nothing signed.
    RequestChanged,
    /// A SeedQR or seed words with a bad checksum or digit, or not 12 or 24
    /// words.
    NotASeed,
    /// A kpub that did not read as one.
    NotAKpub,
    /// A cosigner's key already among the group's being made.
    KeyAdded,
    /// The group could not be made of its keys.
    GroupNotMade,
    /// A descriptor the home scanner read that is not a group's.
    NotADescriptor,
    /// A scanned card backup line that does not rebuild its card, and why.
    CardBackup(CardBackupError),
    /// A seed picked for a group that has no cosigner key.
    NoCosignerKey,
    /// KCC-3 Address for an account xprv or a raw key, which have none.
    NoKcc3Key,
    /// A typed raw key that is not a private key.
    NotAKey,
    /// Sign Message's camera read something that is not text.
    NotText,
    /// A message ending a line or itself with a space, or ending with a
    /// line break: signed, those show as nothing.
    TrailingWhitespace,
    /// A signed message from another network than mainnet. The units are
    /// mainnet only: a transaction does not name its network, but a
    /// message's address does, so another is refused.
    NotMainnet,
    /// Sign Message was given a seed (SeedQR digits, or twelve or more seed
    /// words): never a message, which is shown and signed in the clear, and
    /// nothing of it kept.
    SeedNotMessage,
    /// Text frames on the home scanner that are not a signed message: text
    /// to sign is scanned from Sign Message.
    PlainText,
    /// The seed in use is a key, where its words are needed.
    NoPhrase,
    /// No seed in use.
    NoWallet,
    /// The seed in use was made here and its backup is unchecked: until it
    /// is checked, it can only be backed up.
    NotBackedUp,
    /// A seed could not be stored, or its wallet opened.
    NotOpened,
    /// Every slot holds a seed.
    SlotsFull,
    /// The generator failed.
    NoEntropy,
    /// The person declined.
    Declined,
    /// A file could not be sealed or made.
    NotSaved,
    /// A key of the seed in use, or of a group at a branch, could not be
    /// derived.
    NotDerived,
    /// A message too long to take, save or show.
    TooLong,
    /// A message's signature could not be made.
    MessageNotSigned,
    /// The camera stopped giving pictures while it was on.
    NoCamera,
    /// A photo the steganography carriers could not take, by name.
    Stego(StegoError),
    /// Stego Import: neither carrier gave a payload. A wrong descriptor gives
    /// this too, as the descriptor keys the picture's walk.
    NoBackup,
    /// Stego Import: a payload that did not open under the descriptor.
    WrongDescriptor,
    /// Stego Import: a layout this unit does not open, such as v1.0.5's
    /// containers under one fixed salt.
    UnknownFormat,
}

impl Refusal {
    /// The ERROR screen's words ([`crate::ui::refusal`]), with a second line
    /// for the review and the reply where a person can act on it.
    pub fn words(self) -> refusal::Words {
        match self {
            Refusal::NotRecognised => refusal::NOT_RECOGNISED,
            Refusal::NotARequest => refusal::NOT_A_REQUEST,
            Refusal::NotATransaction => refusal::NOT_A_TRANSACTION,
            Refusal::NotReviewable(e) => (refusal::NOT_REVIEWABLE, not_reviewable(e)),
            Refusal::Unshown(u) => (refusal::NOT_REVIEWABLE, u.words()),
            Refusal::CardLocked(why) => (refusal::CARD_LOCKED, why.words()),
            Refusal::NotDrawn => (refusal::NOT_REVIEWABLE, ""),
            Refusal::NotSigned(e) => (refusal::NOT_SIGNED, not_signed(e)),
            Refusal::NotTheGroups => (refusal::NOT_SIGNED, refusal::NOT_THE_GROUPS),
            Refusal::NotVerified(_) => refusal::NOT_VERIFIED,
            Refusal::RequestChanged => refusal::REQUEST_CHANGED,
            Refusal::NotASeed => refusal::NOT_A_SEED,
            Refusal::NotAKpub => refusal::NOT_A_KPUB,
            Refusal::KeyAdded => refusal::KEY_ADDED,
            Refusal::GroupNotMade => refusal::GROUP_NOT_MADE,
            Refusal::NotADescriptor => refusal::NOT_A_DESCRIPTOR,
            Refusal::CardBackup(e) => (refusal::CARD_BACKUP, card_backup(e)),
            Refusal::NoCosignerKey => refusal::NO_COSIGNER_KEY,
            Refusal::NoKcc3Key => refusal::NO_KCC3_KEY,
            Refusal::NotAKey => refusal::NOT_A_KEY,
            Refusal::NotText => refusal::NOT_TEXT,
            Refusal::TrailingWhitespace => refusal::TRAILING_WHITESPACE,
            Refusal::NotMainnet => refusal::NOT_MAINNET,
            Refusal::SeedNotMessage => refusal::SEED_NOT_MESSAGE,
            Refusal::PlainText => refusal::PLAIN_TEXT,
            Refusal::NoPhrase => refusal::NO_PHRASE,
            Refusal::NoWallet => refusal::NO_WALLET,
            Refusal::NotBackedUp => refusal::NOT_BACKED_UP,
            Refusal::NotOpened => refusal::NOT_OPENED,
            Refusal::SlotsFull => refusal::SLOTS_FULL,
            Refusal::NoEntropy => refusal::NO_ENTROPY,
            Refusal::Declined => refusal::DECLINED,
            Refusal::NotSaved => refusal::NOT_SAVED,
            Refusal::Stego(e) => match e {
                StegoError::NotJpeg => refusal::NOT_A_JPEG,
                StegoError::Progressive => refusal::PROGRESSIVE_JPEG,
                StegoError::TooSmall => refusal::PHOTO_TOO_SMALL,
                StegoError::TooLarge | StegoError::Bounds => refusal::PHOTO_TOO_LARGE,
                StegoError::Damaged => refusal::PHOTO_DAMAGED,
                StegoError::Exif => refusal::EXIF_FAILED,
                StegoError::Verify => refusal::VERIFY_FAILED,
            },
            Refusal::NoBackup => refusal::NO_BACKUP,
            Refusal::WrongDescriptor => refusal::WRONG_DESCRIPTOR,
            Refusal::UnknownFormat => refusal::UNKNOWN_FORMAT,
            Refusal::NotDerived => refusal::NOT_DERIVED,
            Refusal::TooLong => refusal::TOO_LONG,
            Refusal::MessageNotSigned => refusal::MESSAGE_NOT_SIGNED,
            Refusal::NoCamera => refusal::NO_CAMERA,
        }
    }
}

/// Why a card's backup line was not taken: the ERROR screen's second line
/// for one scanned, the reason under Card Load Failed for one from a file.
pub(super) const fn card_backup(e: CardBackupError) -> &'static str {
    match e {
        CardBackupError::NotABackup | CardBackupError::BufferTooSmall => refusal::BACKUP_NOT_ONE,
        CardBackupError::Malformed => refusal::BACKUP_MALFORMED,
        CardBackupError::BadKey => refusal::BACKUP_BAD_KEY,
        CardBackupError::BadDate => refusal::BACKUP_BAD_DATE,
        CardBackupError::BadAddress => refusal::BACKUP_BAD_ADDRESS,
        CardBackupError::NotTheCard => refusal::BACKUP_NOT_THE_CARD,
        CardBackupError::NotCanonical => refusal::BACKUP_NOT_CANONICAL,
    }
}

/// A page the review does not draw yet: a request with one is refused
/// before any page is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unshown {
    /// A payload.
    Payload,
    /// An input of ours under a redeem script that is not a multisig: the
    /// signature agrees to a script no page shows.
    Script,
    /// An input whose sequence is a relative lock: the signature covers
    /// it, and no page shows one yet.
    RelativeLock,
}

impl Unshown {
    /// The ERROR screen's second line.
    pub const fn words(self) -> &'static str {
        match self {
            Unshown::Payload => refusal::PAYLOAD_UNSHOWN,
            Unshown::Script => refusal::SCRIPT_UNSHOWN,
            Unshown::RelativeLock => refusal::RELATIVE_UNSHOWN,
        }
    }
}

/// Why a Time-Locked Savings card stays locked to a transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardLock {
    /// Its lock time is before the card's time, or none, or a DAA score.
    Early,
    /// The card's input is final, which turns the lock time off.
    Final,
}

impl CardLock {
    /// The ERROR screen's second line.
    pub const fn words(self) -> &'static str {
        match self {
            CardLock::Early => refusal::CARD_EARLY,
            CardLock::Final => refusal::CARD_FINAL,
        }
    }
}

/// A plan's refusal as a person is told it: a script the review cannot show
/// or a relative lock as a missing page ("Cannot review"); a card its
/// program would not open as still locked; anything else as the reply's.
pub(super) fn planned(e: reply::Error) -> Refusal {
    match e {
        reply::Error::Keyring {
            error: keyring::Error::ScriptUnshown,
            ..
        } => Refusal::Unshown(Unshown::Script),
        reply::Error::Sequence { .. } => Refusal::Unshown(Unshown::RelativeLock),
        reply::Error::CardEarly { .. } => Refusal::CardLocked(CardLock::Early),
        reply::Error::CardFinal { .. } => Refusal::CardLocked(CardLock::Final),
        e => Refusal::NotSigned(e),
    }
}

/// [`Flow::unchanged`]'s comparison of `bytes` with the SHA-256 `taken` as
/// a review started: `RequestChanged` if they differ or none was taken.
pub(super) fn unchanged(
    taken: Option<[u8; frame::SHA256_LEN]>,
    bytes: &[u8],
) -> Result<(), Refusal> {
    match taken {
        Some(taken) if taken == frame::sha256(bytes) => Ok(()),
        _ => Err(Refusal::RequestChanged),
    }
}

/// Why a transaction cannot be reviewed, where a person can tell.
pub(super) fn not_reviewable(e: session::Error) -> &'static str {
    use crate::review::Error as R;
    match e {
        session::Error::Review(R::TooManyPages { .. }) => refusal::TOO_MANY_PAGES,
        session::Error::Review(R::ValueOverflow)
        | session::Error::Consensus(TxRuleError::SpendTooHigh(..)) => refusal::VALUE_OVERFLOW,
        session::Error::Review(R::NonNativeSubnetwork) => refusal::NOT_NATIVE,
        session::Error::Review(R::GasNotZero { .. }) => refusal::GAS,
        session::Error::Review(R::StorageMass { .. }) => refusal::STORAGE_MASS,
        session::Error::Consensus(TxRuleError::UnknownTxVersion(_)) => refusal::TX_VERSION,
        session::Error::Consensus(TxRuleError::AuthInputOutOfBounds(..)) => refusal::COVENANT_INPUT,
        session::Error::NoOutputs => refusal::NO_OUTPUTS,
        session::Error::Consensus(TxRuleError::TxOutZero(_)) => refusal::ZERO_OUTPUT,
        session::Error::Consensus(TxRuleError::TxDuplicateInputs) => refusal::DUPLICATE_INPUT,
        session::Error::Consensus(
            TxRuleError::TxOutTooHigh(_)
            | TxRuleError::OutputsValueOverflow
            | TxRuleError::TotalTxOutTooHigh
            | TxRuleError::InputAmountOverflow
            | TxRuleError::InputAmountTooHigh,
        ) => refusal::ABOVE_SUPPLY,
        session::Error::Consensus(_) => refusal::CONSENSUS,
        session::Error::NonStandard(NonStandardError::RejectScriptPublicKeyVersion(_)) => {
            refusal::SCRIPT_VERSION
        }
        session::Error::NonStandard(NonStandardError::RejectOutputScriptClass(_)) => {
            refusal::NON_STANDARD_OUTPUT
        }
        _ => "",
    }
}

/// Why a reply was not signed, where a person can tell.
pub(super) fn not_signed(e: reply::Error) -> &'static str {
    match e {
        reply::Error::NothingSigned => refusal::NOTHING_SIGNED,
        reply::Error::NotEveryInput { .. } => refusal::NOT_EVERY_INPUT,
        reply::Error::InputUnsigned { .. } => refusal::INPUT_UNSIGNED,
        reply::Error::TooLargeToShow { .. } => refusal::TOO_LARGE,
        reply::Error::NotOneTransaction { .. } => refusal::NOT_ONE_TRANSACTION,
        reply::Error::SighashNotAll { .. } => refusal::SIGHASH_NOT_ALL,
        reply::Error::Sequence { .. } => refusal::RELATIVE_UNSHOWN,
        reply::Error::CardEarly { .. } => refusal::CARD_EARLY,
        reply::Error::CardFinal { .. } => refusal::CARD_FINAL,
        reply::Error::AlreadySigned { .. } => refusal::ALREADY_SIGNED,
        reply::Error::BadSignature { .. } => refusal::BAD_SIGNATURE,
        reply::Error::TooFewSigOps { .. } => refusal::MULTISIG_OP_COUNT,
        reply::Error::NoSigOp { .. } => refusal::OP_COUNT,
        reply::Error::Keyring { error, .. } => match error {
            keyring::Error::UnsupportedMultisig { required: 0, .. } => {
                refusal::MULTISIG_NO_THRESHOLD
            }
            keyring::Error::UnsupportedMultisig { .. } => refusal::MULTISIG_TOO_MANY_KEYS,
            keyring::Error::RepeatedKey { .. } => refusal::MULTISIG_REPEATED_KEY,
            keyring::Error::RedeemMismatch => refusal::REDEEM_MISMATCH,
            keyring::Error::NoRedeemScript => refusal::NO_REDEEM_SCRIPT,
            keyring::Error::Wallet(_) | keyring::Error::KeyMismatch => refusal::NOT_DERIVED.0,
            keyring::Error::ScriptUnshown => refusal::SCRIPT_UNSHOWN,
        },
        reply::Error::Session(session::Error::NoEntropy(_)) => refusal::NO_ENTROPY.0,
        reply::Error::Session(e) => not_reviewable(e),
        _ => "",
    }
}
