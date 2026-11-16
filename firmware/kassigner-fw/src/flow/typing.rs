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

//! What a keyboard types and its limits; what the word and count screens
//! serve.

use super::*;

/// What the keyboard is typing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Typing {
    /// A seed's BIP39 passphrase.
    Passphrase,
    /// The same passphrase again.
    PassphraseAgain,
    /// A backup's file name: letters and digits, eight at most.
    FileName,
    /// A kpub's file name.
    KpubFileName,
    /// A signature's file name.
    SigFileName,
    /// Sign Message's text.
    Message,
    /// A backup's password.
    Password,
    /// The same password again.
    PasswordAgain,
    /// A backup's password, to delete it: titled apart from a restore's,
    /// which looks the same.
    DeletePassword,
    /// The password of a sealed file a save would overwrite (the new file's
    /// is asked after).
    OverwritePassword,
    /// Import Raw Key's private key, in hex.
    RawKey,
    /// Steganography's image descriptor, the password, with no strength
    /// rule: at most 64 characters to hide a backup, 128 to open one.
    Descriptor,
    /// Steganography's recovery hint, at most 64 characters.
    Hint,
    /// The descriptor of a backup a photo holds, to overwrite it.
    OldDescriptor,
}

/// Characters in a backup's file name: 8.3's eight.
pub const NAME_MAX: usize = 8;

/// Hex characters in a private key: two per byte.
pub const RAW_KEY_HEX: usize = 2 * PRIVATE_KEY_SIZE;

/// Digits the Address keypad takes, up to 99,999: summed in 32 bits, as 16
/// would wrap above 65,535.
pub const INDEX_DIGITS: usize = 5;

/// Which word tool is typing words.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordsFor {
    /// Import Words: the whole phrase, checked.
    Import,
    /// Calc Last Word: all but the last, which the unit works out.
    LastWord,
}

/// Which Seed Tools row the 12-or-24 screen is choosing for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CountFor {
    /// A tool that types words.
    Words(WordsFor),
    /// Dice Seed: the count picks how many rolls.
    Dice,
    /// BIP85 Child: the count picks the child's length.
    Bip85,
}

impl CountFor {
    /// The count screen's title, the Seed Tools row's name.
    pub const fn title(self) -> &'static str {
        match self {
            CountFor::Words(WordsFor::Import) => "IMPORT WORDS",
            CountFor::Words(WordsFor::LastWord) => "CALC LAST WORD",
            CountFor::Dice => "DICE SEED",
            CountFor::Bip85 => "BIP85 CHILD",
        }
    }
}

impl WordsFor {
    /// The word screen's title, before the word's place.
    pub const fn heading(self) -> &'static str {
        match self {
            WordsFor::Import => "IMPORT",
            WordsFor::LastWord => "CALC LAST",
        }
    }
}

impl Typing {
    /// Which keys type for it, with `len` characters typed.
    pub const fn mode(self, len: usize) -> keyboard::Mode {
        match self {
            Typing::FileName | Typing::KpubFileName | Typing::SigFileName => keyboard::Mode::Name {
                full: len >= NAME_MAX,
            },
            Typing::RawKey => keyboard::Mode::Hex {
                full: len >= RAW_KEY_HEX,
            },
            _ => keyboard::Mode::Text,
        }
    }

    /// The keyboard screen's title for it.
    pub const fn title(self) -> &'static str {
        match self {
            Typing::Passphrase => "PASSPHRASE",
            Typing::PassphraseAgain => "PASSPHRASE AGAIN",
            Typing::FileName => "FILENAME",
            Typing::KpubFileName => "KPUB FILENAME",
            Typing::SigFileName => "SIG FILENAME",
            Typing::Message => "MESSAGE",
            Typing::Password => "PASSWORD",
            Typing::PasswordAgain => "PASSWORD AGAIN",
            Typing::DeletePassword => "PASSWORD (DELETE)",
            Typing::OverwritePassword => "PASSWORD (OVERWRITE)",
            Typing::RawKey => "IMPORT KEY",
            Typing::Descriptor => "IMAGE DESCRIPTOR",
            Typing::Hint => "CUSTOM HINT",
            Typing::OldDescriptor => "OLD DESCRIPTOR",
        }
    }

    /// Whether what is typed is a secret: anything but a file name or a
    /// message.
    pub const fn secret(self) -> bool {
        match self {
            Typing::Passphrase
            | Typing::PassphraseAgain
            | Typing::Password
            | Typing::PasswordAgain
            | Typing::DeletePassword
            | Typing::OverwritePassword
            | Typing::RawKey
            | Typing::Descriptor
            | Typing::Hint
            | Typing::OldDescriptor => true,
            Typing::FileName | Typing::KpubFileName | Typing::SigFileName | Typing::Message => {
                false
            }
        }
    }
}
