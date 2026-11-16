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

//! The card in the slot: whether one answers, a read and write test, the
//! format, and the files the unit saves, lists, reads and deletes.
//!
//! Each board opens a session on its card its own way; what is done inside
//! is the same on all three, so it is here, written against
//! `kassigner_fat32::block::BlockDevice` and tested on the host. The binary
//! opens the session, calls [`run`] inside it and reports the [`Outcome`];
//! a session that would not start is [`Outcome::Absent`].

use kassigner_fat32::block::{self, BlockDevice};
use kassigner_fat32::fat32::{self, Fat32Error};

/// What kind of card answered, as the boards' drivers return it.
pub use kassigner_hal::card::Kind;

/// What the SD Card screen knows of the slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    /// Being looked at.
    Checking,
    /// Nothing answered.
    Absent,
    /// A card answered.
    Present(Kind),
}

/// What a session is opened for. A list's names go into
/// [`Request::names`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Job {
    /// Whether a card answers, and what kind.
    Probe,
    /// The read and write test ([`test()`]).
    Test,
    /// Format the card FAT32.
    Format,
    /// The next free name of [`Request::name`]'s form ([`next_name`]).
    NextName,
    /// Whether [`Request::name`] is already in the root.
    Exists,
    /// Write [`Request::file`]'s first [`Request::len`] bytes as
    /// [`Request::name`] ([`write()`]).
    Write,
    /// Text files of [`Request::name`]'s extension ([`list_text`]).
    ListText,
    /// The photos no larger than [`Request::file`] ([`list_photos`]), their
    /// long names into [`Request::long`].
    ListPhotos,
    /// The backups, or with a `.TXT` name the kpub files ([`list`]); a
    /// backup of a derivation this firmware does not know is listed, so it
    /// says so when tapped.
    List,
    /// The multisig descriptors, each read into [`Request::file`]
    /// ([`list_groups`]).
    ListGroups,
    /// The multisig addresses named as [`Request::name`] is
    /// ([`list_addresses`]).
    ListAddresses,
    /// The covenant cards' backups named as [`Request::name`] is
    /// ([`list_cards`]).
    ListCards,
    /// Read [`Request::name`] into [`Request::file`].
    Read,
    /// Delete [`Request::name`] from the root.
    Delete,
}

/// What a job that names, writes, reads or lists files works with: the
/// flow holds it, the binary hands it to the session.
#[derive(Debug)]
pub struct Request<'r> {
    /// The file, 8.3 as it sits in the root.
    pub name: [u8; 11],
    /// What [`Job::Write`] writes, [`Request::len`] of it, and where
    /// [`Job::Read`] reads to.
    pub file: &'r mut [u8],
    pub len: usize,
    /// Where a list's names go.
    pub names: &'r mut [[u8; 11]],
    /// Each listed photo's name as a computer shows it, [`LONG_SLOT`] bytes
    /// each, in the order of [`Request::names`]; empty for every other job.
    pub long: &'r mut [u8],
}

/// Bytes a photo's long name takes: its length, then up to
/// [`fat32::MAX_LONG_NAME`] characters.
pub const LONG_SLOT: usize = 1 + fat32::MAX_LONG_NAME;

/// The `i`th photo's long name in `long`; `None` past what it holds.
pub fn long_name(long: &[u8], i: usize) -> Option<&str> {
    let slot = long.get(i * LONG_SLOT..(i + 1) * LONG_SLOT)?;
    let n = usize::from(slot[0]).min(fat32::MAX_LONG_NAME);
    core::str::from_utf8(&slot[1..1 + n])
        .ok()
        .filter(|s| !s.is_empty())
}

/// A backup file's extension, as v1.0.7 also writes it.
pub const BACKUP_EXT: [u8; 3] = *b"KAS";

/// A cosigner's kpub file's extension (`KMnnnn.K45`), its own so a unit
/// finds them whatever they are named; the content says it again
/// ([`crate::kpub::read_cosigner`]).
pub const COSIGNER_EXT: [u8; 3] = *b"K45";

/// `base`'s first eight letters and digits (anything else left out) as an
/// 8.3 name with `ext`: upper case, padded with spaces, as the root holds it.
pub fn name83(base: &[u8], ext: &[u8; 3]) -> [u8; 11] {
    let mut out = [b' '; 11];
    for (n, &c) in base
        .iter()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(8)
        .enumerate()
    {
        out[n] = c.to_ascii_uppercase();
    }
    out[8..].copy_from_slice(ext);
    out
}

/// A file's 8.3 name on a screen, printed as `SD0001.KAS`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FileName(pub [u8; 11]);

impl core::fmt::Debug for FileName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut shown = [0u8; 12];
        let n = shown_name(&self.0, &mut shown);
        f.write_str(core::str::from_utf8(&shown[..n]).unwrap_or("?"))
    }
}

/// An 8.3 name as a person reads it, `NAME.KAS`, into `out`; its length.
pub fn shown_name(name: &[u8; 11], out: &mut [u8; 12]) -> usize {
    let mut n = 0;
    for &c in name[..8].iter().filter(|&&c| c != b' ') {
        out[n] = c;
        n += 1;
    }
    out[n] = b'.';
    n += 1;
    for &c in name[8..].iter().filter(|&&c| c != b' ') {
        out[n] = c;
        n += 1;
    }
    n
}

/// The number in a name of `pattern`'s form (two letters, four digits, the
/// extension): for `SD` and `KAS`, `SD0042  KAS` is 42.
fn numbered(name: &[u8; 11], pattern: &[u8; 11]) -> Option<u16> {
    if name[..2] != pattern[..2] || name[8..] != pattern[8..] || &name[6..8] != b"  " {
        return None;
    }
    name[2..6].iter().try_fold(0u16, |n, &c| {
        c.is_ascii_digit().then(|| n * 10 + u16::from(c - b'0'))
    })
}

/// What a job came to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// No card answered: the session would not start.
    Absent,
    /// A card answered.
    Present(Kind),
    /// The test file was written, read back and matched: its bytes, and the
    /// root's entries with it there.
    Tested { bytes: usize, files: u32 },
    /// The card was formatted and mounts.
    Formatted,
    /// The next free backup number.
    NextName(u16),
    /// Whether the file is there.
    Exists(bool),
    /// The file was written.
    Written,
    /// Files listed, and how many more of the kind did not fit.
    Listed { count: u8, extra: u16 },
    /// The file was read: its length.
    Read(usize),
    /// The file was deleted.
    Deleted,
    /// The job failed, and why.
    Failed(Error),
}

impl Outcome {
    /// Whether the job did what it was for.
    pub const fn ok(self) -> bool {
        matches!(
            self,
            Outcome::Present(_)
                | Outcome::Tested { .. }
                | Outcome::Formatted
                | Outcome::NextName(_)
                | Outcome::Exists(_)
                | Outcome::Written
                | Outcome::Listed { .. }
                | Outcome::Read(_)
                | Outcome::Deleted
        )
    }
}

/// Why a test or a format failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The card failed: gone, or a transfer that did not complete.
    Device(block::Error),
    /// The filesystem's own words, naming the field that disagreed.
    Filesystem(&'static str),
    /// The test file's directory entry has the wrong size.
    Size,
    /// Reading the test file back gave the wrong number of bytes.
    ReadBack,
    /// Reading it back gave other bytes than were written.
    Data,
    /// A backup that could not be listed, read or opened, as the screen
    /// says it.
    Backup(&'static str),
}

/// A failure's line when no card answered, whatever the job.
pub const NO_CARD: &str = "No SD card";

impl Error {
    /// The line the screen says it with.
    pub const fn describe(self) -> &'static str {
        match self {
            Error::Device(block::Error::NotPresent) => NO_CARD,
            Error::Device(block::Error::OutOfRange { .. }) => "Past the end of the card",
            Error::Device(block::Error::Unaligned { .. }) => "Unaligned transfer",
            Error::Device(block::Error::Io) => "Card error",
            Error::Filesystem(why) => why,
            Error::Size => "Size mismatch",
            Error::ReadBack => "Read size mismatch",
            Error::Data => "Data mismatch",
            Error::Backup(why) => why,
        }
    }
}

impl From<Fat32Error> for Error {
    fn from(e: Fat32Error) -> Self {
        match e {
            Fat32Error::Device(d) => Error::Device(d),
            Fat32Error::Format(why) => Error::Filesystem(why),
        }
    }
}

impl From<block::Error> for Error {
    fn from(e: block::Error) -> Self {
        Error::Device(e)
    }
}

/// The test file's name, `TEST.TXT`, 8.3 as it sits in the root.
pub const TEST_NAME: [u8; 11] = *b"TEST    TXT";

/// What the test writes: 34 bytes.
pub const TEST_DATA: &[u8] = b"KasSigner SD test 1234567890ABCDEF";

/// A card that says it is alive: `alive` is called before every transfer.
///
/// For the binary's watchdog: a job can outrun its timeout (formatting a
/// 32 GB card on the M5 takes 35.6 s, a 64 GB one twice that). A job still
/// moving blocks is not hung; one that stops calling `alive` lets the
/// watchdog reset the unit, as for a hung loop. A transfer of several
/// blocks is one call.
pub struct Alive<'a, D> {
    dev: &'a mut D,
    alive: &'a mut dyn FnMut(),
}

impl<'a, D: BlockDevice> Alive<'a, D> {
    /// `dev`, calling `alive` on every transfer.
    pub fn new(dev: &'a mut D, alive: &'a mut dyn FnMut()) -> Self {
        Self { dev, alive }
    }
}

impl<D: BlockDevice> BlockDevice for Alive<'_, D> {
    fn blocks(&self) -> u32 {
        self.dev.blocks()
    }

    fn read(&mut self, at: u32, buf: &mut [u8; block::BLOCK_SIZE]) -> Result<(), block::Error> {
        (self.alive)();
        self.dev.read(at, buf)
    }

    fn write(&mut self, at: u32, data: &[u8; block::BLOCK_SIZE]) -> Result<(), block::Error> {
        (self.alive)();
        self.dev.write(at, data)
    }

    fn read_many(&mut self, at: u32, out: &mut [u8]) -> Result<(), block::Error> {
        (self.alive)();
        self.dev.read_many(at, out)
    }

    fn write_many(&mut self, at: u32, data: &[u8]) -> Result<(), block::Error> {
        (self.alive)();
        self.dev.write_many(at, data)
    }
}

/// Do `job` on the card a session has open; `kind` is what the board found.
pub fn run<D: BlockDevice>(
    job: Job,
    kind: Kind,
    dev: &mut D,
    request: &mut Request<'_>,
) -> Outcome {
    let failed = |e: Error| Outcome::Failed(e);
    let listed = |(count, extra): (usize, u16)| Outcome::Listed {
        count: u8::try_from(count).unwrap_or(u8::MAX),
        extra,
    };
    match job {
        Job::NextName => next_name(dev, &request.name).map_or_else(failed, Outcome::NextName),
        Job::Exists => exists(dev, &request.name).map_or_else(failed, Outcome::Exists),
        Job::Write => write(dev, &request.name, &request.file[..request.len])
            .map_or_else(failed, |()| Outcome::Written),
        Job::ListText => list_text(dev, &request.name, request.file.len(), request.names)
            .map_or_else(failed, listed),
        Job::ListPhotos => list_photos(dev, request.file.len(), request.names, request.long)
            .map_or_else(failed, listed),
        Job::List => list(dev, &request.name, request.names).map_or_else(failed, listed),
        Job::ListGroups => {
            list_groups(dev, request.file, request.names).map_or_else(failed, listed)
        }
        Job::ListAddresses => {
            list_addresses(dev, &request.name, request.names).map_or_else(failed, listed)
        }
        Job::ListCards => list_cards(dev, &request.name, request.names).map_or_else(failed, listed),
        Job::Read => read(dev, &request.name, request.file).map_or_else(failed, Outcome::Read),
        Job::Delete => delete(dev, &request.name).map_or_else(failed, |()| Outcome::Deleted),
        Job::Probe => Outcome::Present(kind),
        Job::Test => match test(dev) {
            Ok((bytes, files)) => Outcome::Tested { bytes, files },
            Err(e) => Outcome::Failed(e),
        },
        Job::Format => match format(dev) {
            Ok(()) => Outcome::Formatted,
            Err(e) => Outcome::Failed(e),
        },
    }
}

/// The test: write `TEST.TXT`, find it, read it back, compare, count the
/// root's entries, delete it; the bytes read and the entries counted. A
/// `TEST.TXT` already there is replaced (`overwrite_file` goes on only once
/// it is gone), never doubled.
///
/// # Errors
///
/// The step that failed; nothing after it runs, and a file already written
/// is left on the card.
pub fn test<D: BlockDevice>(dev: &mut D) -> Result<(usize, u32), Error> {
    let info = fat32::mount_fat32(dev)?;
    fat32::overwrite_file(dev, &info, &TEST_NAME, TEST_DATA)?;
    let (entry, _, _) = fat32::find_file_in_root(dev, &info, &TEST_NAME)?;
    if entry.file_size as usize != TEST_DATA.len() {
        return Err(Error::Size);
    }
    let mut back = [0u8; block::BLOCK_SIZE];
    let read = fat32::read_file(dev, &info, &entry, &mut back)?;
    if read != TEST_DATA.len() {
        return Err(Error::ReadBack);
    }
    if &back[..read] != TEST_DATA {
        return Err(Error::Data);
    }
    let mut files = 0u32;
    fat32::list_root_dir(dev, &info, |_| {
        files = files.saturating_add(1);
        true
    })?;
    fat32::delete_file(dev, &info, &TEST_NAME)?;
    Ok((read, files))
}

/// One past the highest number in the root of `pattern`'s form (its two
/// letters and extension: `SDnnnn.KAS`, `KPnnnn.TXT`), from 1, so numbering
/// goes on past files v1.0.7 wrote.
///
/// # Errors
///
/// A card that does not mount or read.
pub fn next_name<D: BlockDevice>(dev: &mut D, pattern: &[u8; 11]) -> Result<u16, Error> {
    let info = fat32::mount_fat32(dev)?;
    let mut high = 0u16;
    fat32::list_root_dir(dev, &info, |entry| {
        if let Some(n) = numbered(&entry.name, pattern) {
            high = high.max(n);
        }
        true
    })?;
    Ok(high.saturating_add(1).min(9999))
}

/// Whether `name` is in the root.
///
/// # Errors
///
/// A card that does not mount or read.
pub fn exists<D: BlockDevice>(dev: &mut D, name: &[u8; 11]) -> Result<bool, Error> {
    let info = fat32::mount_fat32(dev)?;
    match fat32::find_file_in_root(dev, &info, name) {
        Ok(_) => Ok(true),
        Err(Fat32Error::Format("File not found")) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Write `data` as `name`, replacing a file of that name, then read it back
/// and compare: a card that keeps other bytes (worn or counterfeit) is
/// caught at the save, not when the backup is needed. Every save comes here.
///
/// # Errors
///
/// As the filesystem says; [`Error::Data`] for a file that reads back other
/// bytes or another size, which is left on the card as written.
pub fn write<D: BlockDevice>(dev: &mut D, name: &[u8; 11], data: &[u8]) -> Result<(), Error> {
    let info = fat32::mount_fat32(dev)?;
    fat32::overwrite_file(dev, &info, name, data)?;
    let (entry, _, _) = fat32::find_file_in_root(dev, &info, name)?;
    if !fat32::file_holds(dev, &info, &entry, data)? {
        return Err(Error::Data);
    }
    Ok(())
}

/// Text files of `pattern`'s extension, 1 to `max` bytes (the buffer they
/// are read into), into `names`: `.TXT` for Sign Message, `.KSP` for Import
/// from SD (`TXnnnn.KSP`, as a unit saves a signed one). Their content is
/// checked when read. Returns the count listed and the count over.
///
/// # Errors
///
/// A card that does not mount or read.
pub fn list_text<D: BlockDevice>(
    dev: &mut D,
    pattern: &[u8; 11],
    max: usize,
    names: &mut [[u8; 11]],
) -> Result<(usize, u16), Error> {
    let info = fat32::mount_fat32(dev)?;
    let (mut found, mut extra) = (0usize, 0u16);
    fat32::list_root_dir(dev, &info, |entry| {
        let size = entry.file_size as usize;
        if entry.name[8..] == pattern[8..] && size > 0 && size <= max {
            if found < names.len() {
                names[found] = entry.name;
                found += 1;
            } else {
                extra = extra.saturating_add(1);
            }
        }
        true
    })?;
    Ok((found, extra))
}

/// The backups, into `names`: `.KAS` files of one block at most whose
/// header says seed or xprv, or names a derivation this firmware does not
/// know. With `pattern`'s extension `TXT`, the kpub files instead (a kpub's
/// text, or sealed under the KSPT purpose) and the cosigners' `.K45` files;
/// with `K45`, those alone. A `.K45` file is listed whatever it holds, and
/// refused by name when opened if it is not a cosigner's kpub.
///
/// Each candidate is looked into as the walk reaches it, so files that are
/// not backups cannot crowd the real ones off the list. The walk keeps its
/// place across those reads ([`fat32::RootCursor`]), so the root is walked
/// once: restarting it every few candidates takes hours on a full root.
/// Returns the count listed and how many more did not fit.
///
/// # Errors
///
/// A card that does not mount or read.
pub fn list<D: BlockDevice>(
    dev: &mut D,
    pattern: &[u8; 11],
    names: &mut [[u8; 11]],
) -> Result<(usize, u16), Error> {
    use kassigner_crypto::backup::{backup_kdf, BackupError};
    use kassigner_crypto::container::OpenError;
    use kassigner_protocol::container::{parse, ContainerError, Purpose};

    let ext = &pattern[8..];
    let wanted = |head: &[u8]| -> bool {
        if *ext == BACKUP_EXT {
            match backup_kdf(head) {
                Ok(_) => true,
                Err(BackupError::Container(OpenError::Framing(
                    ContainerError::UnsupportedKdf(_),
                ))) => true,
                Err(_) => false,
            }
        } else {
            // A kpub's file: its text, or sealed under the KSPT purpose as
            // v1.0.7 sealed one (which says nothing more until opened).
            crate::kpub::read(head).is_some()
                || matches!(parse(head), Ok(c) if c.purpose == Purpose::Kspt)
                || matches!(parse(head), Err(ContainerError::UnsupportedKdf(_)))
        }
    };

    kept(dev, names, |dev, info, entry| {
        let cosigner = entry.name[8..] == COSIGNER_EXT;
        let kind = entry.name[8..] == *ext || (cosigner && *ext == *b"TXT");
        if !kind || entry.file_size as usize > block::BLOCK_SIZE {
            return false;
        }
        if cosigner {
            return true;
        }
        let mut head = [0u8; block::BLOCK_SIZE];
        fat32::read_file(dev, info, entry, &mut head).is_ok_and(|len| wanted(&head[..len]))
    })
}

/// The `.JPG` and `.JPE` files of 1 to `max` bytes (the photo buffer, so
/// none is offered that the unit cannot hold): their 8.3 names into `names`,
/// and beside each, while `long` has room, the name a computer shows: its
/// long name where the card holds all of it, else `NAME.EXT`
/// ([`fat32::list_root_dir_lfn`]).
///
/// # Errors
///
/// A card that does not mount or read.
pub fn list_photos<D: BlockDevice>(
    dev: &mut D,
    max: usize,
    names: &mut [[u8; 11]],
    long: &mut [u8],
) -> Result<(usize, u16), Error> {
    let info = fat32::mount_fat32(dev)?;
    let (mut found, mut extra) = (0usize, 0u16);
    fat32::list_root_dir_lfn(dev, &info, |entry, shown, len| {
        let size = entry.file_size as usize;
        let photo = entry.name[8..] == *b"JPG" || entry.name[8..] == *b"JPE";
        if !photo || size == 0 || size > max {
            return true;
        }
        if found < names.len() {
            names[found] = entry.name;
            if let Some(slot) = long.get_mut(found * LONG_SLOT..(found + 1) * LONG_SLOT) {
                let n = len.min(fat32::MAX_LONG_NAME);
                slot[0] = n as u8;
                slot[1..1 + n].copy_from_slice(&shown[..n]);
            }
            found += 1;
        } else {
            extra = extra.saturating_add(1);
        }
        true
    })?;
    Ok((found, extra))
}

/// The multisig descriptors, into `names`: `.TXT` files read whole into
/// `scratch`, holding a descriptor's text (with or without the `#` line
/// v1.0.7 and this firmware write over it) or sealed under the descriptor's
/// purpose. Only the text's form is checked; a descriptor of more keys than
/// a unit holds is not listed. `scratch` is wiped after, having held any
/// text file.
///
/// # Errors
///
/// A card that does not mount or read.
pub fn list_groups<D: BlockDevice>(
    dev: &mut D,
    scratch: &mut [u8],
    names: &mut [[u8; 11]],
) -> Result<(usize, u16), Error> {
    use kassigner_protocol::container::{parse, Purpose};
    use kassigner_protocol::descriptor;

    let found = kept(dev, names, |dev, info, entry| {
        let size = entry.file_size as usize;
        if entry.name[8..] != *b"TXT" || size == 0 || size > scratch.len() {
            return false;
        }
        let Ok(len) = fat32::read_file(dev, info, entry, scratch) else {
            return false;
        };
        let file = &scratch[..len];
        let mut keys = [""; crate::limits::MAX_MULTISIG_KEYS];
        matches!(parse(file), Ok(c) if c.purpose == Purpose::Descriptor)
            || core::str::from_utf8(file).is_ok_and(|t| descriptor::parse(t, &mut keys).is_ok())
    });
    crate::wipe::wipe(scratch);
    found
}

/// The multisig addresses, into `names`: files of `pattern`'s two letters
/// and extension (`MSnnnn.TXT`) holding a multisig (script-hash) address on
/// Kaspa's main network, or sealed as text and checked when opened.
///
/// # Errors
///
/// A card that does not mount or read.
pub fn list_addresses<D: BlockDevice>(
    dev: &mut D,
    pattern: &[u8; 11],
    names: &mut [[u8; 11]],
) -> Result<(usize, u16), Error> {
    use kassigner_kaspa::address::{Prefix, Version};

    // The shared rule for a network's address, as when the file opens.
    named_text(dev, pattern, names, |text| {
        let mut payload = [0u8; 33];
        matches!(
            crate::checks::decode_expecting(Prefix::Mainnet, text.trim_ascii(), &mut payload),
            Ok((Version::ScriptHash, _))
        )
    })
}

/// The covenant cards' backups, into `names`: files of `pattern`'s two
/// letters and extension (`CVnnnn.TXT`) holding a backup line, or sealed as
/// text and checked when opened.
///
/// # Errors
///
/// A card that does not mount or read.
pub fn list_cards<D: BlockDevice>(
    dev: &mut D,
    pattern: &[u8; 11],
    names: &mut [[u8; 11]],
) -> Result<(usize, u16), Error> {
    named_text(dev, pattern, names, |text| {
        kassigner_protocol::card::backup::read(text).is_ok()
    })
}

/// Files of `pattern`'s two letters and extension, one block at most, whose
/// text `is_one` takes or that are sealed as text.
///
/// # Errors
///
/// A card that does not mount or read.
fn named_text<D: BlockDevice>(
    dev: &mut D,
    pattern: &[u8; 11],
    names: &mut [[u8; 11]],
    is_one: impl Fn(&[u8]) -> bool,
) -> Result<(usize, u16), Error> {
    use kassigner_protocol::container::{parse, Purpose};

    kept(dev, names, |dev, info, entry| {
        let size = entry.file_size as usize;
        if entry.name[..2] != pattern[..2]
            || entry.name[8..] != pattern[8..]
            || size == 0
            || size > block::BLOCK_SIZE
        {
            return false;
        }
        let mut head = [0u8; block::BLOCK_SIZE];
        let Ok(len) = fat32::read_file(dev, info, entry, &mut head) else {
            return false;
        };
        let file = &head[..len];
        matches!(parse(file), Ok(c) if c.purpose == Purpose::Text) || is_one(file)
    })
}

/// The root's files `keep` takes, walked once in directory order, into
/// `names`: the count listed and the count over. `keep` may read the file;
/// the walk keeps its place ([`fat32::RootCursor`]).
///
/// # Errors
///
/// A card that does not mount or read.
fn kept<D: BlockDevice>(
    dev: &mut D,
    names: &mut [[u8; 11]],
    mut keep: impl FnMut(&mut D, &fat32::Fat32Info, &fat32::DirEntry) -> bool,
) -> Result<(usize, u16), Error> {
    let info = fat32::mount_fat32(dev)?;
    let (mut found, mut extra) = (0usize, 0u16);
    let mut root = fat32::RootCursor::new(&info);
    while let Some(entry) = root.next(dev, &info)? {
        if !keep(dev, &info, &entry) {
            continue;
        }
        if found < names.len() {
            names[found] = entry.name;
            found += 1;
        } else {
            extra = extra.saturating_add(1);
        }
    }
    Ok((found, extra))
}

/// Read `name` into `out`; the bytes read.
///
/// # Errors
///
/// A card that does not mount or read; [`Error::Backup`] for a file larger
/// than `out`, since no backup is.
pub fn read<D: BlockDevice>(dev: &mut D, name: &[u8; 11], out: &mut [u8]) -> Result<usize, Error> {
    let info = fat32::mount_fat32(dev)?;
    let (entry, _, _) = fat32::find_file_in_root(dev, &info, name)?;
    if entry.file_size as usize > out.len() {
        return Err(Error::Backup("File error"));
    }
    Ok(fat32::read_file(dev, &info, &entry, out)?)
}

/// Delete `name` from the root.
///
/// # Errors
///
/// As the filesystem says.
pub fn delete<D: BlockDevice>(dev: &mut D, name: &[u8; 11]) -> Result<(), Error> {
    let info = fat32::mount_fat32(dev)?;
    fat32::delete_file(dev, &info, name)?;
    Ok(())
}

/// Format the whole card FAT32, then mount it: a format that does not mount
/// failed.
///
/// # Errors
///
/// As the formatter or the mount says.
pub fn format<D: BlockDevice>(dev: &mut D) -> Result<(), Error> {
    fat32::do_format_fat32(dev)?;
    fat32::mount_fat32(dev)?;
    Ok(())
}
