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

//! Settings' SD Card jobs, against a card in memory: the same code every
//! unit runs inside its card's session.

use kassigner_fat32::block::{BlockDevice, Error as BlockError, Memory, BLOCK_SIZE};
use kassigner_fat32::fat32::{
    create_file, do_format_fat32, find_file_in_root, list_root_dir, mount_fat32, read_file,
};
use kassigner_fw::card::{self, Error, Job, Kind, Outcome, Request, TEST_DATA, TEST_NAME};

type Card = Memory<Vec<[u8; BLOCK_SIZE]>>;

/// A blank card of 64 MB, the smallest the formatter takes happily.
fn blank() -> Card {
    Memory::new(vec![[0u8; BLOCK_SIZE]; 128 * 1024])
}

/// A card this code formatted.
fn formatted() -> Card {
    let mut c = blank();
    do_format_fat32(&mut c).expect("format");
    c
}

/// Entries in the root.
fn files(c: &mut Card) -> u32 {
    let info = mount_fat32(c).expect("mount");
    let mut n = 0;
    list_root_dir(c, &info, |_| {
        n += 1;
        true
    })
    .expect("list");
    n
}

/// A request that names nothing and holds nothing, for the jobs that need
/// neither.
fn none() -> Request<'static> {
    Request {
        name: [b' '; 11],
        file: Box::leak(Box::new([0u8; 0])),
        len: 0,
        names: Box::leak(Box::new([[0u8; 11]; 0])),
        long: &mut [],
    }
}

/// A card that keeps nothing written to it, and says nothing: every write
/// succeeds and the block reads back as it was.
struct Forgetful(Card);

impl BlockDevice for Forgetful {
    fn blocks(&self) -> u32 {
        self.0.blocks()
    }
    fn read(&mut self, block: u32, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), BlockError> {
        self.0.read(block, buf)
    }
    fn write(&mut self, _: u32, _: &[u8; BLOCK_SIZE]) -> Result<(), BlockError> {
        Ok(())
    }
}

/// A probe touches nothing and says what the board found.
#[test]
fn a_probe_reports_the_kind() {
    let mut c = blank();
    assert_eq!(
        card::run(Job::Probe, Kind::SdV2High, &mut c, &mut none()),
        Outcome::Present(Kind::SdV2High)
    );
    assert!(Outcome::Present(Kind::SdV1).ok());
    assert_eq!(Kind::SdV2High.label(), "SDHC (High Capacity)");
    assert_eq!(Kind::SdV2Standard.label(), "SD v2 (Standard)");
    assert_eq!(Kind::SdV1.label(), "SD v1");
}

/// **The test writes, reads back, matches and cleans up**: 34 bytes, the
/// root counted with it there, nothing left behind.
#[test]
fn the_test_passes_on_a_formatted_card_and_leaves_it_as_it_was() {
    let mut c = formatted();
    assert_eq!(
        card::run(Job::Test, Kind::SdV2High, &mut c, &mut none()),
        Outcome::Tested {
            bytes: TEST_DATA.len(),
            files: 1
        }
    );
    assert_eq!(TEST_DATA.len(), 34, "v1.0.7's test data");
    assert_eq!(files(&mut c), 0, "the test file is deleted");

    // The person's files are counted and left alone.
    let info = mount_fat32(&mut c).unwrap();
    create_file(&mut c, &info, b"KEEP    TXT", b"theirs").unwrap();
    assert_eq!(
        card::test(&mut c),
        Ok((TEST_DATA.len(), 2)),
        "theirs and the test's"
    );
    let info = mount_fat32(&mut c).unwrap();
    let (entry, _, _) = find_file_in_root(&mut c, &info, b"KEEP    TXT").unwrap();
    let mut back = [0u8; BLOCK_SIZE];
    let n = read_file(&mut c, &info, &entry, &mut back).unwrap();
    assert_eq!(&back[..n], b"theirs");
    assert_eq!(files(&mut c), 1);
}

/// A `TEST.TXT` left by a test that failed half way is replaced, not
/// doubled.
#[test]
fn a_test_file_left_behind_is_replaced() {
    let mut c = formatted();
    let info = mount_fat32(&mut c).unwrap();
    create_file(
        &mut c,
        &info,
        &TEST_NAME,
        b"an older one, longer than the new",
    )
    .unwrap();
    assert_eq!(card::test(&mut c), Ok((TEST_DATA.len(), 1)));
    assert_eq!(files(&mut c), 0);
}

/// A card that is not FAT32 fails the test in the filesystem's words.
#[test]
fn the_test_fails_on_a_card_that_is_not_fat32() {
    let mut c = blank();
    match card::run(Job::Test, Kind::SdV2High, &mut c, &mut none()) {
        Outcome::Failed(Error::Filesystem(why)) => assert!(!why.is_empty()),
        other => panic!("{other:?}"),
    }
}

/// A card pulled out is a device failure, and says so.
#[test]
fn a_card_that_is_gone_fails_as_gone() {
    let mut c = formatted();
    c.present = false;
    let out = card::run(Job::Test, Kind::SdV2High, &mut c, &mut none());
    assert_eq!(out, Outcome::Failed(Error::Device(BlockError::NotPresent)));
    assert!(!out.ok());
    assert_eq!(
        Error::Device(BlockError::NotPresent).describe(),
        card::NO_CARD
    );
}

/// The format leaves a card that mounts and passes the test.
#[test]
fn a_formatted_card_mounts_and_tests() {
    let mut c = blank();
    assert_eq!(
        card::run(Job::Format, Kind::SdV2High, &mut c, &mut none()),
        Outcome::Formatted
    );
    assert!(mount_fat32(&mut c).is_ok());
    assert!(matches!(card::test(&mut c), Ok((34, 1))));
}

/// A card that keeps nothing fails the format, in the formatter's words.
#[test]
fn a_card_that_keeps_nothing_fails_the_format() {
    let mut c = Forgetful(blank());
    match card::run(Job::Format, Kind::SdV2High, &mut c, &mut none()) {
        Outcome::Failed(Error::Filesystem(why)) => assert!(why.starts_with("Verify"), "{why}"),
        other => panic!("{other:?}"),
    }
}

/// Every failure has a line to say it with.
#[test]
fn every_failure_says_why() {
    for e in [
        Error::Device(BlockError::NotPresent),
        Error::Device(BlockError::Io),
        Error::Device(BlockError::OutOfRange {
            block: 1,
            blocks: 1,
        }),
        Error::Device(BlockError::Unaligned { len: 1 }),
        Error::Filesystem("Disk full"),
        Error::Size,
        Error::ReadBack,
        Error::Data,
    ] {
        assert!(!e.describe().is_empty(), "{e:?}");
    }
}

/// A request for the next name of `letters` and `ext`'s form.
fn pattern(letters: &[u8], ext: &[u8; 3]) -> Request<'static> {
    Request {
        name: card::name83(letters, ext),
        ..none()
    }
}

/// **A file's name.** The next is one past the highest of the request's
/// form (`SDnnnn.KAS` for a backup, `KPnnnn.TXT` for a kpub, `KMnnnn.K45`
/// for a cosigner's), names in other forms not counting; a name typed is
/// upper case, letters and digits, eight at most.
#[test]
fn backup_names_number_on_and_read_back() {
    let mut c = formatted();
    let backups = || pattern(b"SD", &card::BACKUP_EXT);
    assert_eq!(
        card::run(Job::NextName, Kind::SdV2High, &mut c, &mut backups()),
        Outcome::NextName(1)
    );
    let info = mount_fat32(&mut c).unwrap();
    for name in [
        b"SD0007  KAS",
        b"SD0003  KAS",
        b"SD0099  TXT",
        b"SDX001  KAS",
        b"MINE    KAS",
        b"KP0004  TXT",
        b"KM0002  TXT",
    ] {
        create_file(&mut c, &info, name, b"x").unwrap();
    }
    assert_eq!(
        card::run(Job::NextName, Kind::SdV2High, &mut c, &mut backups()),
        Outcome::NextName(8)
    );
    assert_eq!(
        card::run(
            Job::NextName,
            Kind::SdV2High,
            &mut c,
            &mut pattern(b"KP", b"TXT")
        ),
        Outcome::NextName(5),
        "a kpub's own numbers"
    );
    assert_eq!(
        card::run(
            Job::NextName,
            Kind::SdV2High,
            &mut c,
            &mut pattern(b"KM", &card::COSIGNER_EXT)
        ),
        Outcome::NextName(1),
        "a cosigner key's, a .TXT not among them"
    );

    assert_eq!(
        &card::name83(b"my-Seed_2026", &card::BACKUP_EXT),
        b"MYSEED20KAS"
    );
    assert_eq!(&card::name83(b"sd0008", &card::BACKUP_EXT), b"SD0008  KAS");
    let mut shown = [0u8; 12];
    let n = card::shown_name(b"SD0008  KAS", &mut shown);
    assert_eq!(&shown[..n], b"SD0008.KAS");
    assert_eq!(
        format!("{:?}", card::FileName(*b"SD0008  KAS")),
        "SD0008.KAS",
        "the console prints the name, not its bytes"
    );
}

/// **A backup is written, found, and written again over itself.**
#[test]
fn a_backup_is_written_and_found() {
    let mut c = formatted();
    let name = card::name83(b"SD0001", &card::BACKUP_EXT);
    let mut file = *b"sealed bytes";
    let mut no_names = [[0u8; 11]; 0];
    let mut ask = Request {
        name,
        file: &mut file,
        len: 12,
        names: &mut no_names,
        long: &mut [],
    };
    assert_eq!(
        card::run(Job::Exists, Kind::SdV2High, &mut c, &mut ask),
        Outcome::Exists(false)
    );
    assert_eq!(
        card::run(Job::Write, Kind::SdV2High, &mut c, &mut ask),
        Outcome::Written
    );
    assert_eq!(
        card::run(Job::Exists, Kind::SdV2High, &mut c, &mut ask),
        Outcome::Exists(true)
    );
    let mut other = *b"other";
    let mut no_names = [[0u8; 11]; 0];
    let mut again = Request {
        name,
        file: &mut other,
        len: 5,
        names: &mut no_names,
        long: &mut [],
    };
    assert_eq!(
        card::run(Job::Write, Kind::SdV2High, &mut c, &mut again),
        Outcome::Written
    );
    assert_eq!(files(&mut c), 1, "replaced, not doubled");
    let info = mount_fat32(&mut c).unwrap();
    let (entry, _, _) = find_file_in_root(&mut c, &info, &name).unwrap();
    let mut back = [0u8; BLOCK_SIZE];
    let n = read_file(&mut c, &info, &entry, &mut back).unwrap();
    assert_eq!(&back[..n], b"other");
    c.present = false;
    assert_eq!(
        card::run(Job::Write, Kind::SdV2High, &mut c, &mut again),
        Outcome::Failed(Error::Device(BlockError::NotPresent))
    );
}

/// A seed backup as a device seals it, under `password`.
fn sealed_backup(password: &[u8]) -> Vec<u8> {
    use kassigner_crypto::backup::{seal_slot, FILE_MAX};
    use kassigner_crypto::container::SealKdf;
    use kassigner_crypto::slot::Slot;
    let words = kassigner_crypto::bip39::from_entropy(&[7u8; 16]).unwrap();
    let slot = Slot::mnemonic(words, b"").unwrap();
    let mut out = [0u8; FILE_MAX];
    let n = seal_slot(
        &slot,
        password,
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut out,
    )
    .unwrap();
    out[..n].to_vec()
}

/// **The list is the backups, and only them.** A `.KAS` that is a sealed
/// seed is listed; one that is not a container, one too large to be a
/// backup, and a backup under another extension are not; past the list's
/// room, the rest are counted. Read gives a listed file back whole.
#[test]
fn the_list_is_the_backups_and_read_gives_one_back() {
    let mut c = formatted();
    let info = mount_fat32(&mut c).unwrap();
    let backup = sealed_backup(b"Correct-Horse-9");
    create_file(&mut c, &info, b"SD0001  KAS", &backup).unwrap();
    create_file(&mut c, &info, b"MINE    KAS", &backup).unwrap();
    create_file(&mut c, &info, b"JUNK    KAS", b"not a container").unwrap();
    create_file(&mut c, &info, b"BIG     KAS", &vec![0u8; 2000]).unwrap();
    create_file(&mut c, &info, b"SD0002  TXT", &backup).unwrap();

    let mut file = [0u8; 600];
    let mut names = [[0u8; 11]; 8];
    let mut ask = Request {
        name: card::name83(b"", &card::BACKUP_EXT),
        file: &mut file,
        len: 0,
        names: &mut names,
        long: &mut [],
    };
    assert_eq!(
        card::run(Job::List, Kind::SdV2High, &mut c, &mut ask),
        Outcome::Listed { count: 2, extra: 0 }
    );
    let mut listed = [ask.names[0], ask.names[1]];
    listed.sort();
    assert_eq!(listed, [*b"MINE    KAS", *b"SD0001  KAS"]);

    // Room for one: the other backup is counted; JUNK is no backup and BIG
    // too large to be one, so neither is.
    let mut one = [[0u8; 11]; 1];
    let mut small = Request {
        name: card::name83(b"", &card::BACKUP_EXT),
        file: &mut file,
        len: 0,
        names: &mut one,
        long: &mut [],
    };
    assert_eq!(
        card::run(Job::List, Kind::SdV2High, &mut c, &mut small),
        Outcome::Listed { count: 1, extra: 1 }
    );

    let mut back = [0u8; 600];
    let mut names = [[0u8; 11]; 0];
    let mut read = Request {
        name: *b"SD0001  KAS",
        file: &mut back,
        len: 0,
        names: &mut names,
        long: &mut [],
    };
    assert_eq!(
        card::run(Job::Read, Kind::SdV2High, &mut c, &mut read),
        Outcome::Read(backup.len())
    );
    assert_eq!(&read.file[..backup.len()], &backup[..]);
}

/// **Files that are not backups do not push the backups off the list.**
/// Seventy small `.KAS` files of junk ahead of three backups, more than the
/// list's room: the three are listed, and "+N" counts backups only.
#[test]
fn junk_ahead_of_the_backups_does_not_hide_them() {
    let mut c = formatted();
    let info = mount_fat32(&mut c).unwrap();
    let backup = sealed_backup(b"Correct-Horse-9");
    for i in 0..70u32 {
        let mut name = *b"JUNK0000KAS";
        name[4..8].copy_from_slice(format!("{i:04}").as_bytes());
        create_file(&mut c, &info, &name, b"not a container").unwrap();
    }
    for name in [b"SD0001  KAS", b"SD0002  KAS", b"SD0003  KAS"] {
        create_file(&mut c, &info, name, &backup).unwrap();
    }

    let mut file = [0u8; 600];
    let mut names = [[0u8; 11]; 64];
    let mut ask = Request {
        name: card::name83(b"", &card::BACKUP_EXT),
        file: &mut file,
        len: 0,
        names: &mut names,
        long: &mut [],
    };
    assert_eq!(
        card::run(Job::List, Kind::SdV2High, &mut c, &mut ask),
        Outcome::Listed { count: 3, extra: 0 }
    );
    assert_eq!(
        ask.names[..3],
        [*b"SD0001  KAS", *b"SD0002  KAS", *b"SD0003  KAS"]
    );

    // Room for two: the third backup is the one counted, none of the junk.
    let mut two = [[0u8; 11]; 2];
    let mut small = Request {
        name: card::name83(b"", &card::BACKUP_EXT),
        file: &mut file,
        len: 0,
        names: &mut two,
        long: &mut [],
    };
    assert_eq!(
        card::run(Job::List, Kind::SdV2High, &mut c, &mut small),
        Outcome::Listed { count: 2, extra: 1 }
    );
}

/// **The kpub files, listed apart from the backups.** With `.TXT` asked
/// for: a kpub's text, and a file sealed under the KSPT purpose as v1.0.7
/// sealed a kpub; not a `.TXT` that is neither, nor a backup.
#[test]
fn the_kpub_files_are_listed() {
    use kassigner_crypto::container::{seal, SealKdf};
    use kassigner_protocol::container::Purpose;
    let mut c = formatted();
    let info = mount_fat32(&mut c).unwrap();
    let kpub = b"kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK";
    create_file(&mut c, &info, b"KP0001  TXT", kpub).unwrap();
    let mut sealed = [0u8; 512];
    let n = seal(
        Purpose::Kspt,
        kpub,
        b"Correct-Horse-9",
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut sealed,
    )
    .unwrap();
    create_file(&mut c, &info, b"KP0002  TXT", &sealed[..n]).unwrap();
    create_file(&mut c, &info, b"NOTES   TXT", b"hello").unwrap();
    create_file(&mut c, &info, b"KP0003  KAS", kpub).unwrap();
    let mut names = [[0u8; 11]; 8];
    let mut ask = Request {
        name: card::name83(b"", b"TXT"),
        file: Box::leak(Box::new([0u8; 0])),
        len: 0,
        names: &mut names,
        long: &mut [],
    };
    assert_eq!(
        card::run(Job::List, Kind::SdV2High, &mut c, &mut ask),
        Outcome::Listed { count: 2, extra: 0 }
    );
    let mut listed = names[..2].to_vec();
    listed.sort();
    assert_eq!(listed, [*b"KP0001  TXT", *b"KP0002  TXT"]);
}

/// **A job through [`card::Alive`] reads and writes the card as it would
/// bare, and says it is alive on every transfer**, so a long job keeps the
/// watchdog fed. A format through it leaves a card that mounts; a write and
/// a read back return the file's bytes.
#[test]
fn a_job_through_alive_is_the_same_job_and_says_so() {
    let mut card = blank();
    let calls = std::cell::Cell::new(0u32);
    let mut alive = || calls.set(calls.get() + 1);
    let mut fed = card::Alive::new(&mut card, &mut alive);
    assert_eq!(fed.blocks(), 128 * 1024);
    let mut req = none();
    assert_eq!(
        card::run(Job::Format, Kind::SdV2High, &mut fed, &mut req),
        Outcome::Formatted
    );
    let formatting = calls.get();
    assert!(
        formatting > 100,
        "every transfer of the format: {formatting}"
    );
    assert_eq!(files(&mut card), 0, "the card mounts, empty");

    let data = b"alive and well".repeat(100);
    let mut fed = card::Alive::new(&mut card, &mut alive);
    let info = mount_fat32(&mut fed).expect("mount");
    create_file(&mut fed, &info, b"ALIVE   TXT", &data).expect("write");
    let (entry, ..) = find_file_in_root(&mut fed, &info, b"ALIVE   TXT").expect("find");
    let mut back = vec![0u8; data.len()];
    assert_eq!(
        read_file(&mut fed, &info, &entry, &mut back),
        Ok(data.len())
    );
    assert!(back == data);
    assert!(
        calls.get() > formatting,
        "the write and the read said so too"
    );
}

/// A card that keeps every write, but changes the first byte of a block
/// starting with `marked`, as a worn or counterfeit card might.
struct Garbles {
    card: Card,
    marked: &'static [u8],
}

impl BlockDevice for Garbles {
    fn blocks(&self) -> u32 {
        self.card.blocks()
    }
    fn read(&mut self, block: u32, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), BlockError> {
        self.card.read(block, buf)
    }
    fn write(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), BlockError> {
        let mut kept = *data;
        if data.starts_with(self.marked) {
            kept[0] ^= 0x01;
        }
        self.card.write(block, &kept)
    }
}

/// **A save that reads back other bytes is not saved.** Every save is read
/// back and compared: a card that changes a byte fails the save as "Data
/// mismatch"; one that keeps it is saved.
#[test]
fn a_save_that_reads_back_other_bytes_is_not_saved() {
    let backup = sealed_backup(b"Correct-Horse-9");
    let marked: &'static [u8] = Box::leak(backup[..8].to_vec().into_boxed_slice());
    let mut c = Garbles {
        card: formatted(),
        marked,
    };
    let mut file = backup.clone();
    let mut no_names = [[0u8; 11]; 0];
    let mut save = Request {
        name: card::name83(b"SD0001", &card::BACKUP_EXT),
        len: file.len(),
        file: &mut file,
        names: &mut no_names,
        long: &mut [],
    };
    let outcome = card::run(Job::Write, Kind::SdV2High, &mut c, &mut save);
    assert_eq!(outcome, Outcome::Failed(Error::Data));
    assert_eq!(Error::Data.describe(), "Data mismatch");

    let mut kept = formatted();
    assert_eq!(
        card::run(Job::Write, Kind::SdV2High, &mut kept, &mut save),
        Outcome::Written
    );
}

/// **The backup list walks the root once**, so its reads do not grow with
/// the square of the files. Two hundred small `.KAS` files: each root sector
/// is read once, and the list is right.
#[test]
fn the_backup_list_walks_the_root_once() {
    use kassigner_fat32::fat32::read_fat_entry;

    /// The card, counting reads by block.
    struct Counted(Card, std::collections::HashMap<u32, usize>);
    impl BlockDevice for Counted {
        fn blocks(&self) -> u32 {
            self.0.blocks()
        }
        fn read(&mut self, block: u32, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), BlockError> {
            *self.1.entry(block).or_insert(0) += 1;
            self.0.read(block, buf)
        }
        fn write(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), BlockError> {
            self.0.write(block, data)
        }
    }

    let mut c = formatted();
    let info = mount_fat32(&mut c).unwrap();
    let backup = sealed_backup(b"Correct-Horse-9");
    for i in 0..200u32 {
        let name: [u8; 11] = format!("J{i:04}   KAS").as_bytes().try_into().unwrap();
        create_file(&mut c, &info, &name, b"not a container").unwrap();
    }
    create_file(&mut c, &info, b"SD0001  KAS", &backup).unwrap();

    let mut root = Vec::new();
    let mut cluster = info.root_cluster;
    loop {
        for s in 0..u32::from(info.sectors_per_cluster) {
            root.push(info.cluster_to_sector(cluster) + s);
        }
        match read_fat_entry(&mut c, &info, cluster).unwrap() {
            next if next >= 0x0FFF_FFF8 => break,
            next => cluster = next,
        }
    }

    let mut c = Counted(c, std::collections::HashMap::new());
    let mut file = [0u8; 600];
    let mut names = [[0u8; 11]; 8];
    let mut ask = Request {
        name: card::name83(b"", &card::BACKUP_EXT),
        file: &mut file,
        len: 0,
        names: &mut names,
        long: &mut [],
    };
    assert_eq!(
        card::run(Job::List, Kind::SdV2High, &mut c, &mut ask),
        Outcome::Listed { count: 1, extra: 0 }
    );
    assert_eq!(ask.names[0], *b"SD0001  KAS");
    let reads: usize = root.iter().map(|b| c.1.get(b).copied().unwrap_or(0)).sum();
    assert_eq!(reads, 201usize.div_ceil(16), "each root sector once");
}

/// **The descriptors, listed apart from every other text file.** A
/// descriptor's text, one with v1.0.7's comment line over it and `\r\n`
/// line ends, and one sealed under the descriptor's own purpose, two blocks
/// long: listed. A kpub's text, a note, an address sealed as text, a
/// descriptor of more keys than a unit holds, and one longer than the
/// buffer it is read into: not. The buffer is wiped after.
#[test]
fn the_descriptors_are_listed() {
    use kassigner_crypto::container::{seal, SealKdf};
    use kassigner_kaspa::kat::MULTISIG_45;
    use kassigner_protocol::container::Purpose;
    let keys = MULTISIG_45.kpubs;
    let three = format!("multi_hd45(2,{},{},{})", keys[0], keys[1], keys[2]);
    let five = format!(
        "# KasSigner multisig, 45' coordinated, 3-of-5\r\nmulti_hd45(3,{})\r\n",
        keys.join(",")
    );
    let sixth = keys[0].replace("kpub2J9", "kpub2J8");
    let six = format!("multi_hd45(2,{},{sixth})", keys.join(","));
    let long = format!("{three}{}", " ".repeat(1100));
    let mut sealed = [0u8; 1024];
    let n = seal(
        Purpose::Descriptor,
        five.as_bytes(),
        b"Correct-Horse-9",
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut sealed,
    )
    .unwrap();
    assert!(n > BLOCK_SIZE, "two blocks");
    let mut text = [0u8; 256];
    let address = b"kaspa:pqvgkyjeuxmd8k70egrrzpdz5rqj0acmr6y94mwsltxfp6nc50742295c3998";
    let t = seal(
        Purpose::Text,
        address,
        b"Correct-Horse-9",
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut text,
    )
    .unwrap();

    let mut c = formatted();
    for (name, bytes) in [
        (b"MD0001  TXT", three.as_bytes()),
        (b"MD0002  TXT", five.as_bytes()),
        (b"MD0003  TXT", &sealed[..n]),
        (b"KP0001  TXT", keys[0].as_bytes()),
        (b"NOTES   TXT", b"hello"),
        (b"MS0001  TXT", &text[..t]),
        (b"MD0004  TXT", six.as_bytes()),
        (b"MD0005  TXT", long.as_bytes()),
    ] {
        let info = mount_fat32(&mut c).unwrap();
        create_file(&mut c, &info, name, bytes).unwrap();
    }
    let mut scratch = [0u8; 1024];
    let mut names = [[0u8; 11]; 8];
    let mut ask = Request {
        name: card::name83(b"", b"TXT"),
        file: &mut scratch,
        len: 0,
        names: &mut names,
        long: &mut [],
    };
    assert_eq!(
        card::run(Job::ListGroups, Kind::SdV2High, &mut c, &mut ask),
        Outcome::Listed { count: 3, extra: 0 }
    );
    assert_eq!(
        ask.names[..3],
        [*b"MD0001  TXT", *b"MD0002  TXT", *b"MD0003  TXT"]
    );
    assert!(scratch.iter().all(|&b| b == 0), "the buffer wiped");
}

/// **A group's addresses, listed apart from every other text file.**
/// `MSnnnn.TXT` holding a multisig address on Kaspa's main network, a line
/// end after it or not, and one sealed as text: listed. A single key's
/// address, one on another network, a note, and a multisig address under
/// another name: not.
#[test]
fn the_multisig_addresses_are_listed() {
    use kassigner_crypto::container::{seal, SealKdf};
    use kassigner_kaspa::address::{encode, Prefix, Version, MAX_ADDRESS_LEN};
    use kassigner_protocol::container::Purpose;
    let address = |prefix, version| {
        let mut out = [0u8; MAX_ADDRESS_LEN];
        let n = encode(prefix, version, &[7; 32], &mut out).unwrap();
        out[..n].to_vec()
    };
    let group = address(Prefix::Mainnet, Version::ScriptHash);
    let mut ended = group.clone();
    ended.extend_from_slice(b"\r\n");
    let mut sealed = [0u8; 256];
    let n = seal(
        Purpose::Text,
        &group,
        b"Correct-Horse-9",
        &[1; 16],
        &[2; 12],
        SealKdf::Pbkdf2Sha256,
        &mut sealed,
    )
    .unwrap();
    let single = address(Prefix::Mainnet, Version::PubKey);
    let testnet = address(Prefix::Testnet, Version::ScriptHash);

    let mut c = formatted();
    for (name, bytes) in [
        (b"MS0001  TXT", &group[..]),
        (b"MS0002  TXT", &ended[..]),
        (b"MS0003  TXT", &sealed[..n]),
        (b"MS0004  TXT", &single[..]),
        (b"MS0005  TXT", &testnet[..]),
        (b"MS0006  TXT", b"hello"),
        (b"AD0001  TXT", &group[..]),
    ] {
        let info = mount_fat32(&mut c).unwrap();
        create_file(&mut c, &info, name, bytes).unwrap();
    }
    let mut names = [[0u8; 11]; 8];
    let mut ask = Request {
        name: card::name83(b"MS", b"TXT"),
        file: Box::leak(Box::new([0u8; 0])),
        len: 0,
        names: &mut names,
        long: &mut [],
    };
    assert_eq!(
        card::run(Job::ListAddresses, Kind::SdV2High, &mut c, &mut ask),
        Outcome::Listed { count: 3, extra: 0 }
    );
    assert_eq!(
        ask.names[..3],
        [*b"MS0001  TXT", *b"MS0002  TXT", *b"MS0003  TXT"]
    );
}
