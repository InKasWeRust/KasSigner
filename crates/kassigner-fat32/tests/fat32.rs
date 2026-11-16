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

//! FAT32 against a card in memory: a block device is numbered sectors, and
//! an array is one.

use kassigner_fat32::block::{BlockDevice, Error, Memory, BLOCK_SIZE};
use kassigner_fat32::fat32::{
    create_file, csd_plausible, derive_geometry, do_format_fat32, find_file_in_root, lfn_checksum,
    list_root_dir, list_root_dir_lfn, mount_fat32, read_fat_entry, read_file,
    write_dir_entry_with_long_name, DirEntry, Fat32Error, Fat32Info, MAX_LONG_NAME,
};

/// A card in memory: the crate's own, which the firmware's card tests use
/// too.
type RamCard = Memory<Vec<[u8; BLOCK_SIZE]>>;

/// A blank card of `blocks` blocks.
fn ram(blocks: usize) -> RamCard {
    Memory::new(vec![[0u8; BLOCK_SIZE]; blocks])
}

/// A card this crate formats mounts: its boot sector, FATs and root
/// directory parse back.
#[test]
fn a_card_this_formats_can_be_mounted() {
    // 64 MB: small, and enough clusters for FAT32.
    let mut card = ram(128 * 1024);

    do_format_fat32(&mut card).expect("format");

    let info = mount_fat32(&mut card).expect("mount");
    assert_eq!(info.num_fats, 2, "both FATs, as the format wrote");
    assert!(info.sectors_per_cluster > 0);
    assert_eq!(info.root_cluster, 2, "the root is the first data cluster");
    assert!(info.data_start_sector > info.fat_start_sector);
}

/// A freshly formatted card has an empty root.
#[test]
fn a_fresh_card_has_no_files() {
    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");

    let mut count = 0;
    // The callback returns `bool`: false stops the walk early.
    list_root_dir(&mut card, &info, |_e| {
        count += 1;
        true
    })
    .expect("list");
    assert_eq!(count, 0);

    // Names are 8.3, space padded, as they sit in a directory entry.
    let absent = *b"NOTHERE TXT";
    assert!(matches!(
        find_file_in_root(&mut card, &info, &absent),
        Err(Fat32Error::Format(_))
    ));
}

/// A formatted card with its boot sector patched: each test below differs
/// from a card that mounts by exactly the bytes it names.
fn card_with_patched_boot(patch: impl Fn(&mut [u8; BLOCK_SIZE])) -> RamCard {
    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let mut sector = [0u8; BLOCK_SIZE];
    card.read(0, &mut sector).expect("read");
    patch(&mut sector);
    card.write(0, &sector).expect("write");
    card
}

/// Assert the boot sector is refused for `reason`, and its card does not
/// mount. The reason is checked on the boot sector itself: after its
/// fallbacks, `mount_fat32` gives one message for most failures.
fn refused_because(patch: impl Fn(&mut [u8; BLOCK_SIZE]), reason: &str) {
    let mut card = card_with_patched_boot(patch);
    let mut sector = [0u8; BLOCK_SIZE];
    card.read(0, &mut sector).expect("read");
    match Fat32Info::from_boot_sector(&sector) {
        Err(Fat32Error::Format(msg)) => assert_eq!(msg, reason),
        other => panic!("expected {reason}, got {other:?}"),
    }
    assert!(matches!(mount_fat32(&mut card), Err(Fat32Error::Format(_))));
}

/// A FAT16 card, the usual format at or below 2 GB, does not mount as FAT32.
/// FAT16 keeps its FAT size in the 16-bit field at 22 and leaves the 32-bit
/// one at 36 zero; mounted as FAT32, its data area would sit on its own FAT,
/// and a write would go over its FAT and root directory.
#[test]
fn a_fat16_card_is_not_mounted_as_fat32() {
    // The FAT16 shape: size in the 16-bit field, 32-bit field zero.
    refused_because(
        |s| {
            s[22] = 0x00;
            s[23] = 0x04;
            s[36..40].fill(0);
        },
        "Zero FAT size",
    );

    // Both fields set: neither alone decides it.
    refused_because(
        |s| {
            s[22] = 0x00;
            s[23] = 0x04;
        },
        "Not FAT32: FAT size is in the 16-bit field",
    );
}

/// A boot sector with no reserved sectors is refused: the FAT would start at
/// sector 0, and the first allocation would write over the boot sector.
#[test]
fn a_volume_with_no_reserved_sectors_is_refused() {
    refused_because(
        |s| {
            s[14] = 0;
            s[15] = 0;
        },
        "Zero reserved sectors",
    );
}

/// A FAT larger than the volume is refused: the allocators' cluster ceiling
/// is the volume's size less the data start, which would go below zero.
#[test]
fn a_fat_that_does_not_fit_the_volume_is_refused() {
    refused_because(
        |s| s[36..40].copy_from_slice(&0x0010_0000u32.to_le_bytes()),
        "Data area starts past the end of the volume",
    );
}

/// A FAT too small for its clusters is refused: `read_fat_entry` would read
/// past it, taking file contents for links.
#[test]
fn a_fat_too_small_for_its_clusters_is_refused() {
    refused_because(
        |s| s[36..40].copy_from_slice(&1u32.to_le_bytes()),
        "FAT too small for the cluster count",
    );
}

/// A root cluster past the last cluster is refused: every root walk starts
/// there, so its first read would be outside the data area.
#[test]
fn a_root_cluster_outside_the_data_area_is_refused() {
    refused_because(
        |s| s[44..48].copy_from_slice(&0x00FF_FFFFu32.to_le_bytes()),
        "Invalid root cluster",
    );
}

/// A card that is not FAT32 is refused, not misread as a geometry that sends
/// reads anywhere.
#[test]
fn a_card_that_is_not_fat32_is_refused() {
    let mut blank = ram(1024);
    assert!(matches!(
        mount_fat32(&mut blank),
        Err(Fat32Error::Format(_))
    ));

    // A boot signature and nothing else behind it.
    let mut lying = ram(1024);
    let mut sector = [0u8; BLOCK_SIZE];
    sector[510] = 0x55;
    sector[511] = 0xAA;
    lying.write(0, &sector).expect("write");
    assert!(matches!(
        mount_fat32(&mut lying),
        Err(Fat32Error::Format(_))
    ));
}

/// A device failure is not a format failure: a missing card and one that is
/// not FAT32 want different responses.
#[test]
fn a_missing_card_reports_a_device_error() {
    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    card.present = false;

    match mount_fat32(&mut card) {
        Err(Fat32Error::Device(Error::NotPresent)) => {}
        other => panic!("expected a device error, got {other:?}"),
    }
}

/// An empty card in memory refuses every block: a size of zero is unknown
/// to the range check, so the store itself says no.
#[test]
fn an_empty_card_in_memory_refuses_every_block() {
    let mut card = ram(0);
    let mut buf = [0u8; BLOCK_SIZE];
    let refused = Err(Error::OutOfRange {
        block: 0,
        blocks: 0,
    });
    assert_eq!(card.read(0, &mut buf), refused);
    assert_eq!(card.write(0, &buf), refused);
    assert_eq!(card.read_many(0, &mut [0u8; 2 * BLOCK_SIZE]), refused);
}

/// The formatter's geometry holds together: the FATs have an entry for every
/// cluster, and the clusters fit after them.
#[test]
fn the_derived_geometry_holds_together() {
    for sectors in [128u32 * 1024, 512 * 1024, 2 * 1024 * 1024, 8 * 1024 * 1024] {
        let geo = derive_geometry(sectors).expect("geometry");

        assert!(csd_plausible(sectors));
        assert!(geo.sectors_per_cluster.is_power_of_two());
        assert!(geo.total_sectors <= sectors);

        // Every cluster needs a four-byte FAT entry, and both FATs hold them.
        let entries_per_sector = BLOCK_SIZE as u32 / 4;
        let needed = geo.clusters.div_ceil(entries_per_sector);
        assert!(
            geo.fat_size >= needed,
            "{sectors} sectors: FAT of {} cannot hold {} clusters",
            geo.fat_size,
            geo.clusters
        );

        // And the data area really has room for them.
        let data = geo.total_sectors - (32 + 2 * geo.fat_size);
        assert!(
            data >= geo.clusters * geo.sectors_per_cluster as u32,
            "{sectors} sectors: data area too small for the cluster count"
        );
    }
}

/// A card too small to hold a filesystem is refused.
#[test]
fn a_card_too_small_is_refused() {
    assert!(derive_geometry(0).is_err());
    assert!(derive_geometry(100).is_err());
    assert!(!csd_plausible(0));
}

/// Reading a file needs a buffer that fits it: a buffer a byte short is
/// refused before any sector is read, and left as it was. One that fits
/// reads the file whole.
#[test]
fn a_short_buffer_is_refused_before_reading() {
    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8 + 1).collect();
    create_file(&mut card, &info, b"SHORT   BIN", &data).expect("create");
    let (entry, _, _) = find_file_in_root(&mut card, &info, b"SHORT   BIN").expect("find");

    let mut card = Counted::new(card);
    let mut short = vec![0xEEu8; data.len() - 1];
    assert_eq!(
        read_file(&mut card, &info, &entry, &mut short),
        Err(Fat32Error::Format("Buffer too small"))
    );
    assert_eq!(card.read_count(None), 0, "a sector was read");
    assert!(short.iter().all(|&b| b == 0xEE), "the buffer was written");

    let mut whole = vec![0u8; data.len()];
    assert_eq!(
        read_file(&mut card, &info, &entry, &mut whole),
        Ok(data.len())
    );
    assert_eq!(whole, data);
}

// ═══════════════════════════════════════════════════════════════
// Files and directories
// ═══════════════════════════════════════════════════════════════

/// A chain longer than its file is refused. A read stops at the file's size,
/// so a looping chain would give bytes from the wrong clusters, which a
/// signer shows as a wrong passphrase. One FAT read after the data settles
/// it: a chain of the right length ends in an end-of-chain marker.
#[test]
fn a_chain_that_outlives_its_file_is_refused() {
    use kassigner_fat32::fat32::{read_file, write_fat_entry, DirEntry};

    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");

    // A one-cluster file whose chain does not stop: cluster 3 points at 4.
    let cluster_bytes = info.sectors_per_cluster as u32 * BLOCK_SIZE as u32;
    write_fat_entry(&mut card, &info, 3, 4).expect("link");
    write_fat_entry(&mut card, &info, 4, 0x0FFF_FFFF).expect("eoc");

    let entry = DirEntry {
        name: *b"LOOPY   BIN",
        attr: 0x20,
        cluster_hi: 0,
        cluster_lo: 3,
        file_size: cluster_bytes,
    };

    let mut out = vec![0u8; cluster_bytes as usize];
    match read_file(&mut card, &info, &entry, &mut out) {
        Err(Fat32Error::Format(msg)) => assert!(
            msg.contains("outlives"),
            "expected the chain-length check, got {msg:?}"
        ),
        other => panic!("a chain longer than the file must be refused, got {other:?}"),
    }
}

/// A file whose chain ends where it should still reads.
#[test]
fn a_chain_that_ends_correctly_still_reads() {
    use kassigner_fat32::fat32::{read_file, write_fat_entry, DirEntry};

    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");

    let cluster_bytes = info.sectors_per_cluster as u32 * BLOCK_SIZE as u32;
    write_fat_entry(&mut card, &info, 3, 0x0FFF_FFFF).expect("eoc");

    let entry = DirEntry {
        name: *b"FINE    BIN",
        attr: 0x20,
        cluster_hi: 0,
        cluster_lo: 3,
        file_size: cluster_bytes,
    };

    let mut out = vec![0u8; cluster_bytes as usize];
    let n = read_file(&mut card, &info, &entry, &mut out).expect("a good chain reads");
    assert_eq!(n, cluster_bytes as usize);
}

/// A read takes the file's sectors and no others, whatever the buffer's
/// length, and not the slack of its last sector: every byte past the file's
/// end stays as the caller left it, in a buffer a caller may reuse for
/// secrets. Eight-sector clusters, built by hand, for a read of several
/// sectors at once.
#[test]
fn a_read_takes_the_files_sectors_and_no_others() {
    use kassigner_fat32::fat32::{read_file, write_fat_entry, DirEntry};

    const SPC: u32 = 8;
    let info = Fat32Info {
        bytes_per_sector: 512,
        sectors_per_cluster: SPC as u8,
        reserved_sectors: 32,
        num_fats: 1,
        fat_size_32: 1,
        root_cluster: 2,
        total_sectors: 33 + 4 * SPC,
        fat_start_sector: 32,
        data_start_sector: 33,
        fsinfo_sector: 0,
    };
    let mut card = ram(info.total_sectors as usize);

    // A file over clusters 3 and 4, one and a bit: the bit is two sectors of
    // cluster 4, and the six after them belong to nothing it names.
    let size = SPC as usize * BLOCK_SIZE + 1000;
    write_fat_entry(&mut card, &info, 3, 4).expect("link");
    write_fat_entry(&mut card, &info, 4, 0x0FFF_FFFF).expect("eoc");
    let file = |i: usize| (i as u8).wrapping_mul(7).wrapping_add(1);
    let first = info.cluster_to_sector(3);
    for s in 0..2 * SPC {
        let mut sector = [0xEEu8; BLOCK_SIZE];
        let at = s as usize * BLOCK_SIZE;
        if at < size {
            for (i, b) in sector.iter_mut().enumerate() {
                *b = file(at + i);
            }
        }
        card.write(first + s, &sector).expect("data");
    }
    let entry = DirEntry {
        name: *b"SPAN    BIN",
        attr: 0x20,
        cluster_hi: 0,
        cluster_lo: 3,
        file_size: size as u32,
    };
    let want: Vec<u8> = (0..size).map(file).collect();
    let used = size.div_ceil(BLOCK_SIZE) * BLOCK_SIZE;
    let untouched = |rest: &[u8]| rest.iter().all(|&b| b == 0xAA);

    // Room for both clusters whole: the six sectors past the file stay out,
    // and so does the slack of its last.
    let mut out = vec![0xAAu8; 2 * SPC as usize * BLOCK_SIZE];
    assert_eq!(read_file(&mut card, &info, &entry, &mut out), Ok(size));
    assert!(out[..size] == want[..], "the file reads back");
    assert!(
        untouched(&out[size..]),
        "nothing past the file's end is written"
    );

    // A length that is not whole sectors.
    let mut odd = vec![0xAAu8; used + 300];
    assert_eq!(read_file(&mut card, &info, &entry, &mut odd), Ok(size));
    assert!(odd[..size] == want[..]);
    assert!(untouched(&odd[size..]));

    // More room than the card has after the file.
    let mut wide = vec![0xAAu8; 4 * used];
    assert_eq!(read_file(&mut card, &info, &entry, &mut wide), Ok(size));
    assert!(wide[..size] == want[..]);
    assert!(untouched(&wide[size..]));

    // Exactly the file's size.
    let mut exact = vec![0u8; size];
    assert_eq!(read_file(&mut card, &info, &entry, &mut exact), Ok(size));
    assert!(exact == want);
}

/// A partition, here as far into the card as it is long, is used to its
/// last cluster and keeps its own FSInfo; the card's sector 1, the gap after
/// the MBR, is untouched.
#[test]
fn a_partition_is_used_whole_and_keeps_its_own_fsinfo() {
    use kassigner_fat32::fat32::allocate_cluster;

    const SECTORS: u32 = 70_000;
    const LBA: u32 = SECTORS;
    let mut volume = ram(SECTORS as usize);
    do_format_fat32(&mut volume).expect("format");
    let mut card = ram((LBA + SECTORS) as usize);
    let mut sector = [0u8; BLOCK_SIZE];
    for s in 0..SECTORS {
        volume.read(s, &mut sector).expect("read");
        card.write(LBA + s, &sector).expect("write");
    }
    // An MBR with one FAT32 (LBA) partition.
    let mut mbr = [0u8; BLOCK_SIZE];
    mbr[446 + 4] = 0x0C;
    mbr[446 + 8..446 + 12].copy_from_slice(&LBA.to_le_bytes());
    mbr[446 + 12..446 + 16].copy_from_slice(&SECTORS.to_le_bytes());
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    card.write(0, &mbr).expect("mbr");

    let info = mount_fat32(&mut card).expect("mount");
    assert_eq!(info.fsinfo_sector, LBA + 1, "the volume's FSInfo");
    let fsinfo_free = |card: &mut RamCard| {
        let mut buf = [0u8; BLOCK_SIZE];
        card.read(LBA + 1, &mut buf).expect("fsinfo");
        assert_eq!(&buf[0..4], b"RRaA", "lead signature");
        u32::from_le_bytes(buf[488..492].try_into().unwrap())
    };
    let before = fsinfo_free(&mut card);

    // The last cluster the volume has, asked for by name.
    let data = info.data_start_sector - LBA;
    let last = 2 + (SECTORS - data) / info.sectors_per_cluster as u32 - 1;
    assert_eq!(allocate_cluster(&mut card, &info, last), Ok(last));
    assert_eq!(fsinfo_free(&mut card), before - 1, "the count moved");
    card.read(1, &mut sector).expect("read");
    assert!(
        sector.iter().all(|&b| b == 0),
        "the card's sector 1 untouched"
    );
}

/// Allocation moves FSInfo's free count. The specification calls it a hint
/// a driver must not trust, and nothing here decides by it, but a computer
/// shows it as the card's free space.
#[test]
fn allocation_moves_the_free_count() {
    use kassigner_fat32::fat32::allocate_cluster;

    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");

    let before = free_count(&mut card);
    assert_ne!(before, 0, "a fresh card has free clusters");

    allocate_cluster(&mut card, &info, 2).expect("allocate");
    assert_eq!(free_count(&mut card), before - 1);

    allocate_cluster(&mut card, &info, 2).expect("allocate");
    assert_eq!(free_count(&mut card), before - 2);
}

/// A chain across a gap and a FAT sector, kept without a list: a new file
/// fills a deleted one's hole, steps over the file after it, and runs on into
/// the FAT's second sector. It reads back whole, both FATs agree, and the
/// free count moves by exactly its clusters.
#[test]
fn a_chain_fills_a_hole_steps_over_a_file_and_crosses_a_fat_sector() {
    use kassigner_fat32::fat32::{create_file, delete_file, find_file_in_root, read_file};

    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    let cb = info.cluster_bytes() as usize;
    let fill = |n: usize, seed: u8| -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    };

    create_file(&mut card, &info, b"HOLE    BIN", &fill(100 * cb, 1)).expect("hole");
    create_file(&mut card, &info, b"KEEP    BIN", &fill(2 * cb, 2)).expect("keep");
    delete_file(&mut card, &info, b"HOLE    BIN").expect("delete");
    let before = free_count(&mut card);

    // 140 clusters: the 100 of the hole, over KEEP's 2, then 40 more, the
    // chain reaching past cluster 127 and so into the FAT's second sector.
    let data = fill(140 * cb - 7, 3);
    create_file(&mut card, &info, b"BIG     BIN", &data).expect("big");
    assert_eq!(free_count(&mut card), before - 140);

    let mut back = vec![0u8; data.len()];
    let (entry, _, _) = find_file_in_root(&mut card, &info, b"BIG     BIN").expect("find");
    let n = read_file(&mut card, &info, &entry, &mut back).expect("read");
    assert_eq!(n, data.len());
    assert!(back == data, "read back whole");
    let (keep, _, _) = find_file_in_root(&mut card, &info, b"KEEP    BIN").expect("keep");
    let mut kept = vec![0u8; 2 * cb];
    read_file(&mut card, &info, &keep, &mut kept).expect("read keep");
    assert!(
        kept == fill(2 * cb, 2),
        "the file stepped over is untouched"
    );

    let (mut one, mut two) = ([0u8; BLOCK_SIZE], [0u8; BLOCK_SIZE]);
    for s in 0..info.fat_size_32 {
        card.read(info.fat_start_sector + s, &mut one).unwrap();
        card.read(info.fat_start_sector + info.fat_size_32 + s, &mut two)
            .unwrap();
        assert_eq!(one, two, "FAT sector {s}: both copies the same");
    }
}

/// The free count as FSInfo reports it.
fn free_count(card: &mut RamCard) -> u32 {
    let mut buf = [0u8; BLOCK_SIZE];
    card.read(1, &mut buf).expect("fsinfo");
    assert_eq!(&buf[0..4], b"RRaA", "lead signature");
    assert_eq!(&buf[484..488], b"rrAa", "struct signature");
    u32::from_le_bytes([buf[488], buf[489], buf[490], buf[491]])
}

/// The long-name checksum, which binds a set to its short entry, is the
/// specification's rotate-then-add: not a sum, so the same bytes in another
/// order give another answer.
#[test]
fn the_long_name_checksum_matches_the_specification() {
    assert_eq!(lfn_checksum(b"ABCDEFGHIJK"), {
        let mut s: u8 = 0;
        for &c in b"ABCDEFGHIJK" {
            s = s.rotate_right(1).wrapping_add(c);
        }
        s
    });

    assert_ne!(
        lfn_checksum(b"ABCDEFGHIJK"),
        lfn_checksum(b"KJIHGFEDCBA"),
        "a sum would collide here"
    );
    assert_ne!(lfn_checksum(b"KASSIG~1BIN"), lfn_checksum(b"KASSIG~2BIN"));
}

/// A long name written here reads back: the writer's reversed set, with
/// sequence numbers and checksum, is put back together by the reader.
#[test]
fn a_long_name_written_is_read_back() {
    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");

    let entry = DirEntry {
        name: *b"SIGNED~1KAS",
        attr: 0x20,
        cluster_hi: 0,
        cluster_lo: 3,
        file_size: 1234,
    };
    let long: Vec<u16> = "signed-transaction-2026.kas".encode_utf16().collect();

    write_dir_entry_with_long_name(&mut card, &info, &entry, &long).expect("write");

    let mut seen: Vec<String> = Vec::new();
    list_root_dir_lfn(&mut card, &info, |_e, name, len| {
        seen.push(String::from_utf8_lossy(&name[..len]).into_owned());
        true
    })
    .expect("list");

    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0], "signed-transaction-2026.kas");
}

/// The names `list_root_dir_lfn` shows, in directory order.
fn names(card: &mut RamCard, info: &Fat32Info) -> Vec<String> {
    let mut seen = Vec::new();
    list_root_dir_lfn(card, info, |_e, name, len| {
        seen.push(String::from_utf8_lossy(&name[..len]).into_owned());
        true
    })
    .expect("list");
    seen
}

/// A long name laid in deleted slots does not hide the file after it: no
/// end-of-directory marker goes after a set that filled a hole.
#[test]
fn a_long_name_in_a_hole_keeps_the_file_after_it() {
    use kassigner_fat32::fat32::{create_file, delete_file};

    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    for name in [
        b"A       BIN",
        b"B       BIN",
        b"C       BIN",
        b"D       BIN",
    ] {
        create_file(&mut card, &info, name, b"x").expect("create");
    }
    delete_file(&mut card, &info, b"B       BIN").expect("delete");
    delete_file(&mut card, &info, b"C       BIN").expect("delete");

    // Twelve characters, one long-name entry and the short one: the hole.
    let entry = DirEntry {
        name: *b"NOTE~1  TXT",
        attr: 0x20,
        cluster_hi: 0,
        cluster_lo: 0,
        file_size: 0,
    };
    let long: Vec<u16> = "a-note.txt-1".encode_utf16().collect();
    write_dir_entry_with_long_name(&mut card, &info, &entry, &long).expect("write");

    assert_eq!(names(&mut card, &info), ["A.BIN", "a-note.txt-1", "D.BIN"]);
    assert!(find_file_in_root(&mut card, &info, b"D       BIN").is_ok());
}

/// A long name that does not fit before the end of the directory is seen.
/// Two-sector clusters: fourteen files leave two slots in the root's first
/// sector, and a set of four, three long-name entries and the short one,
/// goes at the start of the second, past the end-of-directory marker, which
/// is lifted.
#[test]
fn a_long_name_past_the_end_of_the_directory_is_seen() {
    use kassigner_fat32::fat32::create_file;

    let mut card = ram(140_000);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    assert!(info.sectors_per_cluster > 1, "the root has a second sector");

    let mut want: Vec<String> = Vec::new();
    for i in 0..14u8 {
        let mut name = *b"F00     BIN";
        name[1] = b'0' + i / 10;
        name[2] = b'0' + i % 10;
        create_file(&mut card, &info, &name, b"x").expect("create");
        want.push(format!("F{}{}.BIN", i / 10, i % 10));
    }

    let entry = DirEntry {
        name: *b"SIGNED~1KAS",
        attr: 0x20,
        cluster_hi: 0,
        cluster_lo: 0,
        file_size: 0,
    };
    let long: Vec<u16> = "signed-transaction-2026.kas".encode_utf16().collect();
    write_dir_entry_with_long_name(&mut card, &info, &entry, &long).expect("write");
    want.push("signed-transaction-2026.kas".into());
    assert_eq!(names(&mut card, &info), want);

    // The slots it lifted the marker from take the next file.
    create_file(&mut card, &info, b"LAST    BIN", b"x").expect("create");
    want.insert(14, "LAST.BIN".into());
    assert_eq!(names(&mut card, &info), want);
}

/// A name of the full length, six long-name entries and 78 characters, reads
/// back whole.
#[test]
fn a_long_name_of_the_full_length_reads_back_whole() {
    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");

    let entry = DirEntry {
        name: *b"LONGES~1KAS",
        attr: 0x20,
        cluster_hi: 0,
        cluster_lo: 0,
        file_size: 0,
    };
    let text: String = "kassigner-signed-"
        .repeat(5)
        .chars()
        .take(MAX_LONG_NAME)
        .collect();
    let long: Vec<u16> = text.encode_utf16().collect();
    write_dir_entry_with_long_name(&mut card, &info, &entry, &long).expect("write");

    assert_eq!(names(&mut card, &info), [text]);
}

/// A long name is shown only for the short entry it was written for: every
/// part carries its checksum, so once the short name is changed the listing
/// shows the new short name.
#[test]
fn a_long_name_whose_checksum_does_not_match_is_not_shown() {
    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");

    let entry = DirEntry {
        name: *b"SIGNED~1KAS",
        attr: 0x20,
        cluster_hi: 0,
        cluster_lo: 0,
        file_size: 0,
    };
    let long: Vec<u16> = "signed-transaction-2026.kas".encode_utf16().collect();
    write_dir_entry_with_long_name(&mut card, &info, &entry, &long).expect("write");

    let (_, sector, offset) = find_file_in_root(&mut card, &info, &entry.name).expect("find");
    let mut buf = [0u8; BLOCK_SIZE];
    card.read(sector, &mut buf).expect("read");
    buf[offset..offset + 11].copy_from_slice(b"OTHER   BIN");
    card.write(sector, &buf).expect("write");

    assert_eq!(names(&mut card, &info), ["OTHER.BIN"]);
}

/// Deleting a file deletes the long-name entries in front of it.
#[test]
fn deleting_a_file_deletes_its_long_name() {
    use kassigner_fat32::fat32::delete_file;

    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");

    let entry = DirEntry {
        name: *b"SIGNED~1KAS",
        attr: 0x20,
        cluster_hi: 0,
        cluster_lo: 0,
        file_size: 0,
    };
    let long: Vec<u16> = "signed-transaction-2026.kas".encode_utf16().collect();
    write_dir_entry_with_long_name(&mut card, &info, &entry, &long).expect("write");
    delete_file(&mut card, &info, &entry.name).expect("delete");

    let mut root = [0u8; BLOCK_SIZE];
    card.read(info.cluster_to_sector(info.root_cluster), &mut root)
        .expect("read");
    for (i, slot) in root.chunks_exact(32).enumerate() {
        assert!(
            slot[0] == 0x00 || slot[0] == 0xE5,
            "slot {i} still holds an entry"
        );
    }
    assert!(names(&mut card, &info).is_empty());
}

/// A long name over `MAX_LONG_NAME` characters is refused, and so is an
/// empty one.
#[test]
fn an_over_long_name_is_refused() {
    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");

    let entry = DirEntry {
        name: *b"TOOLONG BIN",
        attr: 0x20,
        cluster_hi: 0,
        cluster_lo: 2,
        file_size: 0,
    };

    let too_long: Vec<u16> = std::iter::repeat_n(b'A' as u16, MAX_LONG_NAME + 1).collect();
    assert!(matches!(
        write_dir_entry_with_long_name(&mut card, &info, &entry, &too_long),
        Err(Fat32Error::Format(_))
    ));

    assert!(matches!(
        write_dir_entry_with_long_name(&mut card, &info, &entry, &[]),
        Err(Fat32Error::Format(_))
    ));
}

/// A format clears the whole of both FATs: filled with junk first, every
/// sector past the first is zero after it, and the first holds only the
/// entries of clusters 0 and 1 and the root's end of chain.
#[test]
fn a_format_clears_both_whole_fats() {
    use kassigner_fat32::fat32::CLEAR_RUN;

    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    assert!(
        info.fat_size_32 as usize > 2 * CLEAR_RUN,
        "more than a couple of runs"
    );
    let junk = [0xA5u8; BLOCK_SIZE];
    for s in 0..2 * info.fat_size_32 {
        card.write(info.fat_start_sector + s, &junk).unwrap();
    }

    do_format_fat32(&mut card).expect("format again");
    let mut b = [0u8; BLOCK_SIZE];
    for copy in 0..2 {
        let start = info.fat_start_sector + copy * info.fat_size_32;
        card.read(start, &mut b).unwrap();
        assert!(
            b[12..].iter().all(|&x| x == 0),
            "copy {copy}: only the reserved entries"
        );
        for s in 1..info.fat_size_32 {
            card.read(start + s, &mut b).unwrap();
            assert!(b.iter().all(|&x| x == 0), "copy {copy}, FAT sector {s}");
        }
    }
    assert_eq!(free_count(&mut card), {
        let mut fresh = ram(128 * 1024);
        do_format_fat32(&mut fresh).unwrap();
        free_count(&mut fresh)
    });
}

/// A cluster number past the volume is never followed: a read of an entry
/// naming one is refused, its delete changes no sector but the directory's,
/// and the other file, whose data sits where its FAT entry would be, reads
/// back whole.
#[test]
fn a_cluster_past_the_volume_is_never_followed() {
    use kassigner_fat32::fat32::{create_file, delete_file, find_file_in_root, overwrite_file};

    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");

    let victim: Vec<u8> = (0..1500u32).map(|i| (i * 13 + 5) as u8).collect();
    let v = create_file(&mut card, &info, b"VICTIM  KAS", &victim).expect("victim");
    create_file(&mut card, &info, b"BROKEN  KAS", &[0x42; 700]).expect("broken");

    // The broken entry's first cluster: its FAT entry would be the first word
    // of the victim's data.
    let target = info.cluster_to_sector(v.first_cluster());
    let bogus = (target - info.fat_start_sector) * 128;
    assert!(!info.is_data_cluster(bogus), "past the volume");
    let (_, dir_sector, offset) =
        find_file_in_root(&mut card, &info, b"BROKEN  KAS").expect("find");
    let mut dir = [0u8; BLOCK_SIZE];
    card.read(dir_sector, &mut dir).expect("dir");
    dir[offset + 20..offset + 22].copy_from_slice(&((bogus >> 16) as u16).to_le_bytes());
    dir[offset + 26..offset + 28].copy_from_slice(&(bogus as u16).to_le_bytes());
    card.write(dir_sector, &dir).expect("patch");

    // A read of it is refused, not taken from outside the volume.
    let (broken, _, _) = find_file_in_root(&mut card, &info, b"BROKEN  KAS").expect("find");
    assert_eq!(broken.first_cluster(), bogus);
    let mut out = vec![0u8; 700];
    assert!(read_file(&mut card, &info, &broken, &mut out).is_err());

    // Deleted: only the directory's sector changes.
    let blocks = 128 * 1024;
    let snapshot = |card: &mut RamCard| -> Vec<[u8; BLOCK_SIZE]> {
        (0..blocks)
            .map(|i| {
                let mut b = [0u8; BLOCK_SIZE];
                card.read(i as u32, &mut b).expect("read");
                b
            })
            .collect()
    };
    let before = snapshot(&mut card);
    delete_file(&mut card, &info, b"BROKEN  KAS").expect("delete");
    let after = snapshot(&mut card);
    for i in 0..blocks {
        if i as u32 != dir_sector {
            assert!(before[i] == after[i], "sector {i} changed");
        }
    }
    assert!(find_file_in_root(&mut card, &info, b"BROKEN  KAS").is_err());

    // The victim reads back whole, and the name can be written again.
    let mut back = vec![0u8; victim.len()];
    assert_eq!(read_file(&mut card, &info, &v, &mut back), Ok(victim.len()));
    assert!(back == victim);
    overwrite_file(&mut card, &info, b"BROKEN  KAS", &[0x24; 300]).expect("write again");
    assert_eq!(read_file(&mut card, &info, &v, &mut back), Ok(victim.len()));
    assert!(back == victim);
}

/// A card that loses power after `left` more writes: every later write
/// fails, and what was written stays.
struct Cut {
    blocks: Vec<[u8; BLOCK_SIZE]>,
    left: usize,
    writes: usize,
}

impl BlockDevice for Cut {
    fn blocks(&self) -> u32 {
        u32::try_from(self.blocks.len()).unwrap_or(u32::MAX)
    }

    fn read(&mut self, block: u32, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        *buf = self.blocks[block as usize];
        Ok(())
    }

    fn write(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        if self.left == 0 {
            return Err(Error::Io);
        }
        self.left -= 1;
        self.writes += 1;
        self.blocks[block as usize] = *data;
        Ok(())
    }
}

/// The root's names, as a reader lists them.
fn root_names<D: BlockDevice>(dev: &mut D, info: &Fat32Info) -> Vec<[u8; 11]> {
    let mut names = Vec::new();
    list_root_dir(dev, info, |e| {
        names.push(e.name);
        true
    })
    .expect("list");
    names
}

/// A save that grows the root, cut at any write, leaves the root as it was
/// or with the new file: the free clusters hold old bytes laid out as
/// entries, and the new cluster is zeroed before it is linked.
#[test]
fn a_root_grown_by_a_cut_save_shows_no_old_bytes() {
    let mut card = Cut {
        blocks: vec![[0u8; BLOCK_SIZE]; 128 * 1024],
        left: usize::MAX,
        writes: 0,
    };
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");

    // The root's first cluster, full.
    let slots = usize::from(info.sectors_per_cluster) * 16;
    for i in 0..slots {
        let name: [u8; 11] = format!("F{i:04}   TXT").as_bytes().try_into().unwrap();
        create_file(&mut card, &info, &name, b"x").expect("fill");
    }
    let before = root_names(&mut card, &info);
    assert_eq!(before.len(), slots);

    // Every free cluster below 400 holds old bytes laid out as entries.
    let mut junk = [0u8; BLOCK_SIZE];
    for slot in junk.chunks_exact_mut(32) {
        slot[..11].copy_from_slice(b"JUNK    TXT");
        slot[11] = 0x20;
        slot[26] = 0x07;
        slot[28] = 0x10;
    }
    for cluster in 3..400u32 {
        if read_fat_entry(&mut card, &info, cluster).expect("entry") == 0 {
            let base = info.cluster_to_sector(cluster);
            for s in 0..u32::from(info.sectors_per_cluster) {
                card.blocks[(base + s) as usize] = junk;
            }
        }
    }
    let base = card.blocks.clone();

    // The whole save, counted.
    let mut whole = Cut {
        blocks: base.clone(),
        left: usize::MAX,
        writes: 0,
    };
    create_file(&mut whole, &info, b"NEW     TXT", b"new").expect("save");
    let mut after = before.clone();
    after.push(*b"NEW     TXT");
    assert_eq!(root_names(&mut whole, &info), after);
    let total = whole.writes;

    for n in 0..total {
        let mut cut = Cut {
            blocks: base.clone(),
            left: n,
            writes: 0,
        };
        assert!(
            create_file(&mut cut, &info, b"NEW     TXT", b"new").is_err(),
            "cut after {n} of {total}"
        );
        let names = root_names(&mut cut, &info);
        assert!(
            names == before || names == after,
            "cut after {n} of {total} writes lists {} entries",
            names.len()
        );
    }
}

/// A file's whole contents, if a reader finds and reads it.
fn contents<D: BlockDevice>(dev: &mut D, info: &Fat32Info, name: &[u8; 11]) -> Option<Vec<u8>> {
    let (entry, _, _) = find_file_in_root(dev, info, name).ok()?;
    let mut out = vec![0u8; entry.file_size as usize];
    let n = read_file(dev, info, &entry, &mut out).ok()?;
    out.truncate(n);
    Some(out)
}

/// An overwrite cut at any write leaves the old file or the new one, never
/// neither, and no other file touched: 97 bytes over 97, and two and a half
/// clusters over one and a half, each cut after every write in turn.
#[test]
fn an_overwrite_cut_at_any_write_keeps_the_old_file_or_the_new() {
    use kassigner_fat32::fat32::overwrite_file;

    let mut card = Cut {
        blocks: vec![[0u8; BLOCK_SIZE]; 128 * 1024],
        left: usize::MAX,
        writes: 0,
    };
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    let formatted = card.blocks.clone();
    let cluster = info.cluster_bytes() as usize;

    let keep: Vec<u8> = (0..1500u32).map(|i| (i * 7 + 3) as u8).collect();
    let cases = [
        (vec![0x11u8; 97], vec![0x22u8; 97]),
        (vec![0x33u8; cluster * 3 / 2], vec![0x44u8; cluster * 5 / 2]),
    ];
    for (old, new) in cases {
        let mut card = Cut {
            blocks: formatted.clone(),
            left: usize::MAX,
            writes: 0,
        };
        create_file(&mut card, &info, b"KEEP    KAS", &keep).expect("keep");
        create_file(&mut card, &info, b"SD0001  KAS", &old).expect("old");
        let base = card.blocks.clone();

        // The whole overwrite, counted.
        let mut whole = Cut {
            blocks: base.clone(),
            left: usize::MAX,
            writes: 0,
        };
        overwrite_file(&mut whole, &info, b"SD0001  KAS", &new).expect("overwrite");
        assert_eq!(
            contents(&mut whole, &info, b"SD0001  KAS"),
            Some(new.clone())
        );
        let total = whole.writes;

        for n in 0..total {
            let mut cut = Cut {
                blocks: base.clone(),
                left: n,
                writes: 0,
            };
            let _ = overwrite_file(&mut cut, &info, b"SD0001  KAS", &new);
            let now = contents(&mut cut, &info, b"SD0001  KAS");
            assert!(
                now.as_ref() == Some(&old) || now.as_ref() == Some(&new),
                "{} bytes over {}: cut after {n} of {total} writes reads {:?} bytes",
                new.len(),
                old.len(),
                now.map(|v| v.len())
            );
            assert_eq!(
                contents(&mut cut, &info, b"KEEP    KAS"),
                Some(keep.clone()),
                "cut after {n} of {total}"
            );
        }
    }
}

/// The clusters of `entry`'s chain, as many as its size takes.
fn chain_of(card: &mut RamCard, info: &Fat32Info, entry: &DirEntry) -> Vec<u32> {
    let cb = info.cluster_bytes();
    let n = entry.file_size.div_ceil(cb) as usize;
    let mut chain = vec![entry.first_cluster()];
    while chain.len() < n {
        let next = read_fat_entry(card, info, *chain.last().unwrap()).expect("link");
        chain.push(next);
    }
    chain
}

/// A delete frees the file's own clusters and no more. A chain that runs on
/// past its file, by damage or on purpose, can reach another file's
/// clusters; a delete, and an overwrite freeing the old chain, take the
/// file's clusters by its size, as a read does, and stop there.
#[test]
fn a_delete_frees_its_own_clusters_and_not_the_file_its_chain_runs_into() {
    use kassigner_fat32::fat32::{delete_file, overwrite_file, write_fat_entry};

    for overwrite in [false, true] {
        let mut card = ram(128 * 1024);
        do_format_fat32(&mut card).expect("format");
        let info = mount_fat32(&mut card).expect("mount");
        let cb = info.cluster_bytes() as usize;

        let a = create_file(&mut card, &info, b"A       KAS", &vec![0xA5; 3 * cb - 9]).expect("a");
        let victim: Vec<u8> = (0..4 * cb).map(|i| (i * 7 + 3) as u8).collect();
        let b = create_file(&mut card, &info, b"B       KAS", &victim).expect("b");
        let a_chain = chain_of(&mut card, &info, &a);
        let b_chain = chain_of(&mut card, &info, &b);
        assert_eq!(a_chain.len(), 3);
        assert_eq!(b_chain.len(), 4);

        // A's last link, its end of chain, pointed into B's second cluster.
        write_fat_entry(&mut card, &info, a_chain[2], b_chain[1]).expect("damage");

        let before = free_count(&mut card);
        let what = if overwrite {
            overwrite_file(&mut card, &info, b"A       KAS", &[0x5A; 100]).expect("overwrite");
            "an overwrite"
        } else {
            delete_file(&mut card, &info, b"A       KAS").expect("delete");
            "a delete"
        };

        // B's clusters are still its own, all of them.
        for &c in &b_chain {
            assert_ne!(
                read_fat_entry(&mut card, &info, c),
                Ok(0),
                "{what} freed B's cluster {c}"
            );
        }
        let mut back = vec![0u8; victim.len()];
        assert_eq!(read_file(&mut card, &info, &b, &mut back), Ok(victim.len()));
        assert!(back == victim, "{what}: B reads back whole");

        // A's three clusters were freed, and only they: the count moves by
        // them, less the one an overwrite's new contents took.
        for &c in &a_chain {
            assert_eq!(
                read_fat_entry(&mut card, &info, c),
                Ok(0),
                "{what}: A's {c} free"
            );
        }
        let taken = u32::from(overwrite);
        assert_eq!(
            free_count(&mut card),
            before + 3 - taken,
            "{what}: free count"
        );

        // A file written now does not land on B.
        create_file(&mut card, &info, b"C       KAS", &vec![0x3C; 6 * cb]).expect("c");
        assert_eq!(read_file(&mut card, &info, &b, &mut back), Ok(victim.len()));
        assert!(back == victim, "{what}: B whole after the next write");
    }
}

/// Every sector of `clusters`, read raw.
fn raw_clusters(card: &mut RamCard, info: &Fat32Info, clusters: &[u32]) -> Vec<u8> {
    let mut out = Vec::new();
    for &c in clusters {
        for i in 0..u32::from(info.sectors_per_cluster) {
            let mut block = [0u8; BLOCK_SIZE];
            card.read(info.cluster_to_sector(c) + i, &mut block)
                .expect("read");
            out.extend_from_slice(&block);
        }
    }
    out
}

/// A freed cluster holds zeros, not the file it was. A delete, and an
/// overwrite freeing the old chain, write zeros over each cluster they free
/// before the table calls it free, so a recovery tool finds nothing of the
/// file in free space. The files beside it, and an overwrite's new contents,
/// are not touched.
#[test]
fn a_freed_cluster_holds_zeros() {
    use kassigner_fat32::fat32::{delete_file, overwrite_file};

    for overwrite in [false, true] {
        let mut card = ram(128 * 1024);
        do_format_fat32(&mut card).expect("format");
        let info = mount_fat32(&mut card).expect("mount");
        let cb = info.cluster_bytes() as usize;

        let before: Vec<u8> = (0..2 * cb).map(|i| (i * 5 + 1) as u8).collect();
        let kept = create_file(&mut card, &info, b"KEPT    KAS", &before).expect("kept");
        let secret: Vec<u8> = (0..3 * cb - 7).map(|i| (i * 11 + 9) as u8 | 1).collect();
        let gone = create_file(&mut card, &info, b"GONE    KAS", &secret).expect("gone");
        let after: Vec<u8> = (0..cb + 3).map(|i| (i * 3 + 2) as u8).collect();
        let last = create_file(&mut card, &info, b"LAST    KAS", &after).expect("last");
        let chain = chain_of(&mut card, &info, &gone);
        assert_eq!(chain.len(), 3);
        // The file is there to begin with: its clusters read as its bytes.
        assert!(raw_clusters(&mut card, &info, &chain).starts_with(&secret));

        let fresh = [0x5A; 100];
        let what = if overwrite {
            overwrite_file(&mut card, &info, b"GONE    KAS", &fresh).expect("overwrite");
            "an overwrite"
        } else {
            delete_file(&mut card, &info, b"GONE    KAS").expect("delete");
            "a delete"
        };

        // Free, and nothing of the file in them.
        for &c in &chain {
            assert_eq!(
                read_fat_entry(&mut card, &info, c),
                Ok(0),
                "{what}: {c} free"
            );
        }
        assert!(
            raw_clusters(&mut card, &info, &chain)
                .iter()
                .all(|&b| b == 0),
            "{what}: the freed clusters are zeros"
        );

        // The files on either side read back whole.
        let mut back = vec![0u8; before.len()];
        assert_eq!(
            read_file(&mut card, &info, &kept, &mut back),
            Ok(before.len())
        );
        assert!(back == before, "{what}: the file before");
        let mut back = vec![0u8; after.len()];
        assert_eq!(
            read_file(&mut card, &info, &last, &mut back),
            Ok(after.len())
        );
        assert!(back == after, "{what}: the file after");

        // An overwrite's new contents are the file now; a delete left none.
        let now = contents(&mut card, &info, b"GONE    KAS");
        if overwrite {
            assert_eq!(now.as_deref(), Some(&fresh[..]), "{what}: the new contents");
        } else {
            assert_eq!(now, None, "{what}: no such file");
        }
    }
}

/// A cluster a damaged entry names but another file owns is kept, and kept
/// as it is: what is not freed is not zeroed.
#[test]
fn a_cluster_kept_from_a_delete_keeps_its_bytes() {
    use kassigner_fat32::fat32::{delete_file, write_fat_entry};

    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    let cb = info.cluster_bytes() as usize;

    let a = create_file(&mut card, &info, b"A       KAS", &vec![0xA5; 2 * cb]).expect("a");
    let owned: Vec<u8> = (0..2 * cb).map(|i| (i * 13 + 5) as u8 | 1).collect();
    let b = create_file(&mut card, &info, b"B       KAS", &owned).expect("b");
    let a_chain = chain_of(&mut card, &info, &a);
    let b_chain = chain_of(&mut card, &info, &b);
    // A's first cluster linked straight into B's first: A's second cluster by
    // the table is now B's.
    write_fat_entry(&mut card, &info, a_chain[0], b_chain[0]).expect("damage");

    delete_file(&mut card, &info, b"A       KAS").expect("delete");

    assert_eq!(raw_clusters(&mut card, &info, &b_chain), owned);
    assert!(raw_clusters(&mut card, &info, &a_chain[..1])
        .iter()
        .all(|&x| x == 0));
}

/// A large file is freed whole, 64 clusters a round: here 200 clusters, four
/// rounds. A delete and an overwrite both free all 200, and the free count
/// moves by them, less the cluster an overwrite's new contents take.
#[test]
fn a_large_file_is_freed_whole() {
    use kassigner_fat32::fat32::{delete_file, overwrite_file};

    for overwrite in [false, true] {
        let mut card = ram(128 * 1024);
        do_format_fat32(&mut card).expect("format");
        let info = mount_fat32(&mut card).expect("mount");
        let cb = info.cluster_bytes() as usize;

        let big =
            create_file(&mut card, &info, b"BIG     JPG", &vec![0x5B; 200 * cb - 3]).expect("big");
        let chain = chain_of(&mut card, &info, &big);
        assert_eq!(chain.len(), 200);
        let before = free_count(&mut card);
        let taken = if overwrite {
            overwrite_file(&mut card, &info, b"BIG     JPG", &[0xB5; 100]).expect("overwrite");
            1
        } else {
            delete_file(&mut card, &info, b"BIG     JPG").expect("delete");
            0
        };
        for &c in &chain {
            assert_eq!(read_fat_entry(&mut card, &info, c), Ok(0), "{c} free");
        }
        assert_eq!(free_count(&mut card), before + 200 - taken);
    }
}

/// A large file whose chain runs into another file in its third round frees
/// only its clusters before that point; the other file's clusters, and its
/// own past the damage, stay used.
#[test]
fn a_large_chain_run_into_another_file_frees_only_its_own() {
    use kassigner_fat32::fat32::{delete_file, write_fat_entry};

    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    let cb = info.cluster_bytes() as usize;

    let a = create_file(&mut card, &info, b"A       JPG", &vec![0xA5; 200 * cb]).expect("a");
    let victim: Vec<u8> = (0..4 * cb).map(|i| (i * 7 + 3) as u8).collect();
    let b = create_file(&mut card, &info, b"B       KAS", &victim).expect("b");
    let a_chain = chain_of(&mut card, &info, &a);
    let b_chain = chain_of(&mut card, &info, &b);

    // A's 150th link, in its third round, pointed into B's second cluster.
    write_fat_entry(&mut card, &info, a_chain[149], b_chain[1]).expect("damage");

    let before = free_count(&mut card);
    delete_file(&mut card, &info, b"A       JPG").expect("delete");
    for &c in &a_chain[..150] {
        assert_eq!(read_fat_entry(&mut card, &info, c), Ok(0), "A's {c} free");
    }
    for &c in &a_chain[150..] {
        assert_ne!(
            read_fat_entry(&mut card, &info, c),
            Ok(0),
            "{c} past the damage kept"
        );
    }
    assert_eq!(free_count(&mut card), before + 150);
    let mut back = vec![0u8; victim.len()];
    assert_eq!(read_file(&mut card, &info, &b, &mut back), Ok(victim.len()));
    assert!(back == victim, "B reads back whole");
}

/// A delete frees at most 4,096 clusters, 64 rounds: 2 MB at 512 bytes a
/// cluster, the largest file this device writes. The rest stay marked used
/// and named by nothing, as after a cut delete, so a huge file cannot keep
/// a delete running for as long as its size.
#[test]
fn a_delete_frees_no_more_than_its_bound() {
    use kassigner_fat32::fat32::delete_file;

    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    let cb = info.cluster_bytes() as usize;
    assert_eq!(cb, 512, "these cards' clusters");

    let huge = create_file(
        &mut card,
        &info,
        b"HUGE    BIN",
        &vec![0x48; 4096 * cb + 10 * cb],
    )
    .expect("huge");
    let chain = chain_of(&mut card, &info, &huge);
    let before = free_count(&mut card);
    delete_file(&mut card, &info, b"HUGE    BIN").expect("delete");
    assert_eq!(free_count(&mut card), before + 4096);
    assert_eq!(read_fat_entry(&mut card, &info, chain[4095]), Ok(0));
    assert_ne!(read_fat_entry(&mut card, &info, chain[4096]), Ok(0));
}

/// An empty file frees nothing, even with its entry naming a cluster,
/// another file's here: the size says how many clusters are the file's.
#[test]
fn deleting_an_empty_file_frees_no_cluster() {
    use kassigner_fat32::fat32::delete_file;

    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    let cb = info.cluster_bytes() as usize;

    let victim: Vec<u8> = (0..2 * cb).map(|i| (i * 5 + 1) as u8).collect();
    let b = create_file(&mut card, &info, b"B       KAS", &victim).expect("b");
    create_file(&mut card, &info, b"EMPTY   KAS", &[]).expect("empty");
    let (_, sector, offset) = find_file_in_root(&mut card, &info, b"EMPTY   KAS").expect("find");
    let mut dir = [0u8; BLOCK_SIZE];
    card.read(sector, &mut dir).expect("dir");
    let first = b.first_cluster();
    dir[offset + 20..offset + 22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
    dir[offset + 26..offset + 28].copy_from_slice(&(first as u16).to_le_bytes());
    card.write(sector, &dir).expect("patch");

    let before = free_count(&mut card);
    delete_file(&mut card, &info, b"EMPTY   KAS").expect("delete");
    assert_eq!(free_count(&mut card), before);
    let mut back = vec![0u8; victim.len()];
    assert_eq!(read_file(&mut card, &info, &b, &mut back), Ok(victim.len()));
    assert!(back == victim);
}

/// Point `name`'s entry at `cluster` with `size` bytes, as damage could.
fn point(card: &mut RamCard, info: &Fat32Info, name: &[u8; 11], cluster: u32, size: u32) {
    let (_, sector, offset) = find_file_in_root(card, info, name).expect("find");
    let mut dir = [0u8; BLOCK_SIZE];
    card.read(sector, &mut dir).expect("dir");
    dir[offset + 20..offset + 22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    dir[offset + 26..offset + 28].copy_from_slice(&(cluster as u16).to_le_bytes());
    dir[offset + 28..offset + 32].copy_from_slice(&size.to_le_bytes());
    card.write(sector, &dir).expect("patch");
}

/// Delete `name`, after writing over it if `overwrite`, as the SD Card test
/// does.
fn drop_file(card: &mut RamCard, info: &Fat32Info, name: &[u8; 11], overwrite: bool) {
    use kassigner_fat32::fat32::{delete_file, overwrite_file};
    if overwrite {
        overwrite_file(card, info, name, b"KasSigner SD test").expect("overwrite");
    }
    delete_file(card, info, name).expect("delete");
}

/// An entry naming the root directory frees none of it, or the next save
/// would write over every file. Deleted, or written over and deleted, such
/// an entry goes and the root stays; a chain that runs into the root frees
/// only the clusters before it.
#[test]
fn an_entry_naming_the_root_frees_none_of_it() {
    use kassigner_fat32::fat32::write_fat_entry;
    for overwrite in [false, true] {
        let mut card = ram(128 * 1024);
        do_format_fat32(&mut card).expect("format");
        let info = mount_fat32(&mut card).expect("mount");
        let root = info.root_cluster;
        let root_word = read_fat_entry(&mut card, &info, root).expect("root");
        let backup = vec![0x11; 300];
        let b = create_file(&mut card, &info, b"SD0001  KAS", &backup).expect("backup");

        // The entry's first cluster is the root's.
        create_file(&mut card, &info, b"TEST    TXT", &[0x22; 10]).expect("test");
        point(&mut card, &info, b"TEST    TXT", root, 34);
        drop_file(&mut card, &info, b"TEST    TXT", overwrite);
        assert_eq!(read_fat_entry(&mut card, &info, root), Ok(root_word));

        // A chain of its own that runs into the root: its own cluster goes,
        // the root stays.
        let e = create_file(&mut card, &info, b"EVIL    TXT", &[0x33; 10]).expect("evil");
        let own = e.first_cluster();
        write_fat_entry(&mut card, &info, own, root).expect("into the root");
        point(
            &mut card,
            &info,
            b"EVIL    TXT",
            own,
            2 * info.cluster_bytes(),
        );
        drop_file(&mut card, &info, b"EVIL    TXT", overwrite);
        assert_eq!(read_fat_entry(&mut card, &info, root), Ok(root_word));
        assert_eq!(
            read_fat_entry(&mut card, &info, own),
            Ok(0),
            "its own freed"
        );

        // The next save lands elsewhere, and the backup is still there.
        let next = create_file(&mut card, &info, b"SD0002  KAS", &[0x44; 300]).expect("next");
        assert_ne!(next.first_cluster(), root);
        let (found, _, _) = find_file_in_root(&mut card, &info, b"SD0001  KAS").expect("backup");
        assert_eq!(found.first_cluster(), b.first_cluster());
        let mut back = vec![0u8; backup.len()];
        assert_eq!(
            read_file(&mut card, &info, &found, &mut back),
            Ok(backup.len())
        );
        assert!(back == backup, "the backup reads back whole");
    }
}

/// An entry naming another file's clusters frees none of them: a second
/// entry naming a backup's first cluster or one mid-chain, deleted or
/// written over, leaves them the backup's, the free count unmoved, and the
/// backup whole after the next write.
#[test]
fn an_entry_naming_another_files_clusters_frees_none_of_them() {
    for overwrite in [false, true] {
        for into in [0usize, 1] {
            let mut card = ram(128 * 1024);
            do_format_fat32(&mut card).expect("format");
            let info = mount_fat32(&mut card).expect("mount");
            let cb = info.cluster_bytes() as usize;
            let backup: Vec<u8> = (0..3 * cb).map(|i| (i * 7 + 3) as u8).collect();
            let b = create_file(&mut card, &info, b"SD0001  KAS", &backup).expect("backup");
            let b_chain = chain_of(&mut card, &info, &b);

            create_file(&mut card, &info, b"TEST    TXT", &[0x22; 10]).expect("test");
            let left = (b_chain.len() - into) * cb;
            point(&mut card, &info, b"TEST    TXT", b_chain[into], left as u32);
            let before = free_count(&mut card);
            drop_file(&mut card, &info, b"TEST    TXT", overwrite);

            let what = format!("into cluster {into}, overwrite {overwrite}");
            for &c in &b_chain {
                assert_ne!(
                    read_fat_entry(&mut card, &info, c),
                    Ok(0),
                    "{what}: {c} freed"
                );
            }
            // Written over, its one new cluster is taken and freed again.
            assert_eq!(free_count(&mut card), before, "{what}: free count");
            create_file(&mut card, &info, b"SD0002  KAS", &vec![0x5A; 4 * cb]).expect("next");
            let mut back = vec![0u8; backup.len()];
            assert_eq!(read_file(&mut card, &info, &b, &mut back), Ok(backup.len()));
            assert!(
                back == backup,
                "{what}: the backup whole after the next write"
            );
        }
    }
}

/// A cluster not marked in use is not freed: a free one is not counted free
/// again, a bad one keeps its mark, and the free count does not move.
#[test]
fn a_cluster_not_marked_in_use_is_not_freed() {
    use kassigner_fat32::fat32::write_fat_entry;
    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    let e = create_file(&mut card, &info, b"A       TXT", &[0x22; 10]).expect("a");
    let free = e.first_cluster() + 100;
    assert_eq!(
        read_fat_entry(&mut card, &info, free),
        Ok(0),
        "a free cluster"
    );
    let bad = e.first_cluster() + 101;
    write_fat_entry(&mut card, &info, bad, 0x0FFF_FFF7).expect("mark bad");

    create_file(&mut card, &info, b"B       TXT", &[0x33; 10]).expect("b");
    let after_b = free_count(&mut card);
    point(&mut card, &info, b"B       TXT", free, 10);
    drop_file(&mut card, &info, b"B       TXT", false);
    assert_eq!(
        free_count(&mut card),
        after_b,
        "a free cluster counted again"
    );
    assert_eq!(read_fat_entry(&mut card, &info, free), Ok(0));

    point(&mut card, &info, b"A       TXT", bad, 10);
    drop_file(&mut card, &info, b"A       TXT", false);
    assert_eq!(
        read_fat_entry(&mut card, &info, bad),
        Ok(0x0FFF_FFF7),
        "the mark stays"
    );
    assert_eq!(
        free_count(&mut card),
        after_b,
        "nothing counted that was not freed"
    );
}

/// A card that reports a size of zero, unknown, as some cards do.
struct Unsized(RamCard);

impl BlockDevice for Unsized {
    fn blocks(&self) -> u32 {
        0
    }

    fn read(&mut self, block: u32, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.0.read(block, buf)
    }

    fn write(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.0.write(block, data)
    }
}

/// A volume that ends past the card is refused: its last clusters would be
/// reads and writes the card refuses. A card just the volume's size mounts,
/// one a sector shorter does not, and one of unknown size is taken at the
/// volume's word.
#[test]
fn a_volume_past_the_end_of_the_card_is_refused() {
    let mut card = Cut {
        blocks: vec![[0u8; BLOCK_SIZE]; 128 * 1024],
        left: usize::MAX,
        writes: 0,
    };
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    let end = info.total_sectors as usize;

    let mut whole = Cut {
        blocks: card.blocks[..end].to_vec(),
        left: usize::MAX,
        writes: 0,
    };
    let size = |m: Result<Fat32Info, Fat32Error>| m.map(|i| (i.total_sectors, i.data_start_sector));
    let want = Ok((info.total_sectors, info.data_start_sector));
    assert_eq!(
        size(mount_fat32(&mut whole)),
        want,
        "a card just big enough"
    );

    let mut short = Cut {
        blocks: card.blocks[..end - 1].to_vec(),
        left: usize::MAX,
        writes: 0,
    };
    assert_eq!(
        mount_fat32(&mut short).err(),
        Some(Fat32Error::Format("Volume past the last sector"))
    );

    let mut unknown = Unsized(Memory::new(card.blocks.clone()));
    assert_eq!(
        size(mount_fat32(&mut unknown)),
        want,
        "a size of zero is unknown"
    );
}

/// A volume whose FATs are not mirrored is refused. `BPB_ExtFlags` bit 7
/// says one FAT is active and the others are not kept, and this crate reads
/// the first and writes all, so it could read a stale one. A computer
/// formats with mirroring on, and so does this crate.
#[test]
fn a_volume_whose_fats_are_not_mirrored_is_refused() {
    refused_because(|s| s[40] |= 0x80, "FAT mirroring off");
    refused_because(
        |s| {
            s[40] = 0x81;
            s[41] = 0x00;
        },
        "FAT mirroring off",
    );
    // The active-FAT number alone, mirroring still on, is ignored as FAT says.
    let mut card = card_with_patched_boot(|s| s[40] = 0x01);
    assert!(mount_fat32(&mut card).is_ok());
}

/// Whether each FAT says the volume was left whole: the clean-shutdown bit of
/// its entry for cluster 1.
fn clean_marks<D: BlockDevice>(dev: &mut D, info: &Fat32Info) -> Vec<bool> {
    (0..u32::from(info.num_fats))
        .map(|copy| {
            let mut sector = [0u8; BLOCK_SIZE];
            dev.read(info.fat_start_sector + copy * info.fat_size_32, &mut sector)
                .expect("read");
            let entry = u32::from_le_bytes([sector[4], sector[5], sector[6], sector[7]]);
            entry & 0x0800_0000 != 0
        })
        .collect()
}

/// A volume is marked while a write runs, and clean once it is done: a
/// computer that sees FAT32's clean-shutdown bit cleared checks the card. A
/// save cut at any write leaves a FAT marked, the first until the save is
/// whole; a whole save, an overwrite and a delete leave both clean; a failed
/// save leaves the mark. A fresh format is clean, and the entry's other bits
/// stay.
#[test]
fn a_volume_is_marked_while_a_write_runs() {
    use kassigner_fat32::fat32::{delete_file, overwrite_file};

    let mut card = Cut {
        blocks: vec![[0u8; BLOCK_SIZE]; 128 * 1024],
        left: usize::MAX,
        writes: 0,
    };
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    assert_eq!(
        clean_marks(&mut card, &info),
        [true, true],
        "formatted clean"
    );
    let formatted = card.blocks.clone();
    let data: Vec<u8> = (0..3 * info.cluster_bytes() + 77)
        .map(|i| (i * 13 + 5) as u8)
        .collect();

    // The whole save, counted.
    let mut whole = Cut {
        blocks: formatted.clone(),
        left: usize::MAX,
        writes: 0,
    };
    create_file(&mut whole, &info, b"SD0001  KAS", &data).expect("save");
    assert_eq!(clean_marks(&mut whole, &info), [true, true]);
    let total = whole.writes;

    for n in 1..total {
        let mut cut = Cut {
            blocks: formatted.clone(),
            left: n,
            writes: 0,
        };
        assert!(create_file(&mut cut, &info, b"SD0001  KAS", &data).is_err());
        let marks = clean_marks(&mut cut, &info);
        assert!(
            marks.contains(&false),
            "cut after {n} of {total} writes, the card says clean"
        );
        if marks[0] {
            assert_eq!(
                contents(&mut cut, &info, b"SD0001  KAS"),
                Some(data.clone()),
                "cut after {n} of {total}: the first FAT says clean of a save not whole"
            );
        }
    }

    // The entry's other bits, as the formatter wrote them.
    let mut first = [0u8; BLOCK_SIZE];
    whole.read(info.fat_start_sector, &mut first).expect("read");
    assert_eq!(first[4..8], [0xFF, 0xFF, 0xFF, 0x0F]);

    overwrite_file(&mut whole, &info, b"SD0001  KAS", &data[..100]).expect("overwrite");
    assert_eq!(clean_marks(&mut whole, &info), [true, true]);
    delete_file(&mut whole, &info, b"SD0001  KAS").expect("delete");
    assert_eq!(clean_marks(&mut whole, &info), [true, true]);

    // More than the card holds: refused, the mark left up.
    let big = vec![0u8; 128 * 1024 * BLOCK_SIZE];
    assert!(create_file(&mut whole, &info, b"BIG     KAS", &big).is_err());
    assert_eq!(clean_marks(&mut whole, &info), [false, false]);
    create_file(&mut whole, &info, b"SD0002  KAS", b"x").expect("save");
    assert_eq!(
        clean_marks(&mut whole, &info),
        [true, true],
        "and taken down by the next"
    );
}

/// Put a raw 32-byte entry in the root's first sector, at `slot`.
fn put_entry(card: &mut RamCard, info: &Fat32Info, slot: usize, name: &[u8; 11], attr: u8) {
    let sector = info.cluster_to_sector(info.root_cluster);
    let mut buf = [0u8; BLOCK_SIZE];
    card.read(sector, &mut buf).expect("read");
    let at = slot * 32;
    buf[at..at + 32].fill(0);
    buf[at..at + 11].copy_from_slice(name);
    buf[at + 11] = attr;
    card.write(sector, &buf).expect("write");
}

/// A volume label, the card's name as a root entry with the volume
/// attribute, is not found as a file; a file of the same name after it is.
#[test]
fn a_volume_label_is_not_a_file() {
    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");

    put_entry(&mut card, &info, 0, b"KASSIGNER  ", 0x08);
    assert_eq!(
        find_file_in_root(&mut card, &info, b"KASSIGNER  ").err(),
        Some(Fat32Error::Format("File not found"))
    );

    create_file(&mut card, &info, b"KASSIGNER  ", b"file").expect("save");
    let (found, _, offset) = find_file_in_root(&mut card, &info, b"KASSIGNER  ").expect("find");
    assert_eq!((found.attr, found.file_size, offset), (0x20, 4, 32));
}

/// A name that starts with a directory marker is never written as one: a
/// first byte of `0xE5` marks an entry deleted and `0x00` ends the
/// directory. `to_83_name` writes `0xE5` as `0x05`, as FAT keeps it, and an
/// empty start as a space; a stored `0x05` is found by either spelling; a
/// save asked to write a marker is refused before it writes anything.
#[test]
fn a_name_that_starts_with_a_marker_is_never_written_as_one() {
    use kassigner_fat32::fat32::to_83_name;

    assert_eq!(
        to_83_name(&[0xE5, b'A', b'.', b'T', b'X', b'T']),
        *b"\x05A      TXT"
    );
    assert_eq!(to_83_name(b".TXT"), *b"        TXT");
    assert_eq!(to_83_name(b"ab.kas"), *b"AB      KAS", "as before");

    let mut card = Cut {
        blocks: vec![[0u8; BLOCK_SIZE]; 128 * 1024],
        left: usize::MAX,
        writes: 0,
    };
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");

    let kept = *b"\x05A      TXT";
    let meant = *b"\xE5A      TXT";
    create_file(&mut card, &info, &kept, b"e5").expect("save");
    for name in [kept, meant] {
        let (found, ..) = find_file_in_root(&mut card, &info, &name).expect("find");
        assert_eq!(found.name, kept, "stored as FAT keeps it");
    }

    let before = card.writes;
    for name in [meant, *b"\x00B      TXT"] {
        assert_eq!(
            create_file(&mut card, &info, &name, b"lost").err(),
            Some(Fat32Error::Format("Name starts with a marker"))
        );
        let entry = DirEntry {
            name,
            attr: 0x20,
            cluster_hi: 0,
            cluster_lo: 0,
            file_size: 0,
        };
        let long: Vec<u16> = "lost.txt".encode_utf16().collect();
        assert_eq!(
            write_dir_entry_with_long_name(&mut card, &info, &entry, &long),
            Err(Fat32Error::Format("Name starts with a marker"))
        );
    }
    assert_eq!(card.writes, before, "nothing written");
}

/// A long name finds room in a root full past half the directory's budget:
/// the writer counts each cluster once, as every root walk does.
#[test]
fn a_long_name_finds_room_past_half_the_directory_budget() {
    use kassigner_fat32::fat32::{write_fat_entry, MAX_DIR_SECTORS};

    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    assert_eq!(
        info.sectors_per_cluster, 1,
        "the walk below counts clusters as sectors"
    );

    // The root over `full` clusters of live entries, then one empty one: the
    // walk to it is `full` steps, past half the budget and inside it.
    let full = MAX_DIR_SECTORS / 2 + 1;
    let root = info.root_cluster;
    let mut live = [0u8; BLOCK_SIZE];
    for slot in live.chunks_exact_mut(32) {
        slot[..11].copy_from_slice(b"JUNK    BIN");
        slot[11] = 0x20;
    }
    for c in root..root + full {
        write_fat_entry(&mut card, &info, c, c + 1).expect("link");
        card.write(info.cluster_to_sector(c), &live).expect("fill");
    }
    let last = root + full;
    write_fat_entry(&mut card, &info, last, 0x0FFF_FFFF).expect("end");
    card.write(info.cluster_to_sector(last), &[0u8; BLOCK_SIZE])
        .expect("empty");

    let entry = DirEntry {
        name: *b"SIGNED~1KAS",
        attr: 0x20,
        cluster_hi: 0,
        cluster_lo: 0,
        file_size: 0,
    };
    let long: Vec<u16> = "signed-transaction-2026.kas".encode_utf16().collect();
    write_dir_entry_with_long_name(&mut card, &info, &entry, &long).expect("room past half");

    let (_, sector, _) = find_file_in_root(&mut card, &info, b"SIGNED~1KAS").expect("find");
    assert_eq!(sector, info.cluster_to_sector(last));
    assert!(names(&mut card, &info).contains(&"signed-transaction-2026.kas".to_string()));
}

/// A card in memory that counts reads, by block, and writes.
struct Counted {
    card: RamCard,
    reads: std::collections::HashMap<u32, usize>,
    writes: usize,
}

impl Counted {
    fn new(card: RamCard) -> Self {
        Self {
            card,
            reads: std::collections::HashMap::new(),
            writes: 0,
        }
    }

    /// Reads of all blocks, or of `blocks` alone.
    fn read_count(&self, blocks: Option<&[u32]>) -> usize {
        match blocks {
            None => self.reads.values().sum(),
            Some(only) => only
                .iter()
                .map(|b| self.reads.get(b).copied().unwrap_or(0))
                .sum(),
        }
    }
}

impl BlockDevice for Counted {
    fn blocks(&self) -> u32 {
        self.card.blocks()
    }
    fn read(&mut self, block: u32, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
        *self.reads.entry(block).or_insert(0) += 1;
        self.card.read(block, buf)
    }
    fn write(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
        self.writes += 1;
        self.card.write(block, data)
    }
}

/// A formatted card and its volume.
fn fresh() -> (RamCard, Fat32Info) {
    let mut card = ram(128 * 1024);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    (card, info)
}

/// A save under a name already in the root, a file's or a folder's, in
/// upper or lower case, is refused before anything is written.
#[test]
fn a_name_already_in_the_root_is_refused_before_anything_is_written() {
    let (card, info) = fresh();
    let mut card = Counted::new(card);
    create_file(&mut card, &info, b"SD0001  KAS", b"first").expect("first");
    put_entry(&mut card.card, &info, 1, b"FOLDER     ", 0x10);
    let free = free_count(&mut card.card);
    for name in [b"SD0001  KAS", b"sd0001  kas", b"FOLDER     "] {
        let writes = card.writes;
        assert_eq!(
            create_file(&mut card, &info, name, b"second").err(),
            Some(Fat32Error::Format("Name already in use")),
            "{}",
            String::from_utf8_lossy(name)
        );
        assert_eq!(card.writes, writes, "nothing written");
    }
    assert_eq!(free_count(&mut card.card), free, "no cluster claimed");
    let names = root_names(&mut card, &info);
    assert_eq!(names.iter().filter(|n| *n == b"SD0001  KAS").count(), 1);
}

/// A root that cannot be walked claims no cluster for a save: the root is
/// walked before the file's clusters are claimed. A full root that loops on
/// itself fails the save before it writes a byte, every try.
#[test]
fn a_root_that_loops_claims_no_cluster_for_a_save() {
    use kassigner_fat32::fat32::write_fat_entry;

    let (mut card, info) = fresh();
    let root = info.root_cluster;
    let mut full = [0u8; BLOCK_SIZE];
    for (i, slot) in full.chunks_exact_mut(32).enumerate() {
        slot[..11].copy_from_slice(format!("F{i:04}   TXT").as_bytes());
        slot[11] = 0x20;
    }
    for s in 0..u32::from(info.sectors_per_cluster) {
        card.write(info.cluster_to_sector(root) + s, &full)
            .expect("fill");
    }
    write_fat_entry(&mut card, &info, root, root).expect("loop");

    let free = free_count(&mut card);
    let mut card = Counted::new(card);
    for _ in 0..3 {
        assert_eq!(
            create_file(&mut card, &info, b"SD0001  KAS", &[0x5A; 700]).err(),
            Some(Fat32Error::Format("Circular FAT chain"))
        );
    }
    assert_eq!(card.writes, 0, "nothing written, on any try");
    assert_eq!(free_count(&mut card.card), free, "no cluster claimed");
}

/// A folder is not a file of its name: taken for an empty file, an
/// overwrite or a delete would leave its cluster used and named by nothing.
/// Found, written over or deleted by name, it is refused and stays as it
/// was.
#[test]
fn a_folder_is_not_taken_for_a_file() {
    use kassigner_fat32::fat32::{delete_file, overwrite_file, write_fat_entry};

    let (mut card, info) = fresh();
    let dir_cluster = info.root_cluster + 10;
    write_fat_entry(&mut card, &info, dir_cluster, 0x0FFF_FFFF).expect("claim");
    put_entry(&mut card, &info, 0, b"SD0001  KAS", 0x10);
    let root = info.cluster_to_sector(info.root_cluster);
    let mut dir = [0u8; BLOCK_SIZE];
    card.read(root, &mut dir).expect("root");
    dir[26..28].copy_from_slice(&(dir_cluster as u16).to_le_bytes());
    card.write(root, &dir).expect("point");

    let folder = Some(Fat32Error::Format("Name is a folder"));
    let mut card = Counted::new(card);
    assert_eq!(
        find_file_in_root(&mut card, &info, b"SD0001  KAS").err(),
        folder
    );
    assert_eq!(
        overwrite_file(&mut card, &info, b"SD0001  KAS", b"a backup").err(),
        folder
    );
    assert_eq!(delete_file(&mut card, &info, b"SD0001  KAS").err(), folder);
    assert_eq!(card.writes, 0, "the card as it was");
    assert_eq!(
        read_fat_entry(&mut card, &info, dir_cluster),
        Ok(0x0FFF_FFFF)
    );
}

/// A partition the table puts past the card, or on a sector with no boot
/// sector, goes on to the probes, which find the volume where they look. A
/// card that fails that read for another reason gives that error.
#[test]
fn a_partition_past_the_card_goes_on_to_the_probes() {
    /// The card, failing every read of one block.
    struct FailsAt(RamCard, u32);
    impl BlockDevice for FailsAt {
        fn blocks(&self) -> u32 {
            self.0.blocks()
        }
        fn read(&mut self, block: u32, buf: &mut [u8; BLOCK_SIZE]) -> Result<(), Error> {
            if block == self.1 {
                return Err(Error::Io);
            }
            self.0.read(block, buf)
        }
        fn write(&mut self, block: u32, data: &[u8; BLOCK_SIZE]) -> Result<(), Error> {
            self.0.write(block, data)
        }
    }

    const SECTORS: u32 = 70_000;
    const AT: u32 = 2048;
    let mut volume = ram(SECTORS as usize);
    do_format_fat32(&mut volume).expect("format");
    for named in [AT + SECTORS + 10, 100] {
        let mut card = ram((AT + SECTORS) as usize);
        let mut sector = [0u8; BLOCK_SIZE];
        for s in 0..SECTORS {
            volume.read(s, &mut sector).expect("read");
            card.write(AT + s, &sector).expect("write");
        }
        let mut mbr = [0u8; BLOCK_SIZE];
        mbr[446 + 4] = 0x0C;
        mbr[446 + 8..446 + 12].copy_from_slice(&named.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&SECTORS.to_le_bytes());
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        card.write(0, &mbr).expect("mbr");

        let info = mount_fat32(&mut card).expect("mounted through the probes");
        assert_eq!(
            info.fsinfo_sector,
            AT + 1,
            "the volume at {AT}, table naming {named}"
        );

        let mut failing = FailsAt(card, named);
        assert_eq!(
            mount_fat32(&mut failing).err(),
            Some(Fat32Error::Device(Error::Io))
        );
    }
}

/// Every entry written carries a date that exists: 1980-01-01, FAT's first
/// day, as the device has no clock; created, opened and written, by both
/// writers.
#[test]
fn every_entry_written_carries_a_date_that_exists() {
    let (mut card, info) = fresh();
    create_file(&mut card, &info, b"SD0001  KAS", b"backup").expect("save");
    let entry = DirEntry {
        name: *b"SIGNED~1KSP",
        attr: 0x20,
        cluster_hi: 0,
        cluster_lo: 0,
        file_size: 0,
    };
    let long: Vec<u16> = "signed-2026.kspt".encode_utf16().collect();
    write_dir_entry_with_long_name(&mut card, &info, &entry, &long).expect("long");
    for name in [b"SD0001  KAS", b"SIGNED~1KSP"] {
        let (_, sector, offset) = find_file_in_root(&mut card, &info, name).expect("find");
        let mut dir = [0u8; BLOCK_SIZE];
        card.read(sector, &mut dir).expect("dir");
        let e = &dir[offset..offset + 32];
        for at in [16, 18, 24] {
            assert_eq!(u16::from_le_bytes([e[at], e[at + 1]]), 0x0021, "byte {at}");
        }
        assert_eq!(&e[14..16], [0, 0], "created at midnight");
        assert_eq!(&e[22..24], [0, 0], "written at midnight");
    }
}

/// The root cursor keeps its place across reads: it gives what
/// `list_root_dir` gives, in its order, with a file read between every two
/// entries, and reads each root sector once.
#[test]
fn the_root_cursor_walks_the_root_once_and_keeps_its_place() {
    use kassigner_fat32::fat32::RootCursor;

    let (mut card, info) = fresh();
    for i in 0..200u32 {
        let name: [u8; 11] = format!("F{i:04}   KAS").as_bytes().try_into().unwrap();
        create_file(&mut card, &info, &name, format!("file {i}").as_bytes()).expect("file");
    }
    let listed = root_names(&mut card, &info);
    assert_eq!(listed.len(), 200);

    let mut card = Counted::new(card);
    let mut root = RootCursor::new(&info);
    let mut walked = Vec::new();
    while let Some(entry) = root.next(&mut card, &info).expect("next") {
        let mut buf = [0u8; BLOCK_SIZE];
        let n = read_file(&mut card, &info, &entry, &mut buf).expect("read");
        assert_eq!(&buf[..n], format!("file {}", walked.len()).as_bytes());
        walked.push(entry.name);
    }
    assert_eq!(walked, listed);
    assert!(root.next(&mut card, &info).expect("after").is_none());

    // The root's sectors: its first cluster's, and on through its chain.
    let mut sectors = Vec::new();
    let mut c = info.root_cluster;
    loop {
        for s in 0..u32::from(info.sectors_per_cluster) {
            sectors.push(info.cluster_to_sector(c) + s);
        }
        match read_fat_entry(&mut card.card, &info, c).expect("link") {
            next if next >= 0x0FFF_FFF8 => break,
            next => c = next,
        }
    }
    let used = 200usize.div_ceil(16);
    assert_eq!(
        card.read_count(Some(&sectors)),
        used,
        "each root sector read once"
    );
}

/// When a delete checks the other files' chains, a looping one is walked
/// round once, not for as many links as its size allows (32,768 here), and
/// its clusters are still kept.
#[test]
fn a_looping_chain_is_walked_round_once_while_a_delete_protects_the_rest() {
    use kassigner_fat32::fat32::{delete_file, write_fat_entry};

    let (mut card, info) = fresh();
    create_file(&mut card, &info, b"GONE    KAS", b"to be deleted").expect("gone");
    create_file(&mut card, &info, b"LOOP    BIN", b"x").expect("loop");
    // LOOP's cluster and one in another FAT sector, linked in a circle, under
    // a size of 16 MB.
    let (a, _, _) = find_file_in_root(&mut card, &info, b"LOOP    BIN").expect("find");
    let first = a.first_cluster();
    let far = first + 300;
    write_fat_entry(&mut card, &info, first, far).expect("link");
    write_fat_entry(&mut card, &info, far, first).expect("back");
    point(&mut card, &info, b"LOOP    BIN", first, 16 << 20);

    let mut card = Counted::new(card);
    delete_file(&mut card, &info, b"GONE    KAS").expect("delete");
    assert!(
        card.read_count(None) < 1_000,
        "{} reads for the delete",
        card.read_count(None)
    );
    assert_eq!(
        read_fat_entry(&mut card.card, &info, first),
        Ok(far),
        "kept"
    );
    assert_eq!(
        read_fat_entry(&mut card.card, &info, far),
        Ok(first),
        "kept"
    );
}

/// A chain of `links` clusters alternating between two runs, from `first`
/// up and from `far` up, so every link goes to another FAT sector; its end
/// marked.
fn hopping_chain(card: &mut RamCard, info: &Fat32Info, first: u32, far: u32, links: u32) {
    use kassigner_fat32::fat32::write_fat_entry;
    let at = |k: u32| {
        if k.is_multiple_of(2) {
            first + k / 2
        } else {
            far + k / 2
        }
    };
    for k in 0..links - 1 {
        write_fat_entry(card, info, at(k), at(k + 1)).expect("link");
    }
    write_fat_entry(card, info, at(links - 1), 0x0FFF_FFFF).expect("end");
}

/// A delete stops at its FAT read limit and frees nothing. A chain that
/// jumps to another FAT sector at every link costs a read a link when a
/// delete checks that no other entry names what it frees. Here a folder's
/// chain and a file's, 6,000 links each: the delete reads at most
/// [`KEEP_FAT_READS`](kassigner_fat32::fat32::KEEP_FAT_READS) FAT sectors for
/// them, still deletes, and frees none of the deleted file's clusters, their
/// owners not looked for to the end; both chains are as they were.
#[test]
fn a_delete_stops_at_its_fat_read_limit_and_frees_nothing() {
    use kassigner_fat32::fat32::{delete_file, KEEP_FAT_READS};

    let (mut card, info) = fresh();
    assert_eq!(info.sectors_per_cluster, 1, "512-byte clusters");
    let gone = create_file(&mut card, &info, b"GONE    KAS", b"to be deleted").expect("gone");
    create_file(&mut card, &info, b"LONG    BIN", b"x").expect("long");
    put_entry(&mut card, &info, 2, b"FOLDER     ", 0x10);
    hopping_chain(&mut card, &info, 10_000, 70_000, 6_000);
    hopping_chain(&mut card, &info, 20_000, 90_000, 6_000);
    let sector = info.cluster_to_sector(info.root_cluster);
    let mut dir = [0u8; BLOCK_SIZE];
    card.read(sector, &mut dir).expect("dir");
    dir[2 * 32 + 26..2 * 32 + 28].copy_from_slice(&10_000u16.to_le_bytes());
    card.write(sector, &dir).expect("folder's cluster");
    point(&mut card, &info, b"LONG    BIN", 20_000, 6_000 * 512);

    let fat_sectors: Vec<u32> = (0..info.fat_size_32)
        .map(|s| info.fat_start_sector + s)
        .collect();
    let mut card = Counted::new(card);
    delete_file(&mut card, &info, b"GONE    KAS").expect("delete");
    let reads = card.read_count(Some(&fat_sectors));
    assert!(
        reads <= KEEP_FAT_READS as usize + 4,
        "{reads} FAT reads for the delete"
    );
    let mut card = card.card;
    assert!(
        find_file_in_root(&mut card, &info, b"GONE    KAS").is_err(),
        "deleted"
    );
    assert_ne!(
        read_fat_entry(&mut card, &info, gone.first_cluster()),
        Ok(0),
        "not freed"
    );
    for (first, far) in [(10_000, 70_000), (20_000, 90_000)] {
        assert_eq!(read_fat_entry(&mut card, &info, first), Ok(far), "kept");
        assert_eq!(read_fat_entry(&mut card, &info, far), Ok(first + 1), "kept");
    }
}

/// A delete beside a large file laid out in order still frees its clusters:
/// that file's chain is 128 links a FAT sector, and its walk is well within
/// [`KEEP_FAT_READS`](kassigner_fat32::fat32::KEEP_FAT_READS).
#[test]
fn a_delete_beside_a_large_file_in_order_frees_its_clusters() {
    use kassigner_fat32::fat32::{delete_file, KEEP_FAT_READS};

    let (mut card, info) = fresh();
    let cb = info.cluster_bytes() as usize;
    let gone = create_file(&mut card, &info, b"GONE    KAS", &vec![0x6E; 3 * cb]).expect("gone");
    let gone_chain = chain_of(&mut card, &info, &gone);
    let big = create_file(&mut card, &info, b"BIG     BIN", &vec![0xB1; 60_000 * cb]).expect("big");
    let before = free_count(&mut card);

    let fat_sectors: Vec<u32> = (0..info.fat_size_32)
        .map(|s| info.fat_start_sector + s)
        .collect();
    let mut card = Counted::new(card);
    delete_file(&mut card, &info, b"GONE    KAS").expect("delete");
    let reads = card.read_count(Some(&fat_sectors));
    assert!(reads < KEEP_FAT_READS as usize / 8, "{reads} FAT reads");
    let mut card = card.card;
    for &c in &gone_chain {
        assert_eq!(read_fat_entry(&mut card, &info, c), Ok(0), "{c} freed");
    }
    assert_eq!(free_count(&mut card), before + 3);
    assert_eq!(chain_of(&mut card, &info, &big).len(), 60_000);
}

/// A file is checked against its bytes by reading it back: the same bytes
/// match, a byte changed on the card or another size does not, and a chain
/// a read refuses is that error.
#[test]
fn a_file_is_checked_against_its_bytes_by_reading_it_back() {
    use kassigner_fat32::fat32::{file_holds, write_fat_entry};

    let (mut card, info) = fresh();
    let cb = info.cluster_bytes() as usize;
    let data: Vec<u8> = (0..cb * 5 / 2).map(|i| (i * 13 + 1) as u8).collect();
    create_file(&mut card, &info, b"TX0001  KSP", &data).expect("save");
    let (entry, _, _) = find_file_in_root(&mut card, &info, b"TX0001  KSP").expect("find");
    assert_eq!(file_holds(&mut card, &info, &entry, &data), Ok(true));
    assert_eq!(
        file_holds(&mut card, &info, &entry, &data[1..]),
        Ok(false),
        "size"
    );

    // The last byte, on the card.
    let mut c = entry.first_cluster();
    c = read_fat_entry(&mut card, &info, c).expect("second");
    c = read_fat_entry(&mut card, &info, c).expect("third");
    let at = info.cluster_to_sector(c);
    let mut sector = [0u8; BLOCK_SIZE];
    card.read(at, &mut sector).expect("read");
    let last = (data.len() - 1) % cb;
    sector[last] ^= 1;
    card.write(at, &sector).expect("change");
    assert_eq!(
        file_holds(&mut card, &info, &entry, &data),
        Ok(false),
        "a byte"
    );

    // A chain cut short.
    write_fat_entry(&mut card, &info, entry.first_cluster(), 0x0FFF_FFFF).expect("cut");
    assert_eq!(
        file_holds(&mut card, &info, &entry, &data),
        Err(Fat32Error::Format("Short FAT chain"))
    );
}

/// A root at its size limit is not grown past it: the new cluster is
/// charged against the walk's budget before it is claimed, so the save
/// fails with the root and the free count as they were.
#[test]
fn a_root_at_its_size_limit_is_not_grown() {
    use kassigner_fat32::fat32::{write_fat_entry, MAX_DIR_SECTORS};

    let (mut card, info) = fresh();
    assert_eq!(info.sectors_per_cluster, 1, "clusters counted as sectors");
    let mut full = [0u8; BLOCK_SIZE];
    for slot in full.chunks_exact_mut(32) {
        slot[..11].copy_from_slice(b"JUNK    BIN");
        slot[11] = 0x20;
    }
    // The root's first cluster and `MAX_DIR_SECTORS` more, every slot taken:
    // the walk to its last is the budget exactly.
    let root = info.root_cluster;
    let last = root + MAX_DIR_SECTORS;
    for c in root..=last {
        card.write(info.cluster_to_sector(c), &full).expect("fill");
        let next = if c == last { 0x0FFF_FFFF } else { c + 1 };
        write_fat_entry(&mut card, &info, c, next).expect("link");
    }
    let free = free_count(&mut card);

    let mut card = Counted::new(card);
    assert_eq!(
        create_file(&mut card, &info, b"SD0001  KAS", b"backup").err(),
        Some(Fat32Error::Format("Directory too large"))
    );
    assert_eq!(free_count(&mut card.card), free, "no cluster claimed");
    assert_eq!(
        read_fat_entry(&mut card.card, &info, last),
        Ok(0x0FFF_FFFF),
        "the root as long as it was"
    );
}

/// A raw live entry, `name`, at `slot` of the card's `sector`.
fn put_raw(card: &mut RamCard, sector: u32, slot: usize, name: &[u8; 11]) {
    let mut buf = [0u8; BLOCK_SIZE];
    card.read(sector, &mut buf).expect("read");
    let at = slot * 32;
    buf[at..at + 32].fill(0);
    buf[at..at + 11].copy_from_slice(name);
    buf[at + 11] = 0x20;
    card.write(sector, &buf).expect("write");
}

/// The root's first cluster with live entries in its first `live` slots,
/// and the end-of-directory marker in the slot after them.
fn live_before_the_end(card: &mut RamCard, info: &Fat32Info, live: usize) -> Vec<[u8; 11]> {
    let base = info.cluster_to_sector(info.root_cluster);
    (0..live)
        .map(|i| {
            let name: [u8; 11] = format!("F{i:05}  TXT").as_bytes().try_into().unwrap();
            put_raw(card, base + (i / 16) as u32, i % 16, &name);
            name
        })
        .collect()
}

/// A save that takes the end-of-directory marker's slot puts a new marker
/// after it, so an entry left past the end stays hidden: in the same
/// sector, the cluster's next sector, or the root's next cluster. Each time
/// the root lists what it had and the new file.
#[test]
fn a_save_at_the_end_keeps_what_lies_past_it_hidden() {
    use kassigner_fat32::fat32::{allocate_cluster, write_fat_entry};
    const GHOST: [u8; 11] = *b"GHOST   TXT";
    const NEW: [u8; 11] = *b"SD0001  KAS";

    // The same sector.
    let (mut card, info) = fresh();
    let mut want = live_before_the_end(&mut card, &info, 3);
    let base = info.cluster_to_sector(info.root_cluster);
    put_raw(&mut card, base, 4, &GHOST);
    assert_eq!(
        root_names(&mut card, &info),
        want,
        "past the end, not listed"
    );
    create_file(&mut card, &info, &NEW, b"backup").expect("save");
    want.push(NEW);
    assert_eq!(root_names(&mut card, &info), want);

    // The cluster's next sector: a card of two sectors a cluster.
    let mut card = ram(140_000);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    assert_eq!(info.sectors_per_cluster, 2);
    let mut want = live_before_the_end(&mut card, &info, 15);
    let base = info.cluster_to_sector(info.root_cluster);
    put_raw(&mut card, base + 1, 0, &GHOST);
    assert_eq!(root_names(&mut card, &info), want);
    create_file(&mut card, &info, &NEW, b"backup").expect("save");
    want.push(NEW);
    assert_eq!(root_names(&mut card, &info), want);

    // The root's next cluster: one sector a cluster, and the root two
    // clusters long, the second holding the entry past the end.
    let (mut card, info) = fresh();
    assert_eq!(info.sectors_per_cluster, 1);
    let mut want = live_before_the_end(&mut card, &info, 15);
    let second = allocate_cluster(&mut card, &info, 3).expect("cluster");
    card.write(info.cluster_to_sector(second), &[0u8; BLOCK_SIZE])
        .expect("zero");
    put_raw(&mut card, info.cluster_to_sector(second), 0, &GHOST);
    write_fat_entry(&mut card, &info, info.root_cluster, second).expect("link");
    assert_eq!(root_names(&mut card, &info), want);
    create_file(&mut card, &info, &NEW, b"backup").expect("save");
    want.push(NEW);
    assert_eq!(root_names(&mut card, &info), want);
}

/// A save at the end of a root whose chain loops back to itself is refused
/// before a cluster is claimed: the new marker would go in the root's first
/// slot and end its entries.
#[test]
fn a_save_at_the_end_of_a_looping_root_is_refused() {
    use kassigner_fat32::fat32::write_fat_entry;
    let (mut card, info) = fresh();
    let want = live_before_the_end(&mut card, &info, 15);
    write_fat_entry(&mut card, &info, info.root_cluster, info.root_cluster).expect("loop");
    let free = free_count(&mut card);
    assert_eq!(
        create_file(&mut card, &info, b"SD0001  KAS", b"backup").err(),
        Some(Fat32Error::Format("Circular FAT chain"))
    );
    assert_eq!(free_count(&mut card), free, "no cluster claimed");
    let mut buf = [0u8; BLOCK_SIZE];
    card.read(info.cluster_to_sector(info.root_cluster), &mut buf)
        .expect("read");
    let first: [u8; 11] = buf[..11].try_into().unwrap();
    assert_eq!(first, want[0], "the root's first entry as it was");
    assert_eq!(buf[15 * 32], 0x00, "and its end where it was");
}

/// A long name whose set ends a sector puts the new marker at the next
/// sector's start, so an entry left there stays hidden.
#[test]
fn a_long_name_ending_a_sector_keeps_what_lies_past_it_hidden() {
    let mut card = ram(140_000);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    assert_eq!(info.sectors_per_cluster, 2);
    // Thirteen live entries, the marker in slot 13: a set of three, two
    // long-name entries and the short one, fills slots 13 to 15.
    live_before_the_end(&mut card, &info, 13);
    let base = info.cluster_to_sector(info.root_cluster);
    put_raw(&mut card, base + 1, 0, b"GHOST   TXT");
    let entry = DirEntry {
        name: *b"PHOTO~1 JPG",
        attr: 0x20,
        cluster_hi: 0,
        cluster_lo: 0,
        file_size: 0,
    };
    let long: Vec<u16> = "a-long-photo-name.jpg".encode_utf16().collect();
    write_dir_entry_with_long_name(&mut card, &info, &entry, &long).expect("write");
    let seen = names(&mut card, &info);
    assert_eq!(seen.len(), 14);
    assert_eq!(seen[13], "a-long-photo-name.jpg");
    assert!(!seen.iter().any(|n| n.contains("GHOST")), "{seen:?}");
}

/// A long name past the end goes over what lies there, and nothing left
/// there comes back. Every slot past the end-of-directory marker is free,
/// whatever it holds: a set that does not fit in the marker's sector goes
/// at the next sector's start, over the entries left there, and its new end
/// hides the rest.
#[test]
fn a_long_name_past_the_end_brings_back_nothing_left_there() {
    let mut card = ram(140_000);
    do_format_fat32(&mut card).expect("format");
    let info = mount_fat32(&mut card).expect("mount");
    assert_eq!(info.sectors_per_cluster, 2);
    // Fourteen live entries, the marker in slot 14: a set of three does not
    // fit in slots 14 and 15.
    live_before_the_end(&mut card, &info, 14);
    let base = info.cluster_to_sector(info.root_cluster);
    for (slot, name) in [
        (0, b"GHOST0  TXT"),
        (1, b"GHOST1  TXT"),
        (2, b"GHOST2  TXT"),
        (6, b"GHOST6  TXT"),
    ] {
        put_raw(&mut card, base + 1, slot, name);
    }
    assert_eq!(
        names(&mut card, &info).len(),
        14,
        "past the end, none listed"
    );
    let entry = DirEntry {
        name: *b"PHOTO~1 JPG",
        attr: 0x20,
        cluster_hi: 0,
        cluster_lo: 0,
        file_size: 0,
    };
    let long: Vec<u16> = "a-long-photo-name.jpg".encode_utf16().collect();
    write_dir_entry_with_long_name(&mut card, &info, &entry, &long).expect("write");
    let seen = names(&mut card, &info);
    assert!(!seen.iter().any(|n| n.contains("GHOST")), "{seen:?}");
    assert_eq!(seen.len(), 15);
    assert_eq!(seen[14], "a-long-photo-name.jpg");
    // At the next sector's start, and the old end's slots deleted.
    let mut buf = [0u8; BLOCK_SIZE];
    card.read(base + 1, &mut buf).expect("read");
    assert_eq!(
        &buf[2 * 32..2 * 32 + 11],
        b"PHOTO~1 JPG",
        "the short entry in slot 2"
    );
    assert_eq!(buf[3 * 32], 0x00, "the new end after it");
    card.read(base, &mut buf).expect("read");
    assert_eq!((buf[14 * 32], buf[15 * 32]), (0xE5, 0xE5));
}

/// A long name's characters outside printable ASCII each show as one
/// [`NOT_SHOWN`](kassigner_fat32::fat32::NOT_SHOWN) block, a character
/// UTF-16 writes in two included, and the 8.3 name follows, so names that
/// differ only in such characters show apart. A plain name shows as it is;
/// a long one with a block is cut to leave the 8.3 name room.
#[test]
fn a_long_name_shows_what_it_cannot_draw_as_blocks_and_its_short_name() {
    use kassigner_fat32::fat32::NOT_SHOWN;
    // Each name on a card of its own: the root's one-sector cluster has 16
    // slots, and these sets take 18.
    let shown = |short: &[u8; 11], long: &str| -> Vec<u8> {
        let (mut card, info) = fresh();
        let entry = DirEntry {
            name: *short,
            attr: 0x20,
            cluster_hi: 0,
            cluster_lo: 0,
            file_size: 0,
        };
        let long: Vec<u16> = long.encode_utf16().collect();
        write_dir_entry_with_long_name(&mut card, &info, &entry, &long).expect("write");
        let mut seen = Vec::new();
        list_root_dir_lfn(&mut card, &info, |_e, name, len| {
            seen.push(name[..len].to_vec());
            true
        })
        .expect("list");
        assert_eq!(seen.len(), 1);
        seen.remove(0)
    };
    let text = |bytes: Vec<u8>| String::from_utf8(bytes).expect("one byte a character");
    let block = NOT_SHOWN as char;

    let cafe = text(shown(b"CAFE~1  JPG", "café.jpg"));
    let cafe2 = text(shown(b"CAFE~2  JPG", "cafè.jpg"));
    assert_eq!(cafe, format!("caf{block}.jpg (CAFE~1.JPG)"));
    assert_eq!(cafe2, format!("caf{block}.jpg (CAFE~2.JPG)"));
    assert_ne!(cafe, cafe2, "two photos, two names");
    assert_eq!(
        text(shown(b"SMILE~1 JPG", "\u{1F600} smile.jpg")),
        format!("{block} smile.jpg (SMILE~1.JPG)"),
        "one character, though UTF-16 writes it in two"
    );
    assert_eq!(
        text(shown(b"TAB~1   JPG", "a\tb.jpg")),
        format!("a{block}b.jpg (TAB~1.JPG)"),
        "a control character, kept as a block, not dropped"
    );
    assert_eq!(
        text(shown(b"PLAIN~1 JPG", "plain-name.jpg")),
        "plain-name.jpg"
    );

    let wide = format!("{}é.jpg", "x".repeat(MAX_LONG_NAME - 5));
    assert_eq!(wide.chars().count(), MAX_LONG_NAME);
    let wide = shown(b"WIDE~1  JPG", &wide);
    assert_eq!(wide.len(), MAX_LONG_NAME, "cut to fit, not past");
    let wide = text(wide);
    assert!(wide.ends_with(" (WIDE~1.JPG)"), "{wide}");
    assert!(wide.starts_with("xxxx"), "{wide}");
}

/// A sector count in the 16-bit field is refused: FAT32 keeps it zero, and
/// its size in the 32-bit field.
#[test]
fn a_sector_count_in_the_16_bit_field_is_refused() {
    refused_because(
        |s| s[19..21].copy_from_slice(&1000u16.to_le_bytes()),
        "Not FAT32: sector count in the 16-bit field",
    );
}

/// A volume longer than its partition is not mounted, though the probes
/// would find it: its last clusters would be over whatever follows. As long
/// as its partition, or shorter, it mounts.
#[test]
fn a_volume_longer_than_its_partition_is_not_mounted() {
    const SECTORS: u32 = 70_000;
    const AT: u32 = 2048;
    let mut volume = ram(SECTORS as usize);
    do_format_fat32(&mut volume).expect("format");
    let mut boot = [0u8; BLOCK_SIZE];
    volume.read(0, &mut boot).expect("read");
    let size = u32::from_le_bytes(boot[32..36].try_into().unwrap());
    for (length, mounts) in [(size - 1, false), (size, true), (size + 100, true)] {
        let mut card = ram((AT + SECTORS + 100) as usize);
        let mut sector = [0u8; BLOCK_SIZE];
        for s in 0..SECTORS {
            volume.read(s, &mut sector).expect("read");
            card.write(AT + s, &sector).expect("write");
        }
        let mut mbr = [0u8; BLOCK_SIZE];
        mbr[446 + 4] = 0x0C;
        mbr[446 + 8..446 + 12].copy_from_slice(&AT.to_le_bytes());
        mbr[446 + 12..446 + 16].copy_from_slice(&length.to_le_bytes());
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        card.write(0, &mbr).expect("mbr");
        let mounted = mount_fat32(&mut card);
        if mounts {
            assert_eq!(mounted.map(|i| i.fsinfo_sector), Ok(AT + 1), "{length}");
        } else {
            assert_eq!(
                mounted.err(),
                Some(Fat32Error::Format("Volume past its partition")),
                "{length}"
            );
        }
    }
}
