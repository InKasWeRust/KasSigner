// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

// fat32_tests.rs — the FAT32 layer against an in-memory card image.
//
// `MemCard` is a `Copy` handle to a `RefCell<Vec<u8>>` of 512-byte sectors
// with read and write counters, so the tests can check not only that the
// filesystem is right but how many sectors it took to get there (the
// allocator work, N-21, is measured with the same counters). The image is
// formatted by the crate's own formatter and mounted by its own mount, so
// a test failure here is the layer disagreeing with itself.

extern crate std;
use std::cell::{Cell, RefCell};
use std::vec::Vec;
use crate::fat32::*;

#[derive(Clone, Copy)]
struct MemCard<'a> {
    img: &'a RefCell<Vec<u8>>,
    reads: &'a Cell<u32>,
    writes: &'a Cell<u32>,
    /// Every sector written, in order.
    wlog: &'a RefCell<Vec<u32>>,
}

impl BlockDevice for MemCard<'_> {
    fn read_block(self, block: u32, buf: &mut [u8; 512]) -> Result<(), &'static str> {
        let img = self.img.borrow();
        let off = block as usize * 512;
        if off + 512 > img.len() { return Err("read past end"); }
        buf.copy_from_slice(&img[off..off + 512]);
        self.reads.set(self.reads.get() + 1);
        Ok(())
    }
    fn write_block(self, block: u32, buf: &[u8; 512]) -> Result<(), &'static str> {
        let mut img = self.img.borrow_mut();
        let off = block as usize * 512;
        if off + 512 > img.len() { return Err("write past end"); }
        img[off..off + 512].copy_from_slice(buf);
        self.writes.set(self.writes.get() + 1);
        self.wlog.borrow_mut().push(block);
        Ok(())
    }
    fn read_multi(self, block: u32, out: &mut [u8], count: u32) -> Result<(), &'static str> {
        if out.len() < count as usize * 512 { return Err("buffer too small"); }
        for i in 0..count {
            let mut b = [0u8; 512];
            self.read_block(block + i, &mut b)?;
            let o = i as usize * 512;
            out[o..o + 512].copy_from_slice(&b);
        }
        Ok(())
    }
    fn write_multi(self, block: u32, data: &[u8], count: u32) -> Result<(), &'static str> {
        if data.len() < count as usize * 512 { return Err("buffer too small"); }
        for i in 0..count {
            let o = i as usize * 512;
            let mut b = [0u8; 512];
            b.copy_from_slice(&data[o..o + 512]);
            self.write_block(block + i, &b)?;
        }
        Ok(())
    }
    fn card_sectors(self) -> Result<u32, &'static str> {
        Ok((self.img.borrow().len() / 512) as u32)
    }
}

struct Image {
    img: RefCell<Vec<u8>>,
    reads: Cell<u32>,
    writes: Cell<u32>,
    wlog: RefCell<Vec<u32>>,
}

impl Image {
    fn new(sectors: usize) -> Self {
        Image { img: RefCell::new(alloc::vec![0u8; sectors * 512]), reads: Cell::new(0), writes: Cell::new(0), wlog: RefCell::new(Vec::new()) }
    }
    fn dev(&self) -> MemCard<'_> {
        MemCard { img: &self.img, reads: &self.reads, writes: &self.writes, wlog: &self.wlog }
    }
    fn reset_counters(&self) { self.reads.set(0); self.writes.set(0); self.wlog.borrow_mut().clear(); }
}

/// 64 MB, the smallest capacity `csd_plausible` believes (the drivers apply
/// that check in `card_sectors`; the formatter itself needs 65,525 clusters).
const SECTORS: usize = 131_072;

fn formatted() -> Image {
    let im = Image::new(SECTORS);
    do_format_fat32(im.dev()).expect("format");
    im.reset_counters();
    im
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31) ^ seed).collect()
}

#[test]
fn format_then_mount_agree() {
    let im = formatted();
    let fat = mount_fat32(im.dev()).expect("mount");
    let geo = derive_geometry(SECTORS as u32).unwrap();
    assert_eq!(fat.total_sectors, geo.total_sectors);
    assert_eq!(fat.sectors_per_cluster, geo.sectors_per_cluster);
    assert_eq!(fat.fat_size_32, geo.fat_size);
    assert_eq!(fat.num_fats, 2);
    assert_eq!(fat.root_cluster, 2);
    assert_eq!(fat.bytes_per_sector, 512);
    // Root cluster is EOC, clusters 0 and 1 are the media descriptor pair.
    assert!(read_fat_entry(im.dev(), &fat, 2).unwrap() >= 0x0FFF_FFF8);
    assert!(read_fat_entry(im.dev(), &fat, 3).unwrap() == 0);
    // Both FATs identical over their whole length.
    let img = im.img.borrow();
    let f1 = fat.fat_start_sector as usize * 512;
    let f2 = f1 + fat.fat_size_32 as usize * 512;
    let len = fat.fat_size_32 as usize * 512;
    assert_eq!(&img[f1..f1 + len], &img[f2..f2 + len]);
}

#[test]
fn create_find_read_roundtrip() {
    let im = formatted();
    let fat = mount_fat32(im.dev()).unwrap();
    let name = to_83_name(b"hello.txt");
    assert_eq!(&name, b"HELLO   TXT");
    let data = pattern(1234, 0x5a);
    let entry = create_file(im.dev(), &fat, &name, &data).expect("create");
    assert_eq!(entry.file_size, 1234);
    let (found, _, _) = find_file_in_root(im.dev(), &fat, &name).expect("find");
    assert_eq!(found.first_cluster(), entry.first_cluster());
    let mut out = alloc::vec![0u8; 1234];
    let n = read_file(im.dev(), &fat, &found, &mut out).expect("read");
    assert_eq!(n, 1234);
    assert_eq!(out, data);
    // Too-small buffer is an error, not a panic.
    let mut small = [0u8; 100];
    assert!(read_file(im.dev(), &fat, &found, &mut small).is_err());
}

#[test]
fn multi_cluster_file_chain_is_linked_and_freed() {
    let im = formatted();
    let fat = mount_fat32(im.dev()).unwrap();
    let cluster_bytes = fat.sectors_per_cluster as usize * 512;
    let data = pattern(cluster_bytes * 7 + 17, 0x33); // 8 clusters
    let name = to_83_name(b"BIG.BIN");
    let entry = create_file(im.dev(), &fat, &name, &data).unwrap();
    // Walk the chain: 8 clusters, ends in EOC.
    let mut c = entry.first_cluster();
    let mut hops = 1;
    loop {
        let next = read_fat_entry(im.dev(), &fat, c).unwrap();
        if next >= 0x0FFF_FFF8 { break; }
        c = next;
        hops += 1;
        assert!(hops <= 8, "chain longer than the file");
    }
    assert_eq!(hops, 8);
    let mut out = alloc::vec![0u8; data.len()];
    assert_eq!(read_file(im.dev(), &fat, &entry, &mut out).unwrap(), data.len());
    assert_eq!(out, data);
    // Delete frees every cluster and the name is gone. Batched like the
    // allocator: the 8 clusters share one FAT sector, so freeing them is 2
    // FAT writes plus 1 directory write, not 4 I/O per cluster.
    let first = entry.first_cluster();
    im.reset_counters();
    delete_file(im.dev(), &fat, &name).expect("delete");
    let dir_write = 1;
    std::println!("delete 8-cluster file: {} writes total", im.writes.get());
    assert_eq!(im.writes.get(), 2 + dir_write);
    // The directory entry is written before any FAT sector (a power loss
    // mid-delete leaks clusters rather than leaving a live entry over free
    // ones).
    let wlog = im.wlog.borrow();
    assert!(wlog[0] >= fat.data_start_sector, "first write {} is not in the root directory", wlog[0]);
    assert!(wlog[1..].iter().all(|&s| s < fat.data_start_sector), "FAT writes must follow the directory write");
    drop(wlog);
    assert!(find_file_in_root(im.dev(), &fat, &name).is_err());
    for k in 0..8 {
        assert_eq!(read_fat_entry(im.dev(), &fat, first + k).unwrap(), 0, "cluster {} not freed", first + k);
    }
}

#[test]
fn overwrite_replaces_and_list_sees_it_once() {
    let im = formatted();
    let fat = mount_fat32(im.dev()).unwrap();
    let name = to_83_name(b"NOTE.TXT");
    create_file(im.dev(), &fat, &name, &pattern(300, 1)).unwrap();
    let newer = pattern(900, 2);
    overwrite_file(im.dev(), &fat, &name, &newer).expect("overwrite");
    let mut count = 0;
    let mut size = 0;
    list_root_dir(im.dev(), &fat, |e| {
        if e.name == name { count += 1; size = e.file_size; }
        true
    }).unwrap();
    assert_eq!(count, 1, "overwrite must not leave two entries");
    assert_eq!(size, 900);
    let mut names = Vec::new();
    list_root_dir_lfn(im.dev(), &fat, |_, lfn, len| { names.push(lfn[..len].to_vec()); true }).unwrap();
    assert_eq!(names, alloc::vec![b"NOTE.TXT".to_vec()]);
}

#[test]
fn mount_through_mbr_and_reject_unsigned_mbr() {
    // A formatted superfloppy image relocated behind an MBR at LBA 2048.
    let sf = formatted();
    let fat_sf = mount_fat32(sf.dev()).unwrap();
    let im = Image::new(SECTORS + 2048);
    {
        let src = sf.img.borrow();
        let mut dst = im.img.borrow_mut();
        dst[2048 * 512..].copy_from_slice(&src[..]);
        // Partition entry 0: type 0x0C, LBA start 2048, size = SECTORS.
        let e = 0x1BE;
        dst[e + 4] = 0x0C;
        dst[e + 8..e + 12].copy_from_slice(&2048u32.to_le_bytes());
        dst[e + 12..e + 16].copy_from_slice(&(SECTORS as u32).to_le_bytes());
        dst[510] = 0x55; dst[511] = 0xAA;
    }
    let fat = mount_fat32(im.dev()).expect("mount via MBR");
    assert_eq!(fat.fat_start_sector, fat_sf.fat_start_sector + 2048);
    assert_eq!(fat.data_start_sector, fat_sf.data_start_sector + 2048);
    // Same MBR without the signature: strategy 2 must refuse it (the check the
    // Waveshare copy lacked), and with no BPB at 1 or 2048-from-sector-0
    // either, the mount fails instead of trusting an unsigned table.
    {
        let mut dst = im.img.borrow_mut();
        dst[510] = 0; dst[511] = 0;
        // Also spoil the relocated BPB so strategy 3 cannot rescue it.
        dst[2048 * 512 + 510] = 0;
    }
    let mut mbr = [0u8; 512];
    im.dev().read_block(0, &mut mbr).unwrap();
    assert_eq!(find_fat32_partition(&mbr), Err("Invalid MBR signature"));
    assert!(mount_fat32(im.dev()).is_err());
}

#[test]
fn write_count_for_seven_cluster_file() {
    // N-21. Before the batched allocator this was 26 FAT sector writes
    // (measured on this same test on 2026-08-25: `write_fat_entry` is 2
    // writes per entry and `allocate_chain` called it twice per cluster).
    // Seven clusters share one FAT sector, so the batched allocator writes
    // that sector once to FAT1 and once to FAT2.
    let im = formatted();
    let fat = mount_fat32(im.dev()).unwrap();
    let cluster_bytes = fat.sectors_per_cluster as usize * 512;
    let data = pattern(cluster_bytes * 7, 0x77);
    im.reset_counters();
    create_file(im.dev(), &fat, &to_83_name(b"SEVEN.BIN"), &data).unwrap();
    let data_writes = 7 * fat.sectors_per_cluster as u32;
    let dir_writes = 1;
    let fat_writes = im.writes.get() - data_writes - dir_writes;
    std::println!("seven-cluster file: {} writes total, {} on the FAT, {} reads", im.writes.get(), fat_writes, im.reads.get());
    assert_eq!(fat_writes, 2);
}

#[test]
fn chain_across_fat_sectors_written_high_first() {
    // 128 entries per FAT sector. A 200-cluster chain from cluster 3 spans
    // sectors 0 and 1 of the FAT: two sectors, each written to FAT1 and
    // FAT2, higher sector first, and the chain reads back intact.
    let im = formatted();
    let fat = mount_fat32(im.dev()).unwrap();
    im.reset_counters();
    let first = allocate_chain(im.dev(), &fat, 200).expect("chain");
    let fat_writes: Vec<u32> = im.wlog.borrow().iter().copied().collect();
    assert_eq!(fat_writes.len(), 4, "two sectors, two FAT copies");
    let s0 = fat.fat_start_sector;
    let f2 = fat.fat_size_32;
    assert_eq!(fat_writes, alloc::vec![s0 + 1, s0 + 1 + f2, s0, s0 + f2]);
    // Walk it.
    let mut c = first;
    for k in 0..199 {
        let next = read_fat_entry(im.dev(), &fat, c).unwrap();
        assert_eq!(next, c + 1, "link {k}");
        c = next;
    }
    assert!(read_fat_entry(im.dev(), &fat, c).unwrap() >= 0x0FFF_FFF8);
    // Both FAT copies agree.
    let img = im.img.borrow();
    let a = s0 as usize * 512;
    let b = (s0 + f2) as usize * 512;
    assert_eq!(&img[a..a + 1024], &img[b..b + 1024]);
    drop(img);
    // A second chain lands after the first (first fit) and is still one
    // write per touched sector per FAT copy.
    im.reset_counters();
    let second = allocate_chain(im.dev(), &fat, 3).unwrap();
    assert_eq!(second, first + 200);
    assert_eq!(im.writes.get(), 2);
}

#[test]
fn delete_across_fat_sectors_batches_by_sector() {
    // A 200-cluster chain spans two FAT sectors (128 entries each). Deleting
    // it is 4 FAT writes (two sectors x two FAT copies) plus the directory
    // write, whatever order the chain visits the sectors in.
    let im = formatted();
    let fat = mount_fat32(im.dev()).unwrap();
    let name = to_83_name(b"SPAN.BIN");
    let cluster_bytes = fat.sectors_per_cluster as usize * 512;
    create_file(im.dev(), &fat, &name, &pattern(cluster_bytes * 200, 0x2a)).unwrap();
    let (entry, _, _) = find_file_in_root(im.dev(), &fat, &name).unwrap();
    let first = entry.first_cluster();
    im.reset_counters();
    delete_file(im.dev(), &fat, &name).expect("delete");
    assert_eq!(im.writes.get(), 4 + 1, "two sectors x two FATs + dir entry");
    for k in 0..200u32 {
        assert_eq!(read_fat_entry(im.dev(), &fat, first + k).unwrap(), 0, "cluster {} not freed", first + k);
    }
    // Both FAT copies agree after the delete.
    let img = im.img.borrow();
    let a = fat.fat_start_sector as usize * 512;
    let b = (fat.fat_start_sector + fat.fat_size_32) as usize * 512;
    assert_eq!(&img[a..a + 1024], &img[b..b + 1024]);
}

#[test]
fn delete_terminates_on_circular_chain() {
    // N-09 property: a corrupt chain that loops back on itself must not hang
    // the delete. Build a 6-cluster file, then corrupt entry 5 to point back
    // at cluster 3 (a mid-chain cycle, the case a self-loop check misses).
    // The walk zeroes entries as it goes, so on returning to cluster 3 it
    // reads 0 and stops; every cluster it visited is free and the directory
    // entry is gone.
    let im = formatted();
    let fat = mount_fat32(im.dev()).unwrap();
    let name = to_83_name(b"LOOP.BIN");
    let cluster_bytes = fat.sectors_per_cluster as usize * 512;
    create_file(im.dev(), &fat, &name, &pattern(cluster_bytes * 6, 0x11)).unwrap();
    let (entry, _, _) = find_file_in_root(im.dev(), &fat, &name).unwrap();
    let first = entry.first_cluster();
    // Corrupt: the 6th cluster links back to the 3rd instead of EOC.
    write_fat_entry(im.dev(), &fat, first + 5, first + 2).unwrap();
    assert_eq!(read_fat_entry(im.dev(), &fat, first + 5).unwrap(), first + 2);
    im.reset_counters();
    delete_file(im.dev(), &fat, &name).expect("delete must terminate");
    // All six visited and freed; bounded I/O (one sector, two FAT copies).
    for k in 0..6 {
        assert_eq!(read_fat_entry(im.dev(), &fat, first + k).unwrap(), 0, "cluster {} not freed", first + k);
    }
    assert!(im.writes.get() <= 2 + 1, "delete wrote {} times", im.writes.get());
    assert!(find_file_in_root(im.dev(), &fat, &name).is_err());
}

#[test]
fn delete_scattered_chain_revisiting_a_sector() {
    // A chain that leaves a FAT sector and comes back: clusters in sector 0,
    // then sector 1, then sector 0 again. Each visit is one read/write per
    // FAT copy (a revisit re-reads the sector, already partly zeroed), the
    // chain still ends, and every cluster is freed.
    let im = formatted();
    let fat = mount_fat32(im.dev()).unwrap();
    // Hand-build the chain: 10 -> 11 -> 200 -> 201 -> 12 -> EOC (128 entries
    // per FAT sector, so 10..12 sit in sector 0 and 200..201 in sector 1).
    let chain = [10u32, 11, 200, 201, 12];
    for w in chain.windows(2) { write_fat_entry(im.dev(), &fat, w[0], w[1]).unwrap(); }
    write_fat_entry(im.dev(), &fat, 12, 0x0FFF_FFFF).unwrap();
    // A directory entry pointing at it: create a tiny file then repoint it.
    let name = to_83_name(b"SCAT.BIN");
    let e = create_file(im.dev(), &fat, &name, &pattern(10, 0x5)).unwrap();
    let own = e.first_cluster();
    write_fat_entry(im.dev(), &fat, own, 0).unwrap(); // release its own cluster
    let (_, dsec, doff) = find_file_in_root(im.dev(), &fat, &name).unwrap();
    let mut dbuf = [0u8; 512];
    im.dev().read_block(dsec, &mut dbuf).unwrap();
    dbuf[doff + 26..doff + 28].copy_from_slice(&(10u16).to_le_bytes());
    dbuf[doff + 20..doff + 22].copy_from_slice(&0u16.to_le_bytes());
    im.dev().write_block(dsec, &dbuf).unwrap();
    im.reset_counters();
    delete_file(im.dev(), &fat, &name).expect("delete");
    for &c in &chain {
        assert_eq!(read_fat_entry(im.dev(), &fat, c).unwrap(), 0, "cluster {c} not freed");
    }
    // Three sector visits (0, 1, 0) x two FAT copies + directory write.
    assert_eq!(im.writes.get(), 3 * 2 + 1);
}

#[test]
fn disk_full_is_an_error() {
    let im = formatted();
    let fat = mount_fat32(im.dev()).unwrap();
    let max = 2 + (fat.total_sectors - fat.data_start_sector) / fat.sectors_per_cluster as u32;
    let free = max - 3; // cluster 2 is the root
    assert!(allocate_chain(im.dev(), &fat, free + 1).is_err());
    assert!(allocate_chain(im.dev(), &fat, free).is_ok());
    assert!(allocate_chain(im.dev(), &fat, 1).is_err());
}

#[test]
fn name_helpers() {
    assert_eq!(&to_83_name(b"a.b"), b"A       B  ");
    assert_eq!(&to_83_name(b"verylongname.jpeg"), b"VERYLONGJPE");
    assert_eq!(&to_83_name(b"noext"), b"NOEXT      ");
    let mut out = [0u8; 13];
    let n = format_83_display(b"HELLO   TXT", &mut out);
    assert_eq!(&out[..n], b"HELLO.TXT");
    let n = format_83_display(b"NOEXT      ", &mut out);
    assert_eq!(&out[..n], b"NOEXT");
    assert!(csd_plausible(SECTORS as u32));
    assert!(!csd_plausible(0));
}

// ─── E31: bounded root-directory chains ─────────────────────────────
//
// The four root-directory walkers, `find_file_in_root`,
// `write_dir_entry_to_root`, `list_root_dir` and `list_root_dir_lfn`, each
// followed the chain with `next >= 0x0FFF_FFF8` as their only exit, so a FAT
// with A to B to A never terminated. These build that FAT and require every
// walker to come back.

/// Fill the root cluster with deleted entries so no walker stops on an
/// end-of-directory marker, then close the chain into a cycle of `n` clusters.
///
/// `0xE5` rather than a real entry: `DirEntry::from_bytes` returns `None` for
/// it and `list_root_dir_lfn` resets its accumulator, so the entries are inert
/// and the only thing under test is the chain walk.
fn cyclic_root(im: &Image, fat: &Fat32Info, n: u32) {
    let spc = fat.sectors_per_cluster as u32;
    for c in 0..n {
        let base = fat.cluster_to_sector(2 + c);
        let mut buf = [0u8; 512];
        for i in 0..16 { buf[i * 32] = 0xE5; }
        for s in 0..spc {
            im.dev().write_block(base + s, &buf).unwrap();
        }
    }
    // 2 -> 3 -> ... -> (2+n-1) -> 2
    for c in 0..n {
        let next = if c + 1 == n { 2 } else { 2 + c + 1 };
        write_fat_entry(im.dev(), fat, 2 + c, next).unwrap();
    }
}

#[test]
fn find_terminates_on_circular_root_chain() {
    // The finding as written. Two clusters pointing at each other.
    let im = formatted();
    let fat = mount_fat32(im.dev()).unwrap();
    cyclic_root(&im, &fat, 2);
    // `.err()` rather than `expect_err`: the Ok type here is
    // `(DirEntry, u32, usize)` and `DirEntry` is deliberately not `Debug`,
    // which `expect_err` would require. Deriving it to suit a test would put
    // formatting code in a shipped firmware type.
    assert_eq!(
        find_file_in_root(im.dev(), &fat, &to_83_name(b"NOPE.BIN")).err(),
        Some("Circular FAT chain"));
}

#[test]
fn find_terminates_on_mid_chain_root_cycle() {
    // A cycle that closes in the middle rather than at the start. The partial
    // check at `read_file_progress` compares against the current and first
    // clusters only and says in its own comment that this case passes it, so
    // it is the one that proves the bound is a real bound.
    let im = formatted();
    let fat = mount_fat32(im.dev()).unwrap();
    let spc = fat.sectors_per_cluster as u32;
    for c in 0..6u32 {
        let base = fat.cluster_to_sector(2 + c);
        let mut buf = [0u8; 512];
        for i in 0..16 { buf[i * 32] = 0xE5; }
        for s in 0..spc { im.dev().write_block(base + s, &buf).unwrap(); }
    }
    for c in 0..5u32 { write_fat_entry(im.dev(), &fat, 2 + c, 3 + c).unwrap(); }
    write_fat_entry(im.dev(), &fat, 7, 4).unwrap(); // 7 -> 4, closes mid-chain
    assert_eq!(
        find_file_in_root(im.dev(), &fat, &to_83_name(b"NOPE.BIN")).err(),
        Some("Circular FAT chain"));
}

#[test]
fn listers_terminate_on_circular_root_chain() {
    // `list_root_dir_lfn` is the one the SD picker calls, and it is not the
    // function the finding named.
    let im = formatted();
    let fat = mount_fat32(im.dev()).unwrap();
    cyclic_root(&im, &fat, 2);
    assert_eq!(list_root_dir(im.dev(), &fat, |_| true).err(),
        Some("Circular FAT chain"));
    assert_eq!(list_root_dir_lfn(im.dev(), &fat, |_, _, _| true).err(),
        Some("Circular FAT chain"));
}

#[test]
fn create_terminates_on_circular_root_chain() {
    // `write_dir_entry_to_root` has no end-of-directory exit: its only exit is
    // a free slot. A cycle with none never ended, and on a genuine end of
    // chain it allocates and extends rather than stopping. Every slot here is
    // 0xE5, which IS free, so the cycle is closed with real entries instead.
    let im = formatted();
    let fat = mount_fat32(im.dev()).unwrap();
    let spc = fat.sectors_per_cluster as u32;
    for c in 0..2u32 {
        let base = fat.cluster_to_sector(2 + c);
        let mut buf = [0u8; 512];
        for i in 0..16 {
            buf[i * 32..i * 32 + 11].copy_from_slice(b"FULL    BIN");
            buf[i * 32 + 11] = 0x20; // archive, not a free slot, not LFN
        }
        for s in 0..spc { im.dev().write_block(base + s, &buf).unwrap(); }
    }
    write_fat_entry(im.dev(), &fat, 2, 3).unwrap();
    write_fat_entry(im.dev(), &fat, 3, 2).unwrap();
    // `create_file` returns `Result<DirEntry, _>`, same reason as above.
    assert_eq!(create_file(im.dev(), &fat, &to_83_name(b"NEW.BIN"), b"x").err(),
        Some("Circular FAT chain"));
}

#[test]
fn reserved_cluster_in_root_chain_is_refused() {
    // `cluster_to_sector` guards `< 2` by returning `data_start_sector`, so a
    // chain into cluster 0 or 1 did not fault: it silently re-read cluster 2.
    // This is E28's residual, closed by the same helper.
    for bad in [0u32, 1u32] {
        let im = formatted();
        let fat = mount_fat32(im.dev()).unwrap();
        let spc = fat.sectors_per_cluster as u32;
        let base = fat.cluster_to_sector(2);
        let mut buf = [0u8; 512];
        for i in 0..16 { buf[i * 32] = 0xE5; }
        for s in 0..spc { im.dev().write_block(base + s, &buf).unwrap(); }
        write_fat_entry(im.dev(), &fat, 2, bad).unwrap();
        assert_eq!(
            find_file_in_root(im.dev(), &fat, &to_83_name(b"NOPE.BIN")).err(),
            Some("Bad FAT chain"), "cluster {}", bad);
    }
}

#[test]
fn mount_refuses_reserved_root_cluster() {
    // `root_cluster` was the one BPB field taken from the card unchecked.
    // Refused at the mount rather than guarded in four walkers.
    for bad in [0u32, 1u32] {
        let im = formatted();
        let mut boot = [0u8; 512];
        im.dev().read_block(0, &mut boot).unwrap();
        boot[44..48].copy_from_slice(&bad.to_le_bytes());
        im.dev().write_block(0, &boot).unwrap();
        // The property, not the mechanism: `mount_fat32` has MBR and probe
        // fallbacks, so what must hold is that no walker is ever handed a
        // reserved root cluster, whichever path produced the mount.
        if let Ok(fat) = mount_fat32(im.dev()) {
            assert!(fat.root_cluster >= 2,
                "mounted with root_cluster {}", fat.root_cluster);
        }
    }
    // And the untouched image still mounts, so the check is not refusing
    // everything.
    let im = formatted();
    assert!(mount_fat32(im.dev()).is_ok());
}

#[test]
fn honest_multi_cluster_root_dir_still_walks() {
    // The half that matters: a bound is only correct if it refuses nothing
    // real. Fill the root cluster with genuine entries so the next create has
    // to extend the directory, then find a file that lives past the extension.
    let im = formatted();
    let fat = mount_fat32(im.dev()).unwrap();
    let spc = fat.sectors_per_cluster as u32;
    let base = fat.cluster_to_sector(2);
    let mut buf = [0u8; 512];
    for i in 0..16 {
        buf[i * 32..i * 32 + 11].copy_from_slice(b"FILLER  BIN");
        buf[i * 32 + 11] = 0x20;
    }
    for s in 0..spc { im.dev().write_block(base + s, &buf).unwrap(); }

    let name = to_83_name(b"PAST.BIN");
    let data = pattern(300, 0x5A);
    create_file(im.dev(), &fat, &name, &data).expect("create must extend the root");
    // The root really did grow past one cluster.
    assert!(read_fat_entry(im.dev(), &fat, 2).unwrap() < 0x0FFF_FFF8,
        "root did not extend");
    // And all three readers reach it across the chain.
    let (entry, _, _) = find_file_in_root(im.dev(), &fat, &name).expect("find across chain");
    assert_eq!(entry.file_size as usize, data.len());
    let mut seen = 0u32;
    list_root_dir(im.dev(), &fat, |e| { if e.matches(&name) { seen += 1; } true }).unwrap();
    assert_eq!(seen, 1, "list_root_dir did not see it once");
    let mut seen_lfn = 0u32;
    list_root_dir_lfn(im.dev(), &fat, |e, _, _| { if e.matches(&name) { seen_lfn += 1; } true }).unwrap();
    assert_eq!(seen_lfn, 1, "list_root_dir_lfn did not see it once");
    let mut back = alloc::vec![0u8; data.len()];
    let n = read_file(im.dev(), &fat, &entry, &mut back).unwrap();
    assert_eq!(&back[..n], &data[..]);
}
