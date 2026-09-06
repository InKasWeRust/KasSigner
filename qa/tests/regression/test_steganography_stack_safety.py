from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]


class SteganographyStackSafetyTests(unittest.TestCase):
    def test_jpeg_huffman_banks_are_heap_backed(self):
        frame = (ROOT / "crates/signer-firmware-core/src/backup/stego_picture/frame.rs").read_text()
        self.assertIn("dc_tables: Box<[HuffmanTable]>", frame)
        self.assertIn("ac_tables: Box<[HuffmanTable]>", frame)
        self.assertIn("fn empty_huffman_tables() -> Result<Box<[HuffmanTable]>, PictureError>", frame)
        self.assertIn("try_reserve_exact(4)", frame)
        self.assertNotIn("dc_tables: [HuffmanTable; 4]", frame)
        self.assertNotIn("ac_tables: [HuffmanTable; 4]", frame)

    def test_scan_parse_does_not_copy_huffman_bank_by_value(self):
        frame = (ROOT / "crates/signer-firmware-core/src/backup/stego_picture/frame.rs").read_text()
        self.assertNotIn("struct ScanContext", frame)
        self.assertNotIn("fn scan_context(&self)", frame)
        self.assertIn("state: &mut FrameParseState", frame)
        self.assertIn("core::mem::replace(&mut context.dc_tables", frame)
        self.assertIn("core::mem::replace(&mut context.ac_tables", frame)

    def test_huffman_table_is_built_in_place_without_copy_semantics(self):
        huffman = (ROOT / "crates/signer-firmware-core/src/backup/stego_picture/huffman.rs").read_text()
        frame = (ROOT / "crates/signer-firmware-core/src/backup/stego_picture/frame.rs").read_text()
        tables = (
            ROOT / "crates/signer-firmware-core/src/backup/stego_picture/frame/huffman_tables.rs"
        ).read_text()
        self.assertNotIn("#[derive(Clone, Copy)]\npub(super) struct HuffmanTable", huffman)
        self.assertIn("pub(super) fn rebuild(&mut self", huffman)
        self.assertIn("table.rebuild(", tables)
        self.assertNotIn("let table = HuffmanTable::build(", frame + tables)

    def test_capacity_window_remains_heap_backed(self):
        source = (ROOT / "crates/signer-firmware-core/src/backup/stego_picture/mod.rs").read_text()
        self.assertIn("try_zeroed_vec(rank_window as usize, 0i16)?", source)
        self.assertIn("try_zeroed_vec(bitmap_len(rank_window)?, 0u8)?", source)


if __name__ == "__main__":
    unittest.main()
