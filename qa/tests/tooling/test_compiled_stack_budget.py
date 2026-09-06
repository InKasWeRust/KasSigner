from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "qa/checks/firmware"))
from compiled_stack_budget import (  # noqa: E402
    MAX_FIRST_PARTY_FRAME,
    StackEntry,
    check_entries,
    read_stack_entries,
)


def uleb(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            result.append(byte | 0x80)
        else:
            result.append(byte)
            return bytes(result)


def synthetic_elf(stack_size: int, include_stack_section: bool = True) -> bytes:
    names = [b"", b".shstrtab", b".strtab", b".symtab"]
    if include_stack_section:
        names.append(b".stack_sizes")
    shstr = b"\0" + b"\0".join(name for name in names[1:]) + b"\0"
    name_offsets = {name.decode(): shstr.index(name) for name in names[1:]}
    symbol_name = b"_ZN18kassigner_firmware12critical_path\0"
    strtab = b"\0" + symbol_name
    address = 0x4208_1000
    symtab = bytes(16) + struct.pack("<IIIBBH", 1, address, 32, 0x12, 0, 1)
    stack = address.to_bytes(4, "little") + uleb(stack_size)
    sections_data = [b"", shstr, strtab, symtab] + ([stack] if include_stack_section else [])
    offsets = []
    blob = bytearray(bytes(52))
    for data in sections_data:
        while len(blob) % 4:
            blob.append(0)
        offsets.append(len(blob))
        blob.extend(data)
    while len(blob) % 4:
        blob.append(0)
    shoff = len(blob)
    headers = [bytes(40)]
    headers.append(struct.pack("<IIIIIIIIII", name_offsets[".shstrtab"], 3, 0, 0, offsets[1], len(shstr), 0, 0, 1, 0))
    headers.append(struct.pack("<IIIIIIIIII", name_offsets[".strtab"], 3, 0, 0, offsets[2], len(strtab), 0, 0, 1, 0))
    headers.append(struct.pack("<IIIIIIIIII", name_offsets[".symtab"], 2, 0, 0, offsets[3], len(symtab), 2, 1, 4, 16))
    if include_stack_section:
        headers.append(struct.pack("<IIIIIIIIII", name_offsets[".stack_sizes"], 1, 0, 0, offsets[4], len(stack), 0, 0, 1, 0))
    for header in headers:
        blob.extend(header)
    ident = bytearray(16)
    ident[:4] = b"\x7fELF"
    ident[4] = 1
    ident[5] = 1
    blob[:16] = ident
    struct.pack_into(
        "<HHIIIIIHHHHHH", blob, 16,
        2, 94, 1, address, 0, shoff, 0, 52, 0, 0, 40, len(headers), 1,
    )
    return bytes(blob)


class CompiledStackBudgetTests(unittest.TestCase):
    def test_parses_linked_elf_stack_sizes_and_first_party_symbol(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firmware.elf"
            path.write_bytes(synthetic_elf(4096))
            entries = read_stack_entries(path)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0].size, 4096)
        self.assertIn("kassigner_firmware", entries[0].name)
        self.assertEqual(check_entries(entries), [])

    def test_first_party_oversized_frame_fails_closed(self):
        errors = check_entries([
            StackEntry(0x42081000, MAX_FIRST_PARTY_FRAME + 1, "kassigner_firmware::critical"),
        ])
        self.assertTrue(any("first-party compiled stack frame" in error for error in errors))

    def test_missing_stack_sizes_is_a_hard_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "firmware.elf"
            path.write_bytes(synthetic_elf(4096, include_stack_section=False))
            with self.assertRaisesRegex(ValueError, "no .stack_sizes"):
                read_stack_entries(path)

    def test_converged_builds_emit_and_check_stack_metadata_on_both_platforms(self):
        linux = (ROOT / "tools/build/firmware/build_with_hash.sh").read_text()
        windows = (ROOT / "tools/build/firmware/build_with_hash.ps1").read_text()
        for source in (linux, windows):
            self.assertIn("emit-stack-sizes", source)
            self.assertIn("compiled_stack_budget.py", source)


if __name__ == "__main__":
    unittest.main()
