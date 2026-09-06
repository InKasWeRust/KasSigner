#!/usr/bin/env python3
"""Fail closed on oversized compiler-emitted Xtensa stack frames.

Firmware builds set ``-Z emit-stack-sizes`` so LLVM emits a linked ELF
``.stack_sizes`` section.  This checker parses ELF32 little-endian metadata
without external Python packages and enforces both a whole-image ceiling and a
stricter first-party ceiling.  It intentionally complements, rather than
replaces, the source-level stack-pressure contract.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import argparse
import struct
import sys

ELF_MAGIC = b"\x7fELF"
ELFCLASS32 = 1
ELFDATA2LSB = 1
ET_EXEC = 2
SHT_SYMTAB = 2
STT_FUNC = 2
MAX_FIRST_PARTY_FRAME = 8 * 1024
MAX_ANY_FRAME = 16 * 1024
FIRST_PARTY_TOKENS = ("kassigner_firmware", "offline_signer", "shared_signer")


@dataclass(frozen=True)
class Section:
    name: str
    offset: int
    size: int
    link: int
    entsize: int
    section_type: int


@dataclass(frozen=True)
class StackEntry:
    address: int
    size: int
    name: str


def _cstring(data: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\0", offset)
    if end < 0:
        end = len(data)
    return data[offset:end].decode("utf-8", errors="replace")


def _uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while offset < len(data) and shift <= 63:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            return value, offset
        shift += 7
    raise ValueError("truncated or oversized ULEB128 in .stack_sizes")


def _sections(blob: bytes) -> list[Section]:
    if len(blob) < 52 or blob[:4] != ELF_MAGIC:
        raise ValueError("not an ELF file")
    if blob[4] != ELFCLASS32 or blob[5] != ELFDATA2LSB:
        raise ValueError("stack budget checker requires ELF32 little-endian firmware")
    header = struct.unpack_from("<HHIIIIIHHHHHH", blob, 16)
    e_type, _, _, _, _, shoff, _, _, _, _, shentsize, shnum, shstrndx = header
    if e_type != ET_EXEC:
        raise ValueError("stack budget checker requires a fully linked executable ELF")
    if shentsize < 40 or shnum == 0 or shstrndx >= shnum:
        raise ValueError("invalid ELF section table")
    raw: list[tuple[int, ...]] = []
    for index in range(shnum):
        offset = shoff + index * shentsize
        if offset + 40 > len(blob):
            raise ValueError("truncated ELF section table")
        raw.append(struct.unpack_from("<IIIIIIIIII", blob, offset))
    shstr = raw[shstrndx]
    shstr_data = blob[shstr[4]:shstr[4] + shstr[5]]
    sections: list[Section] = []
    for item in raw:
        sections.append(Section(
            name=_cstring(shstr_data, item[0]),
            section_type=item[1],
            offset=item[4],
            size=item[5],
            link=item[6],
            entsize=item[9],
        ))
    return sections


def _function_symbols(blob: bytes, sections: list[Section]) -> dict[int, str]:
    symbols: dict[int, str] = {}
    for section in sections:
        if section.section_type != SHT_SYMTAB or section.entsize < 16:
            continue
        if section.link >= len(sections):
            raise ValueError("ELF symbol table references invalid string table")
        strings_section = sections[section.link]
        strings = blob[strings_section.offset:strings_section.offset + strings_section.size]
        data = blob[section.offset:section.offset + section.size]
        for offset in range(0, len(data) - 15, section.entsize):
            name_offset, value, _, info, _, _ = struct.unpack_from("<IIIBBH", data, offset)
            if info & 0x0F != STT_FUNC or value == 0:
                continue
            name = _cstring(strings, name_offset)
            if name:
                symbols.setdefault(value, name)
    return symbols


def read_stack_entries(path: Path) -> list[StackEntry]:
    blob = path.read_bytes()
    sections = _sections(blob)
    stack = next((section for section in sections if section.name == ".stack_sizes"), None)
    if stack is None or stack.size == 0:
        raise ValueError("ELF has no .stack_sizes metadata; build with -Z emit-stack-sizes")
    symbols = _function_symbols(blob, sections)
    data = blob[stack.offset:stack.offset + stack.size]
    entries: list[StackEntry] = []
    offset = 0
    while offset < len(data):
        if offset + 4 > len(data):
            raise ValueError("truncated function address in .stack_sizes")
        address = int.from_bytes(data[offset:offset + 4], "little")
        offset += 4
        size, offset = _uleb128(data, offset)
        entries.append(StackEntry(address, size, symbols.get(address, f"0x{address:08x}")))
    if not entries:
        raise ValueError("ELF .stack_sizes section is empty")
    return entries


def check_entries(entries: list[StackEntry]) -> list[str]:
    errors: list[str] = []
    first_party = [entry for entry in entries if any(token in entry.name for token in FIRST_PARTY_TOKENS)]
    if not first_party:
        errors.append("compiled stack metadata contains no identifiable first-party functions")
    for entry in entries:
        if entry.size > MAX_ANY_FRAME:
            errors.append(f"compiled stack frame exceeds {MAX_ANY_FRAME} bytes: {entry.name}={entry.size}")
        if entry in first_party and entry.size > MAX_FIRST_PARTY_FRAME:
            errors.append(
                f"first-party compiled stack frame exceeds {MAX_FIRST_PARTY_FRAME} bytes: "
                f"{entry.name}={entry.size}"
            )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=Path)
    args = parser.parse_args()
    try:
        entries = read_stack_entries(args.elf)
    except (OSError, ValueError) as error:
        print(f"ERROR: compiled stack budget evidence unavailable: {error}", file=sys.stderr)
        return 1
    errors = check_entries(entries)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    largest = max(entries, key=lambda entry: entry.size)
    first_party = [entry for entry in entries if any(token in entry.name for token in FIRST_PARTY_TOKENS)]
    first_largest = max(first_party, key=lambda entry: entry.size)
    print(
        "PASS: compiled stack budgets "
        f"entries={len(entries)} first-party={len(first_party)} "
        f"max-any={largest.size} max-first-party={first_largest.size}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
