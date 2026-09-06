"""Fail-closed stack/heap pressure contracts for production signer Rust."""
from __future__ import annotations

import re
from pathlib import Path

from source_contract_support import ROOT, read, require

SOURCE_ROOTS = (
    ROOT / "apps/signer-firmware/src",
    ROOT / "crates/offline-signer/src",
    ROOT / "crates/shared-signer/src",
    ROOT / "crates/signer-firmware-core/src",
)
EXCLUDED_PARTS = {"unit_tests", "workflow_tests", "qemu"}
MAX_LOCAL_FIXED_BYTES = 2_048
MAX_BY_VALUE_ARRAY_BYTES = 1_024
TYPE_BYTES = {"u8": 1, "i8": 1, "bool": 1, "u16": 2, "i16": 2, "u32": 4, "i32": 4, "u64": 8, "i64": 8}
LOCAL_ARRAY = re.compile(
    r"let\s+(?:mut\s+)?[A-Za-z_][A-Za-z0-9_]*[^=;\n]*=\s*"
    r"\[\s*(?:0x[0-9A-Fa-f_]+|[0-9_]+|true|false)(?P<ty>u8|i8|u16|i16|u32|i32|u64|i64)?"
    r"\s*;\s*(?P<count>[0-9_]+)\s*\]"
)
ARRAY_TYPE = re.compile(r"\[(?P<ty>u8|i8|bool|u16|i16|u32|i32|u64|i64)\s*;\s*(?P<count>[0-9_]+)\]")
FUNCTION = re.compile(r"\bfn\s+[A-Za-z_][A-Za-z0-9_]*\s*\((?P<params>.*?)\)\s*(?P<ret>->\s*[^\{]+)?\{", re.S)


def production_sources() -> list[Path]:
    files: list[Path] = []
    for source_root in SOURCE_ROOTS:
        for path in source_root.rglob("*.rs"):
            if EXCLUDED_PARTS.intersection(path.parts):
                continue
            files.append(path)
    return files


def array_bytes(match: re.Match[str]) -> int:
    count = int(match.group("count").replace("_", ""))
    return count * TYPE_BYTES[match.group("ty")]


def check_source_stack_pressure(errors: list[str]) -> None:
    for path in production_sources():
        source = path.read_text(encoding="utf-8", errors="ignore")
        relative = path.relative_to(ROOT)
        for match in LOCAL_ARRAY.finditer(source):
            count = int(match.group("count").replace("_", ""))
            element = TYPE_BYTES.get(match.group("ty") or "u8", 1)
            if count * element > MAX_LOCAL_FIXED_BYTES:
                errors.append(f"{relative}: local fixed array exceeds {MAX_LOCAL_FIXED_BYTES}-byte stack budget")
        for function in FUNCTION.finditer(source):
            params = function.group("params")
            for match in ARRAY_TYPE.finditer(params):
                prefix = params[max(0, match.start() - 8):match.start()]
                if "&" not in prefix and array_bytes(match) >= MAX_BY_VALUE_ARRAY_BYTES:
                    errors.append(f"{relative}: >=1KiB fixed array passed by value")
            for match in ARRAY_TYPE.finditer(function.group("ret") or ""):
                if array_bytes(match) >= MAX_BY_VALUE_ARRAY_BYTES:
                    errors.append(f"{relative}: >=1KiB fixed array returned by value")


def check_allocation_contract(errors: list[str]) -> None:
    for path in production_sources():
        source = path.read_text(encoding="utf-8", errors="ignore")
        relative = path.relative_to(ROOT)
        for token in ("alloc::vec![", "vec![", "Vec::with_capacity(", "Box::new("):
            require(errors, token not in source, f"{relative}: infallible production allocation {token}")


def check_critical_memory_shapes(errors: list[str]) -> None:
    tx = read("crates/offline-signer/src/transaction/model/transaction.rs")
    constants = read("crates/offline-signer/src/transaction/model/constants.rs")
    context = read("crates/offline-signer/src/transaction/kspt/signing/context.rs")
    stego = read("crates/signer-firmware-core/src/backup/stego_picture/mod.rs")
    codec = read("crates/signer-firmware-core/src/backup/stego_picture/codec.rs")
    frame = read("crates/signer-firmware-core/src/backup/stego_picture/frame.rs")
    psram = read("apps/signer-firmware/src/services/memory/psram.rs")
    require(errors, "SIGNER_CAPABILITIES.max_inputs as usize" in constants, "transaction input resource cap must follow the canonical signer capability")
    capabilities = (ROOT / "crates/kassigner-protocol/src/capabilities/mod.rs").read_text(errors="replace")
    require(errors, "max_inputs: 32" in capabilities, "reference signer input capability must remain 32")
    for field in ("outputs: Box<", "payload: Box<", "redeem_pool: Box<"):
        require(errors, field in tx, f"Transaction bulk store must remain heap-backed: {field}")
    require(errors, "pub fn try_new() -> Result<Self, TransactionStorageError>" in tx, "Transaction must retain typed fallible constructor")
    require(errors, "try_reserve_exact" in tx, "Transaction constructor must allocate fallibly")
    require(errors, "try_reserve_exact(1)" in context, "SigningContext cache must allocate fallibly")
    require(errors, "try_zeroed_vec" in stego and "PictureError::AllocationFailed" in stego, "stego scratch allocation must be fallible")
    require(errors, "MAX_DECODE_BLOCKS" in codec and "WorkLimitExceeded" in codec, "JPEG traversal must enforce CPU-work ceiling")
    require(errors, "Result<Box<[HuffmanTable]>, PictureError>" in frame, "JPEG Huffman banks must allocate fallibly")
    require(errors, "allocate_with_reserve" in psram and "free_bytes()" in psram, "PSRAM allocation must support explicit reserve headroom")


def check_stack_budget_contract(errors: list[str]) -> None:
    check_source_stack_pressure(errors)
    check_allocation_contract(errors)
    check_critical_memory_shapes(errors)
