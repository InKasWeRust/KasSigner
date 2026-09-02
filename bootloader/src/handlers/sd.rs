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

// handlers/sd.rs — Touch handlers for SD backup/restore states
//
// Extracted from main.rs to reduce monolith size.
// Covers: SdBackupWarning, SdBackupPassphrase, SdFileList,
//         SdRestorePassphrase, SdXprvExportPassphrase,
//         SdXprvFileList, SdXprvImportPassphrase

use crate::log;
use crate::{app::data::AppData, hw::display, hw::sd_backup, hw::sdcard, hw::sound, hw::touch, wallet};
use crate::ui::helpers::pp_keyboard_hit;

use crate::wallet::hmac::zeroize_buf;

/// Shared state for SD backup/restore touch handlers.
fn hex_nibble(ch: u8) -> u8 {
    match ch {
        b'0'..=b'9' => ch - b'0',
        b'a'..=b'f' => ch - b'a' + 10,
        b'A'..=b'F' => ch - b'A' + 10,
        _ => 0xFF,
    }
}

/// Parse an HD multisig descriptor of the form:
///
///   `multi_hd(M,<130-hex>,<130-hex>,...,<130-hex>)`
///
/// where each participant hex = compressed pubkey (33 bytes = 66 hex)
/// immediately followed by chain code (32 bytes = 64 hex), for a total
/// of 130 hex chars. Trailing whitespace is tolerated.
///
/// Returns `(m, n, cosigner_pubkeys, cosigner_chain_codes)` on success.
///
/// The `multi_hd` function name distinguishes this format from the v1.0.x
/// `multi(...)` single-point format which was incompatible with per-address
/// HD derivation. Old `multi(...)` descriptors will fail to parse here —
/// that's intentional: v1.0.x multisigs cannot be rebuilt as HD wallets
/// because the account-level xpub (needed for child derivation) was never
/// recorded.
#[allow(clippy::type_complexity)]
/// Longest a `multi_hd(...)` descriptor can be, derived from the grammar
/// `parse_descriptor` accepts:
///
///   "multi_hd("  9
///   "M,"         2
///   N x 130 hex  (33-byte pubkey + 32-byte chain code, hex encoded)
///   N-1 commas
///   ")"          1
///
/// At MAX_MULTISIG_KEYS = 5 that is 666 bytes. Concrete sizes:
/// 2 cosigners 273, 3 cosigners 404, 4 cosigners 535, 5 cosigners 666.
///
/// This constant exists because those numbers were previously hard-coded
/// as a 400-byte accept limit, a 512-byte read buffer and a 512-byte file
/// list filter, none of which matched each other or the grammar. A 2-of-3
/// descriptor is 404 bytes: it listed, it read, and then it was rejected
/// four bytes over the accept limit as "Invalid descriptor". Only
/// 2-cosigner multisig could round-trip through SD at all.
pub(crate) const MAX_DESCRIPTOR_LEN: usize = 9
    + 2
    + crate::wallet::transaction::MAX_MULTISIG_KEYS * 130
    + (crate::wallet::transaction::MAX_MULTISIG_KEYS - 1)
    + 1;

/// Read buffer for the kpub / address / descriptor TXT import. Covers
/// MAX_DESCRIPTOR_LEN plus trailing whitespace, and is the single size
/// limit all three file-list filters use.
pub(crate) const TXT_IMPORT_BUF: usize = 1024;

/// Compile-time guard on the invariant this bug violated: the read buffer
/// must be able to hold the largest descriptor the parser will accept.
/// Raising MAX_MULTISIG_KEYS without raising TXT_IMPORT_BUF now fails the
/// build instead of silently making large descriptors unreadable.
const _: () = assert!(TXT_IMPORT_BUF >= MAX_DESCRIPTOR_LEN);

/// Largest plaintext transaction the SD path will carry.
///
/// Separate from `TXT_IMPORT_BUF` on purpose. That constant is sized
/// against `MAX_DESCRIPTOR_LEN` for kpub, address and descriptor imports,
/// and 1,024 is right for those. The KSPT path was built beside it and
/// copied the number as a bare literal in four places, which capped
/// transactions at 1,024 bytes on a device whose signing path carries
/// 8,192 and whose frame assembler holds 16,384. A saved transaction above
/// that wrote to the card correctly and was then invisible to both file
/// pickers, which reported "No .KSP files found".
///
/// Tied to `SIGNED_QR_BUF_LEN` because that is what actually bounds a
/// transaction elsewhere: anything the device can sign and display, it
/// should be able to save and reload.
pub(crate) const KSPT_IMPORT_BUF: usize = crate::app::data::SIGNED_QR_BUF_LEN;

/// Is this an encrypted KSPT container, in either format?
///
/// One predicate for the four sites that used to test `buf[3] == 0x03` by
/// hand. A fifth format goes here and nowhere else.
pub(crate) fn is_kspt_encrypted(buf: &[u8]) -> bool {
    buf.len() >= 4
        && buf[0] == b'K'
        && buf[1] == b'A'
        && buf[2] == b'S'
        && (buf[3] == 0x03 || buf[3] == crate::hw::sd_backup::KSPT_V1_MAGIC[3])
}

/// Bytes the encrypted container adds. Sized for the LARGER of the two
/// formats so one ceiling covers both: KSPT v1 (`KAS\x06`, 53) and the
/// legacy `KAS\x03` (34). Files of either kind list and read.
pub(crate) const KSPT_ENC_OVERHEAD: usize = crate::hw::sd_backup::KSPT_V1_OVERHEAD;

/// Largest KSPT file on the card, plaintext or encrypted. Both the
/// directory scan filter and the read buffer use this, so a file that
/// lists is a file that can be read.
pub(crate) const KSPT_FILE_MAX: usize = KSPT_IMPORT_BUF + KSPT_ENC_OVERHEAD;

/// The encrypted form must fit the buffer that builds it.
const _: () = assert!(KSPT_FILE_MAX >= KSPT_IMPORT_BUF + KSPT_ENC_OVERHEAD);

// The return tuple is (m, n, pubkeys, x-only keys) sized by
// MAX_MULTISIG_KEYS. A type alias would name it but not simplify it, and the
// shape is the multisig descriptor itself: two counts and two parallel key
// tables. Kept explicit so the sizes are visible at the call site.
#[allow(clippy::type_complexity)]
fn parse_descriptor(
    data: &[u8],
) -> Option<(
    u8,
    u8,
    [[u8; 33]; crate::wallet::transaction::MAX_MULTISIG_KEYS],
    [[u8; 32]; crate::wallet::transaction::MAX_MULTISIG_KEYS],
)> {
    // Trim trailing whitespace/newlines
    let mut end = data.len();
    while end > 0 && matches!(data[end - 1], b'\n' | b'\r' | b' ' | b'\t') {
        end -= 1;
    }
    let data = &data[..end];

    // Must start with "multi_hd(" and end with ")"
    let prefix = b"multi_hd(";
    if data.len() < prefix.len() + 2 || &data[..prefix.len()] != prefix {
        return None;
    }
    if data[data.len() - 1] != b')' {
        return None;
    }
    let inner = &data[prefix.len()..data.len() - 1]; // between "multi_hd(" and ")"

    // First field: M (single digit 1..=9)
    if inner.is_empty() || inner[0] < b'1' || inner[0] > b'9' {
        return None;
    }
    let m = inner[0] - b'0';
    if inner.len() < 2 || inner[1] != b',' {
        return None;
    }

    // Remaining: comma-separated 130-char hex strings (33B pubkey + 32B chain code)
    let mut cosigner_pubkeys = [[0u8; 33]; crate::wallet::transaction::MAX_MULTISIG_KEYS];
    let mut cosigner_chain_codes = [[0u8; 32]; crate::wallet::transaction::MAX_MULTISIG_KEYS];
    let mut n: u8 = 0;
    let mut pos = 2usize;
    const HEX_LEN: usize = 130; // 33 pubkey bytes + 32 chain code bytes = 65 bytes = 130 hex chars
    while pos < inner.len() {
        if (n as usize) >= crate::wallet::transaction::MAX_MULTISIG_KEYS {
            return None;
        }
        if pos + HEX_LEN > inner.len() {
            return None;
        }
        let hex_slice = &inner[pos..pos + HEX_LEN];
        // First 66 chars = compressed pubkey (33 bytes)
        for j in 0..33 {
            let hi = hex_nibble(hex_slice[j * 2]);
            let lo = hex_nibble(hex_slice[j * 2 + 1]);
            if hi == 0xFF || lo == 0xFF {
                return None;
            }
            cosigner_pubkeys[n as usize][j] = (hi << 4) | lo;
        }
        // Validate compressed pubkey prefix (must be 0x02 or 0x03)
        if cosigner_pubkeys[n as usize][0] != 0x02 && cosigner_pubkeys[n as usize][0] != 0x03 {
            return None;
        }
        // Next 64 chars = chain code (32 bytes)
        for j in 0..32 {
            let hi = hex_nibble(hex_slice[66 + j * 2]);
            let lo = hex_nibble(hex_slice[66 + j * 2 + 1]);
            if hi == 0xFF || lo == 0xFF {
                return None;
            }
            cosigner_chain_codes[n as usize][j] = (hi << 4) | lo;
        }
        n += 1;
        pos += HEX_LEN;
        if pos < inner.len() {
            if inner[pos] != b',' {
                return None;
            }
            pos += 1;
        }
    }

    if n == 0 || m > n {
        return None;
    }
    Some((m, n, cosigner_pubkeys, cosigner_chain_codes))
}

/// Longest a `multi_hd45(...)` descriptor can be.
///
///   "multi_hd45("  11
///   "M,"            2
///   N x 111         base58 kpub strings
///   N-1 commas
///   ")"             1
///
/// At MAX_MULTISIG_KEYS = 5 that is 573 bytes, inside `TXT_IMPORT_BUF`.
/// An optional `#` header line sits above this and is skipped before parsing,
/// so it does not count against the limit.
pub(crate) const MAX_DESCRIPTOR_45_LEN: usize = 11
    + 2
    + crate::wallet::transaction::MAX_MULTISIG_KEYS * KPUB_STR_LEN
    + (crate::wallet::transaction::MAX_MULTISIG_KEYS - 1)
    + 1;

/// A serialized kpub is always exactly this many base58 characters: the
/// payload is a fixed 78 bytes plus a 4-byte checksum, and the leading version
/// bytes are fixed too, so there is no length variation to allow for. The
/// sort in `parse_descriptor_45` relies on this, since equal lengths mean a
/// plain byte comparison and a string comparison agree.
pub(crate) const KPUB_STR_LEN: usize = 111;

const _: () = assert!(TXT_IMPORT_BUF >= MAX_DESCRIPTOR_45_LEN);

/// Parse a 45' HD multisig descriptor:
///
///   `multi_hd45(M,<kpub>,<kpub>,...,<kpub>)`
///
/// where each entry is a base58check kpub string of exactly `KPUB_STR_LEN`
/// characters, an ACCOUNT-level key at `m/45'/111111'/account'`.
///
/// An optional `#` header line may precede the descriptor:
///
///   `# KasSigner multisig, 45' coordinated, 2-of-3`
///
/// It is DECORATIVE. This function skips it and never reads it. The
/// `multi_hd45(` prefix is the sole authority for the scheme; if a header
/// contradicts it, the header is ignored rather than treated as an error.
/// A label must never enter the entry list, because the sort below is a byte
/// comparison and a label inside an entry would change the ordering and
/// therefore every address.
///
/// **Entries are sorted here, and the descriptor's own order is discarded.**
/// rusty-kaspa sorts the base58 STRINGS (`wallet/core/src/wallet/mod.rs:733`,
/// `sort_unstable` over `xpub_key.to_string(...)`), so descriptors arrive
/// unordered from other wallets: its own cross-implementation vector lists five
/// keys in an order that sorts to the permutation [3, 0, 2, 1, 4]. Sorting on
/// load is what makes an external descriptor work; trusting the written order
/// would silently produce a different redeem script and a different address.
///
/// The sort is a plain byte comparison, NOT case-insensitive and not
/// human-alphabetical: base58 spans digits (0x31-0x39), uppercase (0x41-0x5A)
/// and lowercase (0x61-0x7A), so `Z` sorts before `t`.
///
/// Checks applied, in order:
///   - prefix, suffix, threshold M in 1..=9
///   - every entry exactly `KPUB_STR_LEN` chars
///   - base58check, Kaspa version bytes, 78-byte payload, 02/03 pubkey prefix
///   - depth == 3, i.e. an account key. This is what catches a key exported
///     from the wrong level, which is the likeliest way a wrong key gets pasted
///   - strictly increasing after sorting, so duplicates are rejected. A
///     duplicate would make one participant's slot ambiguous
///
/// Note the caller must ALSO check that its own account key is present in the
/// returned list. That check is not here because this function has no access to
/// the seed, but it is the one that catches a 44'-vs-45' key mix-up: the
/// participant whose key is wrong is exactly the participant whose device fails
/// to find itself.
///
/// Returns `(m, n, parts)` with `parts` in sorted order, so index `i` is
/// cosigner index `i`.
#[allow(clippy::type_complexity)]
fn parse_descriptor_45(
    data: &[u8],
) -> Option<(
    u8,
    u8,
    [crate::wallet::xpub::KpubParts; crate::wallet::transaction::MAX_MULTISIG_KEYS],
)> {
    // Header handled by the shared skipper, so `looks_like_descriptor` and this
    // parser can never disagree about where the descriptor starts.
    let data = skip_header(data);

    // Trim trailing whitespace.
    let mut end = data.len();
    while end > 0 && matches!(data[end - 1], b'\n' | b'\r' | b' ' | b'\t') {
        end -= 1;
    }
    let data = &data[..end];

    let prefix = b"multi_hd45(";
    if data.len() < prefix.len() + 2 || &data[..prefix.len()] != prefix {
        return None;
    }
    if data[data.len() - 1] != b')' {
        return None;
    }
    let inner = &data[prefix.len()..data.len() - 1];

    if inner.is_empty() || inner[0] < b'1' || inner[0] > b'9' {
        return None;
    }
    let m = inner[0] - b'0';
    if inner.len() < 2 || inner[1] != b',' {
        return None;
    }

    // Collect the entry slices without decoding, so the sort sees exactly the
    // strings rusty-kaspa sorts.
    let mut entries: [&[u8]; crate::wallet::transaction::MAX_MULTISIG_KEYS] =
        [&[]; crate::wallet::transaction::MAX_MULTISIG_KEYS];
    let mut n: usize = 0;
    let mut pos = 2usize;
    while pos < inner.len() {
        if n >= crate::wallet::transaction::MAX_MULTISIG_KEYS {
            return None;
        }
        if pos + KPUB_STR_LEN > inner.len() {
            return None;
        }
        entries[n] = &inner[pos..pos + KPUB_STR_LEN];
        n += 1;
        pos += KPUB_STR_LEN;
        if pos < inner.len() {
            if inner[pos] != b',' {
                return None;
            }
            pos += 1;
        }
    }
    if n == 0 || m as usize > n {
        return None;
    }

    // Insertion sort on the raw strings. Same shape as the 44' child sort in
    // transaction.rs, different object: parents here, derived children there.
    for i in 1..n {
        let mut j = i;
        while j > 0 {
            let mut greater = false;
            for b in 0..KPUB_STR_LEN {
                if entries[j - 1][b] != entries[j][b] {
                    greater = entries[j - 1][b] > entries[j][b];
                    break;
                }
            }
            if greater {
                entries.swap(j - 1, j);
                j -= 1;
            } else {
                break;
            }
        }
    }

    // Strictly increasing after sorting: any equal pair is a duplicate key.
    for i in 1..n {
        if entries[i - 1] == entries[i] {
            return None;
        }
    }

    let zero = crate::wallet::xpub::KpubParts {
        depth: 0,
        parent_fp: [0u8; 4],
        child_num: [0u8; 4],
        chain_code: [0u8; 32],
        pubkey: [0u8; 33],
    };
    let mut parts = [zero; crate::wallet::transaction::MAX_MULTISIG_KEYS];
    for i in 0..n {
        let p = crate::wallet::xpub::parse_kpub_parts(entries[i])?;
        // Account level: m/45'/111111'/account' is three hardened steps.
        if p.depth != 3 {
            return None;
        }
        parts[i] = p;
    }

    Some((m, n as u8, parts))
}

/// Write a descriptor for `cfg` into `out`, returning the byte count.
///
/// Emits the scheme the config carries: `multi_hd45(` with base58 kpub entries
/// when `v45`, `multi_hd(` with 130-char hex entries otherwise. One writer for
/// both, so the grammar lives next to the parser that has to read it back.
///
/// With `header` set, the 45' form is preceded by a `#` line naming the scheme
/// and threshold. It is DECORATIVE: `parse_descriptor_45` skips it and never
/// reads it, and the `multi_hd45(` prefix remains the sole authority. It exists
/// so a human opening the file knows what they are looking at, and so two
/// participants comparing copies by eye have something to compare. Deliberately
/// no date and no serial: anything that varies per device would make identical
/// descriptors look different, and that comparison is a defence we rely on.
///
/// Pass `header: false` for a QR. Those 46 bytes are pure payload there, they
/// cost frames, and nothing reading a QR shows them to anyone. KasSee's parser
/// does not skip comment lines either, so a header would break it outright.
/// 44' never gets a header in either case: its readers predate the convention.
///
/// **Entries are written in the config's stored order, which for 45' is
/// already sorted** because `parse_descriptor_45` sorted them at load. Writing
/// sorted is cosmetic rather than load-bearing: every reader sorts again, since
/// a descriptor may arrive from a tool that does not sort. Never re-order here
/// on the assumption a reader will fix it.
///
/// Returns 0 if the config is empty or `out` is too small.
pub(crate) fn write_descriptor(
    cfg: &crate::wallet::transaction::MultisigConfig,
    out: &mut [u8],
    header: bool,
) -> usize {
    if cfg.m == 0 || cfg.n == 0 || cfg.m > cfg.n {
        return 0;
    }
    let n = cfg.n as usize;
    if n > crate::wallet::transaction::MAX_MULTISIG_KEYS {
        return 0;
    }
    let mut pos = 0usize;
    let put = |out: &mut [u8], pos: &mut usize, b: u8| -> bool {
        if *pos >= out.len() {
            return false;
        }
        out[*pos] = b;
        *pos += 1;
        true
    };

    if cfg.v45 {
        if header {
            for &b in b"# KasSigner multisig, 45' coordinated, " {
                if !put(out, &mut pos, b) { return 0; }
            }
            if !put(out, &mut pos, b'0' + cfg.m) { return 0; }
            for &b in b"-of-" {
                if !put(out, &mut pos, b) { return 0; }
            }
            if !put(out, &mut pos, b'0' + cfg.n) { return 0; }
            if !put(out, &mut pos, b'\n') { return 0; }
        }

        for &b in b"multi_hd45(" {
            if !put(out, &mut pos, b) { return 0; }
        }
        if !put(out, &mut pos, b'0' + cfg.m) { return 0; }
        for i in 0..n {
            if !put(out, &mut pos, b',') { return 0; }
            let parts = crate::wallet::xpub::KpubParts {
                depth: cfg.cosigner_depth[i],
                parent_fp: cfg.cosigner_parent_fp[i],
                child_num: cfg.cosigner_child_num[i],
                chain_code: cfg.cosigner_chain_codes[i],
                pubkey: cfg.cosigner_pubkeys[i],
            };
            let mut buf = [0u8; crate::wallet::xpub::KPUB_MAX_LEN];
            let len = crate::wallet::xpub::serialize_kpub_parts(&parts, &mut buf);
            if len != KPUB_STR_LEN {
                // A kpub is a fixed 78-byte payload, so its base58 form is
                // always this long. Anything else means the stored parts are
                // not an account key and the descriptor would be unreadable.
                return 0;
            }
            for &b in &buf[..len] {
                if !put(out, &mut pos, b) { return 0; }
            }
        }
        if !put(out, &mut pos, b')') { return 0; }
        return pos;
    }

    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in b"multi_hd(" {
        if !put(out, &mut pos, b) { return 0; }
    }
    if !put(out, &mut pos, b'0' + cfg.m) { return 0; }
    for i in 0..n {
        if !put(out, &mut pos, b',') { return 0; }
        for j in 0..33 {
            let v = cfg.cosigner_pubkeys[i][j];
            if !put(out, &mut pos, HEX[(v >> 4) as usize]) { return 0; }
            if !put(out, &mut pos, HEX[(v & 0x0f) as usize]) { return 0; }
        }
        for j in 0..32 {
            let v = cfg.cosigner_chain_codes[i][j];
            if !put(out, &mut pos, HEX[(v >> 4) as usize]) { return 0; }
            if !put(out, &mut pos, HEX[(v & 0x0f) as usize]) { return 0; }
        }
    }
    if !put(out, &mut pos, b')') { return 0; }
    pos
}

/// Does this look like a multisig descriptor, either scheme?
///
/// Skips a leading `#` header before testing, so a labelled descriptor is
/// still recognised. Both prefixes, because a device holds wallets of both
/// kinds and the file itself says which it is.
pub(crate) fn looks_like_descriptor(data: &[u8]) -> bool {
    let d = skip_header(data);
    d.starts_with(b"multi_hd45(") || d.starts_with(b"multi_hd(")
}

/// Skip any leading `#` comment lines and the blank space around them.
///
/// The header is DECORATIVE. Nothing downstream reads it, and the
/// `multi_hd45(` / `multi_hd(` prefix remains the sole authority for the
/// scheme: if a header contradicts the prefix, the header is ignored rather
/// than treated as an error. A label must never reach the entry list, because
/// the 45' sort is a byte comparison and a label inside an entry would change
/// the ordering and therefore every address.
pub(crate) fn skip_header(data: &[u8]) -> &[u8] {
    let mut start = 0usize;
    loop {
        while start < data.len() && matches!(data[start], b'\n' | b'\r' | b' ' | b'\t') {
            start += 1;
        }
        if start < data.len() && data[start] == b'#' {
            while start < data.len() && data[start] != b'\n' {
                start += 1;
            }
        } else {
            break;
        }
    }
    &data[start..]
}

/// Load a descriptor of either scheme into `cfg`, or leave it untouched.
///
/// One function instead of a branch at each of the four load sites, and one
/// place where a new scheme would be added. The scheme is read from the file,
/// never inferred: `multi_hd45(` sets `v45`, `multi_hd(` clears it.
///
/// **`cfg.cosigner_index` is NOT set here.** It is our own slot in the sorted
/// list, which requires deriving our account key from the loaded seed, and this
/// function has no access to it. The caller must resolve it before the config
/// is usable for displaying addresses.
///
/// That same caller-side step is what catches a 44'-vs-45' key mix-up: a kpub
/// carries nothing identifying its subtree, so a 44' key pasted into a 45'
/// wallet parses cleanly here. It fails one step later, when the participant
/// whose key is wrong finds their own account key missing from the list.
///
/// Returns false and leaves `cfg` untouched on any parse failure, so a bad
/// descriptor cannot half-load over a good one.
pub(crate) fn load_descriptor_into(
    cfg: &mut crate::wallet::transaction::MultisigConfig,
    data: &[u8],
) -> bool {
    let d = skip_header(data);

    if d.starts_with(b"multi_hd45(") {
        let (m, n, parts) = match parse_descriptor_45(d) {
            Some(v) => v,
            None => return false,
        };
        *cfg = crate::wallet::transaction::MultisigConfig::new();
        cfg.v45 = true;
        cfg.m = m;
        cfg.n = n;
        for i in 0..(n as usize) {
            cfg.cosigner_pubkeys[i] = parts[i].pubkey;
            cfg.cosigner_chain_codes[i] = parts[i].chain_code;
            cfg.cosigner_depth[i] = parts[i].depth;
            cfg.cosigner_parent_fp[i] = parts[i].parent_fp;
            cfg.cosigner_child_num[i] = parts[i].child_num;
        }
        return true;
    }

    if let Some((m, n, pubkeys, chain_codes)) = parse_descriptor(d) {
        *cfg = crate::wallet::transaction::MultisigConfig::new();
        cfg.v45 = false;
        cfg.m = m;
        cfg.n = n;
        cfg.cosigner_pubkeys = pubkeys;
        cfg.cosigner_chain_codes = chain_codes;
        return true;
    }

    false
}

/// Check if a file with the given 8.3 name exists on the SD card.
/// Returns true if the file exists, false if not found or on SD error.
fn sd_file_exists(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    name_83: &[u8; 11],
) -> bool {
    sdcard::with_sd_card(i2c, delay, |ct| {
        let fat32 = sdcard::mount_fat32(ct)?;
        sdcard::find_file_in_root(ct, &fat32, name_83)?;
        Ok(())
    }).is_ok()
}

/// Build an 8.3 filename from pp_input buffer with given 3-byte extension.
/// Uppercases the name portion for FAT32 compatibility.
pub(crate) fn build_filename_83(pp_buf: &[u8], pp_len: usize, ext: &[u8; 3]) -> [u8; 11] {
    let mut name = [b' '; 11];
    let len = pp_len.min(8);
    for j in 0..len {
        let c = pp_buf[j];
        name[j] = if c >= b'a' && c <= b'z' { c - 32 } else { c };
    }
    name[8] = ext[0];
    name[9] = ext[1];
    name[10] = ext[2];
    name
}

/// Write data to SD card, replacing any existing file with the same name.
pub(crate) fn write_file_to_sd(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    fname: &[u8; 11],
    data: &[u8],
) -> Result<(), &'static str> {
    sdcard::with_sd_card(i2c, delay, |ct| {
        let fat32 = sdcard::mount_fat32(ct)?;
        // Same rule as `sdcard::overwrite_file`: "not found" is the one
        // outcome worth ignoring, because replacing a file that is not there
        // is a create. Any other failure means the old chain or its directory
        // entry is still live, and creating on top of it leaves two entries
        // for one name over clusters neither fully owns.
        match sdcard::delete_file(ct, &fat32, fname) {
            Ok(()) => {}
            Err("File not found") => {}
            Err(e) => return Err(e),
        }
        sdcard::create_file(ct, &fat32, fname, data)?;
        Ok(())
    })
}

/// Generate a 12-byte nonce for AES-GCM.
/// Thin wrapper over the shared collector in crypto::entropy, which
/// enables RC_FAST (correct DIG_CLK8M_EN bit) and mixes SYSTIMER,
/// eFuse, WDEV RNG, and camera sensor noise via SHA-256.
/// Returns ALL ZEROS if the hardware RNG failed its continuous health tests.
///
/// Deliberate, and safe because of where it is caught. There are TWO
/// chokepoints, not one, and this comment used to claim one ([D2], corrected
/// 2026-09-02 after tracing all seven callers):
///
///   - `encrypt_v3` at `hw/sd_backup.rs:371` returns `EntropyUnavailable` on an
///     all-zero salt or nonce. FIVE callers converge there: the seed backup, the
///     xprv backup, the two stego passphrase encrypts via `encrypt_raw_v3`, and
///     the stego seed encrypt via `encrypt_backup_progress`;
///   - `kspt_v1_entropy_ok` at `hw/sd_backup.rs:206` covers the KSPT write,
///     which frames its own container and therefore never reaches `encrypt_v3`.
///     That gap was real and was closed by [E15]; the note on that function
///     says so.
///
/// The seventh caller is NOT cryptographic: `handlers/stego.rs:638` uses
/// `rnd[6]` to pick a software name from a table and to format a decoy EXIF
/// datetime. All zeros there picks index 0 and a fixed date, which is
/// harmless. Flagged because it is the one use that needs no chokepoint, and a
/// reader counting callers should not assume otherwise.
///
/// So: an all-zero return is refused on every path where it matters, and the
/// refusal lives at two places rather than at each call site.
pub(crate) fn generate_trng_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    // Failure leaves `nonce` zeroed, which `encrypt_v3` and
    // `kspt_v1_entropy_ok` both refuse. See the note above.
    let _ = crate::crypto::entropy::fill(&mut nonce);
    nonce
}

/// Fresh per-file PBKDF2 salt for a v3 container.
///
/// Never a constant, never derived from the payload. A fixed salt is what made
/// one precomputed dictionary table break every artifact this project ever
/// produced (M-01).
/// Returns ALL ZEROS if the hardware RNG failed its health tests. Caught by
/// `encrypt_v3`; see `generate_trng_nonce`.
pub(crate) fn generate_trng_salt() -> [u8; crate::hw::sd_backup::V3_SALT_SIZE] {
    let mut salt = [0u8; crate::hw::sd_backup::V3_SALT_SIZE];
    let _ = crate::crypto::entropy::fill(&mut salt);
    salt
}

/// Scan SD card for the highest auto-increment number matching a prefix+extension pattern.
/// Returns the next number (max_found + 1). Prefix is 2 bytes (e.g. "SD", "TX", "XP", "KP", "MS").
pub(crate) fn scan_auto_increment(
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    delay: &mut esp_hal::delay::Delay,
    prefix: &[u8; 2],
    ext: &[u8; 3],
) -> u32 {
    let mut max_num: u32 = 0;
    let p0 = prefix[0];
    let p1 = prefix[1];
    let e0 = ext[0];
    let e1 = ext[1];
    let e2 = ext[2];
    let scan_ok = sdcard::with_sd_card(i2c, delay, |ct| {
        let fat32 = sdcard::mount_fat32(ct)?;
        sdcard::list_root_dir(ct, &fat32, |entry| {
            if entry.name[0] == p0 && entry.name[1] == p1
                && entry.name[8] == e0 && entry.name[9] == e1 && entry.name[10] == e2
            {
                let mut n: u32 = 0;
                let mut valid = true;
                for k in 2..8usize {
                    let c = entry.name[k];
                    if c >= b'0' && c <= b'9' {
                        n = n * 10 + (c - b'0') as u32;
                    } else if c == b' ' {
                        break;
                    } else {
                        valid = false;
                        break;
                    }
                }
                if valid && n > max_num { max_num = n; }
            }
            true
        })?;
        Ok(())
    });
    if scan_ok.is_err() { max_num = 0; }
    max_num + 1
}

/// Format an auto-increment number into an 8.3 name: prefix(2) + zero-padded digits(6) + ext(3).
pub(crate) fn format_auto_name(prefix: &[u8; 2], num: u32, ext: &[u8; 3]) -> [u8; 11] {
    let mut name = [b'0'; 11];
    name[0] = prefix[0];
    name[1] = prefix[1];
    let mut val = num;
    for k in (2..8usize).rev() {
        name[k] = b'0' + (val % 10) as u8;
        val /= 10;
    }
    name[8] = ext[0];
    name[9] = ext[1];
    name[10] = ext[2];
    name
}

/// Handle touch for SD backup/restore states. Returns Some(true) for redraw.
/// Handle touch events for SD card backup/restore screens.
#[inline(never)]
#[allow(unused_assignments)]
// `sz >= V3_OVERHEAD + 1` in the v3 file-browser check: overhead plus at
// least one payload byte. See the same expression in `sd_backup::is_v3`.
#[allow(clippy::int_plus_one)]
pub fn handle_sd_touch(
    ad: &mut AppData,
    boot_display: &mut display::BootDisplay<'_>,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    _bb_card_type: &Option<sdcard::SdCardType>,
    list_zones: &[touch::TouchZone; 4],
    page_up_zone: &touch::TouchZone,
    page_down_zone: &touch::TouchZone,
    x: u16, y: u16, is_back: bool,
) -> Option<bool> {
    let mut needs_redraw = false;

    match ad.app.state {
                    crate::app::input::AppState::SdBackupWarning => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::SeedBackupMenu;
                            needs_redraw = true;
                        } else if (85..=235).contains(&x) && y >= 205 {
                            // "I understand" button → filename keyboard first
                            let next = scan_auto_increment(i2c, delay, b"SD", b"KAS");
                            let name = format_auto_name(b"SD", next, b"KAS");
                            ad.kspt_filename = name;
                            ad.pp_input.reset();
                            for j in 0..8usize {
                                if name[j] != b' ' {
                                    ad.pp_input.push_char(name[j]);
                                }
                            }
                            ad.app.state = crate::app::input::AppState::SdSeedFilename;
                            needs_redraw = true;
                        }
                    }
                    crate::app::input::AppState::SdSeedFilename => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::SeedBackupMenu;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "SEED FILENAME"); }
                                5 => { /* no space in filenames */ }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "SEED FILENAME"); }
                                6 => {
                                    // OK — build 8.3 filename, extension KAS
                                    let name_83 = build_filename_83(&ad.pp_input.buf, ad.pp_input.len, b"KAS");
                                    ad.kspt_filename = name_83;
                                    // Check if file already exists on SD
                                    if sd_file_exists(i2c, delay, &name_83) {
                                        ad.sd_overwrite_next = crate::app::input::AppState::SdBackupPassphrase;
                                        ad.sd_overwrite_back = crate::app::input::AppState::SdSeedFilename;
                                        ad.app.state = crate::app::input::AppState::SdOverwriteWarning;
                                    } else {
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdBackupPassphrase;
                                    }
                                    // The last arm still missing this. Reusing an
                                    // existing .KAS filename changed the state to
                                    // the overwrite warning but repainted nothing,
                                    // so the keyboard stayed on screen over an
                                    // active but invisible warning and OK appeared
                                    // to do nothing. The KSP and descriptor arms
                                    // were already fixed; the seed arm was not.
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::SdSigFilename => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.go_main_menu();
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "SIG FILENAME"); }
                                5 => { /* no space in filenames */ }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "SIG FILENAME"); }
                                6 => {
                                    // OK — build 8.3 filename, extension TXT
                                    let name_83 = build_filename_83(&ad.pp_input.buf, ad.pp_input.len, b"TXT");
                                    ad.kspt_filename = name_83;
                                    // Write signature hex to SD
                                    boot_display.draw_saving_screen("Saving sig...");
                                    boot_display.update_progress_bar(50);
                                    delay.delay_millis(50);
                                    // Build hex string locally
                                    let hex_chars = b"0123456789abcdef";
                                    let mut hex_buf = [0u8; 128];
                                    for i in 0..64 {
                                        hex_buf[i * 2] = hex_chars[(ad.sign_msg_sig[i] >> 4) as usize];
                                        hex_buf[i * 2 + 1] = hex_chars[(ad.sign_msg_sig[i] & 0x0f) as usize];
                                    }
                                    let sd_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        // Fail closed on a real delete error,
                                        // as `write_file_to_sd` above does.
                                        match sdcard::delete_file(ct, &fat32, &name_83) {
                                            Ok(()) => {}
                                            Err("File not found") => {}
                                            Err(e) => return Err(e),
                                        }
                                        sdcard::create_file(ct, &fat32, &name_83, &hex_buf)?;
                                        Ok(())
                                    });
                                    if sd_result.is_ok() {
                                        boot_display.draw_success_screen("Signature Saved!");
                                        sound::success(delay);
                                        delay.delay_millis(2000);
                                    } else {
                                        boot_display.draw_rejected_screen("SD write failed");
                                        sound::beep_error(delay);
                                        delay.delay_millis(1500);
                                    }
                                    ad.pp_input.reset();
                                    ad.app.go_main_menu();
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::SdBackupPassphrase => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::SeedBackupMenu;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSWORD"); }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSWORD"); }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "PASSWORD"); }
                                6 => { // OK — encrypt and write backup to SD
                                    // Show encrypting screen with progress bar
                                    boot_display.draw_saving_screen("Encrypting seed...");
                                    let pp_bytes = &ad.pp_input.buf[..ad.pp_input.len];
                                    let nonce = generate_trng_nonce();
                                    let salt = generate_trng_salt();
                                    let mut backup_buf = [0u8; sd_backup::MAX_BACKUP_SIZE];
                                    match sd_backup::encrypt_backup_progress(
                                        &ad.mnemonic_indices, ad.word_count,
                                        pp_bytes, &salt, &nonce, &mut backup_buf,
                                        &mut |done, total| {
                                            let pct = if total > 0 { (done * 50 / total) as u8 } else { 0 };
                                            boot_display.update_progress_bar(pct);
                                        },
                                    ) {
                                        Ok(backup_len) => {
                                            boot_display.update_progress_bar(50);
                                            boot_display.draw_saving_screen("Writing to SD...");
                                            boot_display.update_progress_bar(50);
                                            delay.delay_millis(50); // flush display before SD takes SPI
                                            // Use user-chosen filename from SdSeedFilename keyboard
                                            let fname = ad.kspt_filename;
                                            let write_result = write_file_to_sd(i2c, delay, &fname, &backup_buf[..backup_len]);
                                            sound::stop_ticking();
                                            match write_result {
                                                Ok(()) => {
                                                    boot_display.update_progress_bar(100);
                                                    let mut disp = [0u8; 13];
                                                    let dlen = sd_backup::format_83_display(&fname, &mut disp);
                                                    let name_str = core::str::from_utf8(&disp[..dlen]).unwrap_or("?");
                                                    log!("[SD-BACKUP] Wrote {} bytes as {}", backup_len, name_str);
                                                    boot_display.draw_success_screen("Backup Saved!");
                                                    sound::success(delay);
                                                    delay.delay_millis(3000);
                                                }
                                                Err(e) => {
                                                    log!("[SD-BACKUP] Write failed: {}", e);
                                                    boot_display.draw_rejected_screen("SD write failed");
                                                    sound::beep_error(delay);
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        }
                                        Err(_) => {
                                            sound::stop_ticking();
                                            boot_display.draw_rejected_screen("Encryption failed");
                                            sound::beep_error(delay);
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    ad.pp_input.reset();
                                    ad.app.state = crate::app::input::AppState::SeedList;
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::SdFileList => {
                        if is_back {
                            ad.sd_file_scroll = 0;
                            ad.app.state = crate::app::input::AppState::SdImportMenu;
                            needs_redraw = true;
                        } else {
                            let max_vis: usize = 4;
                            let scroll_off = ad.sd_file_scroll as usize;
                            let can_page_up = scroll_off > 0;
                            let can_page_down = (scroll_off + max_vis) < ad.sd_file_count as usize;

                            // Left arrow — page up
                            if x < 40 && y >= 42 && can_page_up {
                                if ad.sd_file_scroll >= max_vis as u8 {
                                    ad.sd_file_scroll -= max_vis as u8;
                                } else {
                                    ad.sd_file_scroll = 0;
                                }
                                needs_redraw = true;
                            }
                            // Right arrow — page down
                            else if x >= 280 && y >= 42 && can_page_down {
                                ad.sd_file_scroll += max_vis as u8;
                                needs_redraw = true;
                            } else {
                            let mut tapped: Option<usize> = None;
                            let mut tapped_delete = false;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let idx = slot as usize + scroll_off;
                                    if idx < (ad.sd_file_count) as usize {
                                        tapped = Some(idx);
                                        // Right 40px of card = delete zone
                                        tapped_delete = x > 228;
                                    }
                                    break;
                                }
                            }
                            if let Some(i) = tapped {
                                    needs_redraw = true;
                                    ad.sd_selected_file = ad.sd_file_list[i];
                                    if tapped_delete {
                                        // Show delete confirmation
                                        ad.app.state = crate::app::input::AppState::SdDeleteConfirm;
                                    } else {
                                    // Read first bytes to auto-detect format
                                    boot_display.draw_loading_screen("Loading...");
                                    let peek_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &ad.sd_selected_file)?;
                                        // Heap, not stack: this array is RETURNED
                                        // from the closure, so as `[u8; 1024]` it
                                        // occupied a slot in both this frame and
                                        // handle_sd_touch's for the whole function.
                                        let mut buf = alloc::vec![0u8; 1024];
                                        let n = sdcard::read_file(ct, &fat32, &entry, &mut buf[..])?;
                                        Ok((buf, n))
                                    });
                                    match peek_result {
                                        Ok((buf, n)) => {
                                            // Trim trailing whitespace/newlines
                                            let mut len = n;
                                            while len > 0 && (buf[len-1] == b'\n' || buf[len-1] == b'\r' || buf[len-1] == b' ' || buf[len-1] == 0) {
                                                len -= 1;
                                            }

                                            if len >= 4 && buf[0] == b'C' && buf[1] == b'O' && buf[2] == b'V' && (buf[3] == b'B' || buf[3] == b'I') {
                                                // Covenant backup/invite — display as QR
                                                ad.signed_qr_buf[..len].copy_from_slice(&buf[..len]);
                                                ad.signed_qr_len = len;

                                                if len <= 134 {
                                                    // Single frame: fits in V6
                                                    boot_display.draw_qr_fullscreen(&ad.signed_qr_buf[..len], "Cov");
                                                    delay.delay_millis(500);
                                                    loop {
                                                        delay.delay_millis(50);
                                                        #[cfg(feature = "waveshare")]
                                                        {
                                                            let mut _tc = true;
                                                            let (ts, _) = crate::hw::touch::read_touch_full(i2c, &mut _tc);
                                                            if !matches!(ts, crate::hw::touch::TouchState::NoTouch) { break; }
                                                        }
                                                        #[cfg(feature = "m5stack")]
                                                        {
                                                            let ts = crate::hw::touch::read_touch(i2c);
                                                            if !matches!(ts, crate::hw::touch::TouchState::NoTouch) { break; }
                                                        }
                                                    }
                                                } else {
                                                    // Multi-frame: split into chunks of 100 bytes max
                                                    // Wire: [frame_idx:1][total:1][frag_len:1][payload]
                                                    let max_frag: usize = 100;
                                                    let n_frames = (len + max_frag - 1) / max_frag;
                                                    let balanced = (len + n_frames - 1) / n_frames;
                                                    let mut frame: usize = 0;
                                                    let mut _tick: u32 = 0;
                                                    boot_display.clear_screen();
                                                    loop {
                                                        // Draw current frame
                                                        let offset = frame * balanced;
                                                        let remaining = len.saturating_sub(offset);
                                                        let frag_len = remaining.min(balanced);
                                                        let mut fb = [0u8; 134];
                                                        fb[0] = frame as u8;
                                                        fb[1] = n_frames as u8;
                                                        fb[2] = frag_len as u8;
                                                        fb[3..3 + frag_len].copy_from_slice(&ad.signed_qr_buf[offset..offset + frag_len]);
                                                        let qr_len = 3 + frag_len.max(20);

                                                        // Blink-free: draw white quiet-zone over old QR, then dark modules
                                                        if let Ok(qr) = crate::qr::encoder::encode(&fb[..qr_len]) {
                                                            use embedded_graphics::prelude::*;
                                                            use embedded_graphics::primitives::*;
                                                            use crate::hw::display::*;

                                                            let qr_size = qr.size as i32;
                                                            let max_px = 232i32;
                                                            let scale = (max_px / qr_size).max(1);
                                                            let total_qr = qr_size * scale;
                                                            let ox = (320i32 - total_qr) / 2;
                                                            let oy = (240i32 - total_qr) / 2;

                                                            // White background over QR area
                                                            Rectangle::new(
                                                                Point::new(ox - 4, oy - 4),
                                                                Size::new((total_qr + 8) as u32, (total_qr + 8) as u32),
                                                            ).into_styled(PrimitiveStyle::with_fill(COLOR_TEXT))
                                                                .draw(&mut boot_display.display).ok();

                                                            // Dark modules
                                                            for my in 0..qr_size {
                                                                for mx in 0..qr_size {
                                                                    if qr.get(mx as u8, my as u8) {
                                                                        Rectangle::new(
                                                                            Point::new(ox + mx * scale, oy + my * scale),
                                                                            Size::new(scale as u32, scale as u32),
                                                                        ).into_styled(PrimitiveStyle::with_fill(COLOR_BG))
                                                                            .draw(&mut boot_display.display).ok();
                                                                    }
                                                                }
                                                            }
                                                        }

                                                        // Wait ~3s per frame, check for touch to exit
                                                        let mut exit = false;
                                                        for _ in 0..6u16 { // 6 * 50ms = 300ms
                                                            delay.delay_millis(50);
                                                            #[cfg(feature = "waveshare")]
                                                            {
                                                                let mut _tc = true;
                                                                let (ts, _) = crate::hw::touch::read_touch_full(i2c, &mut _tc);
                                                                if !matches!(ts, crate::hw::touch::TouchState::NoTouch) { exit = true; break; }
                                                            }
                                                            #[cfg(feature = "m5stack")]
                                                            {
                                                                let ts = crate::hw::touch::read_touch(i2c);
                                                                if !matches!(ts, crate::hw::touch::TouchState::NoTouch) { exit = true; break; }
                                                            }
                                                        }
                                                        if exit { break; }
                                                        frame = (frame + 1) % n_frames;
                                                        _tick += 1;
                                                    }
                                                }
                                                needs_redraw = true;
                                            } else if len >= 6 && buf[0] == b'K' && buf[1] == b'A' && buf[2] == b'S' && buf[3] == 0x04 {
                                                // v3 container. The purpose byte says which
                                                // secret it holds, so one magic serves all of
                                                // them and the routing is explicit rather than
                                                // inferred from the file size.
                                                ad.pp_input.reset();
                                                match buf[5] {
                                                    sd_backup::PURPOSE_SEED => {
                                                        ad.app.state = crate::app::input::AppState::SdRestorePassphrase;
                                                    }
                                                    sd_backup::PURPOSE_XPRV => {
                                                        ad.app.state = crate::app::input::AppState::SdXprvImportPassphrase;
                                                    }
                                                    _ => {
                                                        boot_display.draw_rejected_screen("Unsupported file");
                                                        delay.delay_millis(1500);
                                                        needs_redraw = true;
                                                    }
                                                }
                                            } else if len >= 4 && buf[0] == b'K' && buf[1] == b'A' && buf[2] == b'S' && buf[3] == 0x01 {
                                                // Legacy seed backup (KAS\x01) — use original n, not trimmed
                                                ad.pp_input.reset();
                                                ad.app.state = crate::app::input::AppState::SdRestorePassphrase;
                                            } else if len >= 4 && buf[0] == b'K' && buf[1] == b'A' && buf[2] == b'S' && buf[3] == 0x02 {
                                                // Legacy xprv backup (KAS\x02)
                                                ad.pp_input.reset();
                                                ad.app.state = crate::app::input::AppState::SdXprvImportPassphrase;
                                            } else if len >= 4 && buf[0] == b'x' && buf[1] == b'p' && buf[2] == b'r' && buf[3] == b'v' {
                                            // Plain text xprv string
                                            match wallet::xpub::import_xprv(&buf[..len]) {
                                                Ok(acct_key) => {
                                                    boot_display.draw_loading_screen("Importing xprv...");
                                                    let raw = acct_key.to_raw();
                                                    ad.acct_key_raw.copy_from_slice(&raw);
                                                    // Derive pubkeys
                                                    let acct = wallet::bip32::ExtendedPrivKey::from_raw(&raw);
                                                    for idx in 0..20u16 {
                                                        if let Ok(ak) = wallet::bip32::derive_address_key(&acct, idx) {
                                                            if let Ok(pk) = ak.public_key_x_only() {
                                                                ad.pubkey_cache[idx as usize].copy_from_slice(&pk);
                                                            }
                                                        }
                                                    }
                                                    // Derive change pubkeys (m/44'/111111'/0'/1/{0..4})
                                                    crate::app::signing::derive_change_pubkeys(
                                                        &raw, &mut ad.change_pubkey_cache);
                                                    // Store in slot
                                                    use sha2::{Sha256, Digest};
                                                    let hash = Sha256::digest(acct_key.private_key_bytes());
                                                    let fp = [hash[0], hash[1], hash[2], hash[3]];
                                                    if let Some(slot_idx) = ad.seed_mgr.find_by_fingerprint(&fp, 2).or_else(|| ad.seed_mgr.find_free()) {
                                                        let slot = &mut ad.seed_mgr.slots[slot_idx];
                                                        if slot.is_empty() {
                                                            // One constructor rather than
                                                            // packing the layout by hand
                                                            // at each site (H-08).
                                                            let mut key = [0u8; 32];
                                                            key.copy_from_slice(&raw[..32]);
                                                            let mut cc = [0u8; 32];
                                                            cc.copy_from_slice(&raw[32..64]);
                                                            slot.set_xprv(&key, &cc, raw[64]);
                                                            slot.fingerprint = fp;
                                                        }
                                                        ad.seed_mgr.activate(slot_idx);
                                                        (ad.seed_loaded) = true;
                                                        (ad.pubkeys_cached) = true;
                                                        (ad.current_addr_index) = 0;
                                                        (ad.extra_pubkey_index) = 0xFFFF;
                                                        ad.word_count = 2;
                                                        log!("[SD-IMPORT] Plain xprv imported to slot {}", slot_idx);
                                                        boot_display.draw_saving_screen("XPrv imported!");
                                                        delay.delay_millis(2000);
                                                        ad.app.state = crate::app::input::AppState::SeedList;
                                                    } else {
                                                        boot_display.draw_rejected_screen("All 4 slots full!");
                                                        delay.delay_millis(2000);
                                                    }
                                                }
                                                Err(_) => {
                                                    boot_display.draw_rejected_screen("Invalid xprv");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                            } else if len == 64 {
                                                // Possibly plain hex private key (64 chars)
                                                let mut key = [0u8; 32];
                                                let mut valid = true;
                                                for j in 0..32 {
                                                    let hi = hex_nibble(buf[j * 2]);
                                                    let lo = hex_nibble(buf[j * 2 + 1]);
                                                    if hi == 0xFF || lo == 0xFF { valid = false; break; }
                                                    key[j] = (hi << 4) | lo;
                                                }
                                                if valid {
                                                    if let Ok(pk) = wallet::bip32::pubkey_from_raw_key(&key) {
                                                        if let Some(slot_idx) = ad.seed_mgr.store_raw_key(&key) {
                                                            ad.seed_mgr.activate(slot_idx);
                                                            (ad.seed_loaded) = true;
                                                            (ad.current_addr_index) = 0;
                                                            (ad.extra_pubkey_index) = 0xFFFF;
                                                            ad.pubkey_cache[0].copy_from_slice(&pk);
                                                            (ad.pubkeys_cached) = true;
                                                            ad.word_count = 1;
                                                            log!("[SD-IMPORT] Plain hex key imported to slot {}", slot_idx);
                                                            boot_display.draw_saving_screen("Key imported!");
                                                            sound::success(delay);
                                                            delay.delay_millis(1500);
                                                        } else {
                                                            boot_display.draw_rejected_screen("All 4 slots full!");
                                                            delay.delay_millis(2000);
                                                        }
                                                    } else {
                                                        boot_display.draw_rejected_screen("Invalid key");
                                                        delay.delay_millis(2000);
                                                    }
                                                } else {
                                                    boot_display.draw_rejected_screen("Not a valid key file");
                                                    delay.delay_millis(2000);
                                                }
                                                for b in key.iter_mut() {
                                                    unsafe { core::ptr::write_volatile(b, 0); }
                                                }
                                            } else {
                                                boot_display.draw_rejected_screen("Unknown file format");
                                                delay.delay_millis(2000);
                                            }
                                        }
                                        Err(e) => {
                                            log!("[SD-IMPORT] Read error: {}", e);
                                            boot_display.draw_rejected_screen("Read error");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    } // close else (import path)
                                    }
                        }
                        } // close page-up/down/tap else
                    }
                    crate::app::input::AppState::SdDeleteConfirm => {
                        // Caller sets ad.sd_delete_return before routing here.
                        // Legacy fallback: if the caller didn't set it (still default
                        // MainMenu), derive from filename like before so the seed-backup
                        // and KSPT file-list paths keep working without modification.
                        let return_state = if ad.sd_delete_return != crate::app::input::AppState::MainMenu {
                            ad.sd_delete_return
                        } else {
                            let is_ksp = ad.sd_selected_file[8] == b'K'
                                && ad.sd_selected_file[9] == b'S'
                                && ad.sd_selected_file[10] == b'P';
                            if is_ksp {
                                crate::app::input::AppState::SdKsptFileList
                            } else {
                                crate::app::input::AppState::SdFileList
                            }
                        };
                        // Consume: reset so a stale value doesn't leak to a future delete
                        ad.sd_delete_return = crate::app::input::AppState::MainMenu;
                        if is_back {
                            ad.app.state = return_state;
                            needs_redraw = true;
                        } else if (180..=230).contains(&y) {
                            if (30..=150).contains(&x) {
                                // CANCEL
                                ad.app.state = return_state;
                                sound::click(delay);
                                needs_redraw = true;
                            } else if (170..=290).contains(&x) {
                                // DELETE — hold-to-confirm (4 seconds)
                                // Wait for finger release first
                                loop {
                                    delay.delay_millis(30);
                                    let ts = crate::hw::touch::read_touch(i2c);
                                    match ts {
                                        crate::hw::touch::TouchState::NoTouch => break,
                                        _ => {}
                                    }
                                }
                                delay.delay_millis(100);

                                // Redraw button as "HOLD 4s" prompt
                                {
                                    use embedded_graphics::primitives::{Rectangle, RoundedRectangle, CornerRadii, PrimitiveStyle};
                                    use embedded_graphics::prelude::*;
                                    use crate::hw::display::*;
                                    let btn_corner = CornerRadii::new(Size::new(8, 8));
                                    let del_rect = Rectangle::new(Point::new(170, 185), Size::new(120, 40));
                                    RoundedRectangle::new(del_rect, btn_corner)
                                        .into_styled(PrimitiveStyle::with_fill(COLOR_RED_BTN))
                                        .draw(&mut boot_display.display).ok();
                                    let dw = measure_title("HOLD 4s");
                                    draw_lato_title(&mut boot_display.display, "HOLD 4s", 170 + (120 - dw) / 2, 212, COLOR_TEXT);
                                }

                                let mut held_ms: u32 = 0;
                                let mut confirmed = false;
                                let mut waiting_for_press = true;
                                loop {
                                    delay.delay_millis(50);
                                    let ts = crate::hw::touch::read_touch(i2c);
                                    match ts {
                                        crate::hw::touch::TouchState::One(pt) => {
                                            if pt.x <= 40 && pt.y <= 40 { break; } // back = cancel
                                            // CANCEL button zone
                                            if pt.x >= 30 && pt.x <= 150 && pt.y >= 180 && pt.y <= 230 { sound::click(delay); break; }
                                            if pt.x >= 170 && pt.x <= 290 && pt.y >= 180 && pt.y <= 230 {
                                                waiting_for_press = false;
                                                held_ms += 50;
                                                let fill = (held_ms * 120 / 4000).min(120);
                                                if fill > 0 {
                                                    use embedded_graphics::primitives::{Rectangle, PrimitiveStyle};
                                                    use embedded_graphics::prelude::*;
                                                    Rectangle::new(
                                                        embedded_graphics::geometry::Point::new(170, 190),
                                                        embedded_graphics::geometry::Size::new(fill, 30))
                                                        .into_styled(PrimitiveStyle::with_fill(
                                                            embedded_graphics::pixelcolor::Rgb565::new(0b11111, 0, 0)))
                                                        .draw(&mut boot_display.display).ok();
                                                }
                                                if held_ms >= 4000 {
                                                    confirmed = true;
                                                    break;
                                                }
                                            } else if !waiting_for_press {
                                                break; // moved off button = cancel
                                            }
                                        }
                                        _ => {
                                            if !waiting_for_press { break; } // released = cancel
                                        }
                                    }
                                }

                                if confirmed {
                                    boot_display.draw_saving_screen("Deleting...");
                                    let del_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        sdcard::delete_file(ct, &fat32, &ad.sd_selected_file)?;
                                        Ok(())
                                    });
                                    sound::stop_ticking();
                                    match del_result {
                                        Ok(()) => {
                                            let mut disp = [0u8; 13];
                                            let dlen = sd_backup::format_83_display(&ad.sd_selected_file, &mut disp);
                                            let name_str = core::str::from_utf8(&disp[..dlen]).unwrap_or("?");
                                            log!("[SD-DELETE] Deleted {}", name_str);
                                            boot_display.draw_success_screen("Backup deleted");
                                            sound::success(delay);
                                            delay.delay_millis(1500);
                                            // Remove from file list
                                            // Shift bounds track SD_FILE_LIST_MAX, not a
                                            // literal. These were `j..7` and `[7]` from
                                            // when the list held 8 entries; left as
                                            // literals they would have shifted only the
                                            // first eight and cleared the wrong slot.
                                            const LAST: usize = crate::app::data::SD_FILE_LIST_MAX - 1;
                                            for j in 0..ad.sd_file_count as usize {
                                                if ad.sd_file_list[j] == ad.sd_selected_file {
                                                    for k in j..LAST {
                                                        ad.sd_file_list[k] = ad.sd_file_list[k + 1];
                                                    }
                                                    ad.sd_file_list[LAST] = [b' '; 11];
                                                    ad.sd_file_count -= 1;
                                                    break;
                                                }
                                            }
                                            if ad.sd_file_scroll > 0 && ad.sd_file_scroll >= ad.sd_file_count {
                                                ad.sd_file_scroll = ad.sd_file_count.saturating_sub(4);
                                            }
                                        }
                                        Err(e) => {
                                            log!("[SD-DELETE] Failed: {}", e);
                                            boot_display.draw_rejected_screen("Delete failed");
                                            sound::beep_error(delay);
                                            delay.delay_millis(2000);
                                        }
                                    }
                                }
                                ad.app.state = return_state;
                                needs_redraw = true;
                            }
                        }
                    }
                    crate::app::input::AppState::SdRestorePassphrase => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::SdFileList;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSPHRASE"); }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSPHRASE"); }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "PASSPHRASE"); }
                                6 => { // OK — read from SD and decrypt
                                    boot_display.draw_loading_screen("Reading from SD...");
                                    let pp_bytes_len = ad.pp_input.len;
                                    // 128, matching PassphraseInput::buf, not the 64 of the seed and
                                    // xprv destinations. The read side has to hold whatever some
                                    // writer already emitted, and a shorter buffer here panicked on
                                    // the slice index before the password was ever tried. Every
                                    // consumer below takes &pp_copy[..pp_bytes_len], and the wipe
                                    // iterates the whole array, so both follow the size.
                                    let mut pp_copy = [0u8; 128];
                                    pp_copy[..pp_bytes_len].copy_from_slice(&ad.pp_input.buf[..pp_bytes_len]);

                                    let read_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &ad.sd_selected_file)?;
                                        let mut file_buf = [0u8; 128];
                                        // Zeroized on the error path too. `?` here
                                        // would abandon the buffer holding a
                                        // partially read encrypted backup, and the
                                        // Ok arm's wipe below never runs because
                                        // `file_buf` is bound by that pattern. The
                                        // reasoning is the same as the note there:
                                        // ciphertext is the input to a dictionary
                                        // attack on the passphrase, and the legacy
                                        // format shares one salt across every device.
                                        let bytes_read = match sdcard::read_file(
                                            ct, &fat32, &entry, &mut file_buf,
                                        ) {
                                            Ok(n) => n,
                                            Err(e) => {
                                                for b in file_buf.iter_mut() {
                                                    unsafe { core::ptr::write_volatile(b, 0); }
                                                }
                                                return Err(e);
                                            }
                                        };
                                        Ok((file_buf, bytes_read))
                                    });

                                    match read_result {
                                        Ok((file_buf, bytes_read)) => {
                                            boot_display.draw_loading_screen("Decrypting...");
                                            let mut restored_indices = [0u16; 24];
                                            match sd_backup::decrypt_backup_versioned(
                                                &file_buf[..bytes_read],
                                                &pp_copy[..pp_bytes_len],
                                                &mut restored_indices,
                                                &mut |done, total| {
                                                    let pct = if total > 0 { (done * 80 / total) as u8 } else { 0 };
                                                    boot_display.update_progress_bar(pct);
                                                },
                                            ) {
                                                Ok((wc, legacy)) => {
                                                    boot_display.update_progress_bar(100);
                                                    ad.mnemonic_indices = [0u16; 24];
                                                    for i in 0..wc as usize {
                                                        ad.mnemonic_indices[i] = restored_indices[i];
                                                    }
                                                    ad.word_count = wc;
                                                    log!("[SD-RESTORE] Decrypted {}-word seed, deferring store", wc);
                                                    boot_display.draw_success_screen("Seed restored!");
                                                    sound::success(delay);
                                                    delay.delay_millis(1500);
                                                    if legacy {
                                                        // Old format: one shared salt across every
                                                        // device and file, so a single dictionary
                                                        // table attacks every backup ever written.
                                                        // The file still works; it should not be
                                                        // the copy the user keeps.
                                                        log!("[SD-RESTORE] Legacy format, prompting re-export");
                                                        boot_display.draw_notice_screen(
                                                            "Old backup format",
                                                            "Re-export for better security");
                                                        delay.delay_millis(2500);
                                                    }
                                                    // Single-store model: the seed is stored exactly
                                                    // once, on the PassphraseEntry OK. Empty field =
                                                    // base wallet; typed passphrase = that wallet.
                                                    ad.pp_input.reset();
                                                    ad.app.state = crate::app::input::AppState::PassphraseEntry;
                                                    needs_redraw = true;
                                                }
                                                Err(_) => {
                                                    log!("[SD-RESTORE] Decrypt failed (wrong password?)");
                                                    boot_display.draw_rejected_screen("Wrong password");
                                                    delay.delay_millis(2000);
                                                }
                                            }

                                            // Wipe the seed and the ciphertext before this arm
                                            // ends, for the same reason `pp_copy` is wiped below.
                                            //
                                            // `restored_indices` holds the decrypted mnemonic as
                                            // BIP39 indices: the whole secret in its most directly
                                            // usable form. It is a stack local on the deepest frame
                                            // this device has, so the bytes survive until something
                                            // reuses that region, which is rarely.
                                            //
                                            // `file_buf` is only ciphertext, but it is the input to
                                            // a dictionary attack on the passphrase, and the
                                            // legacy-format branch above exists precisely because
                                            // that format shares one salt across every device and
                                            // every file.
                                            //
                                            // The copy that matters is `ad.mnemonic_indices`, which
                                            // the OK path in handlers/seed.rs consumes and the back
                                            // path there now clears.
                                            {
                                                let mut file_buf = file_buf;
                                                for w in restored_indices.iter_mut() {
                                                    unsafe { core::ptr::write_volatile(w, 0); }
                                                }
                                                for b in file_buf.iter_mut() {
                                                    unsafe { core::ptr::write_volatile(b, 0); }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            log!("[SD-RESTORE] Read failed: {}", e);
                                            // Show the driver's own message. It named the
                                            // real cause all along and was discarded here;
                                            // `log!` compiles out in a production build, so
                                            // the screen is the only channel.
                                            boot_display.draw_rejected_screen(e);
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    for b in pp_copy.iter_mut() {
                                        unsafe { core::ptr::write_volatile(b, 0); }
                                    }
                                    ad.pp_input.reset();
                                    // If restore succeeded and we're heading to PassphraseEntry,
                                    // don't overwrite. Otherwise go to SeedList/MainMenu.
                                    if ad.app.state != crate::app::input::AppState::PassphraseEntry {
                                        if ad.seed_loaded {
                                            ad.app.state = crate::app::input::AppState::SeedList;
                                        } else {
                                            ad.app.go_main_menu();
                                        }
                                    }
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::SdXprvFilename => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::SigningKeysMenu;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "XPRV FILENAME"); }
                                5 => { /* no space in filenames */ }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "XPRV FILENAME"); }
                                6 => {
                                    // OK — build 8.3 filename, extension KAS
                                    let name_83 = build_filename_83(&ad.pp_input.buf, ad.pp_input.len, b"KAS");
                                    ad.kspt_filename = name_83;
                                    // Check if file already exists on SD
                                    if sd_file_exists(i2c, delay, &name_83) {
                                        ad.sd_overwrite_next = crate::app::input::AppState::SdXprvExportPassphrase;
                                        ad.sd_overwrite_back = crate::app::input::AppState::SdXprvFilename;
                                        ad.app.state = crate::app::input::AppState::SdOverwriteWarning;
                                    } else {
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdXprvExportPassphrase;
                                    }
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::SdXprvExportPassphrase => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::SigningKeysMenu;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSPHRASE"); }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSPHRASE"); }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "PASSPHRASE"); }
                                6 => { // OK — derive xprv, encrypt, write to SD
                                    boot_display.draw_saving_screen("Deriving xprv...");
                                    boot_display.update_progress_bar(15);
                                    let pp_bytes = &ad.pp_input.buf[..ad.pp_input.len];
                                    let pp_str = ad.seed_mgr.active_slot().map(|s| s.passphrase_str()).unwrap_or("");
                                    // Raw-key (wc=1) and xprv (wc=2) slots have no BIP39
                                    // mnemonic: their `indices` hold a packed 32-byte
                                    // private key, not word indices. This site had no
                                    // slot-type check, so both fell into the 24-word
                                    // branch and produced a valid-looking encrypted
                                    // backup that restores a DIFFERENT wallet. Refuse
                                    // instead of writing an unrestorable file.
                                    let seed_bytes = match crate::app::signing::derive_seed(
                                        &ad.mnemonic_indices, ad.word_count, pp_str,
                                    ) {
                                        Some(s) => s,
                                        None => {
                                            ad.pp_input.reset();
                                            boot_display.draw_rejected_screen("Slot has no mnemonic");
                                            sound::beep_error(delay);
                                            delay.delay_millis(2000);
                                            ad.app.state = crate::app::input::AppState::SigningKeysMenu;
                                            return Some(true);
                                        }
                                    };
                                    boot_display.update_progress_bar(33);
                                    let mut xprv_buf = [0u8; wallet::xpub::XPRV_MAX_LEN];
                                    match wallet::xpub::derive_and_serialize_xprv(&seed_bytes.bytes, &mut xprv_buf) {
                                        Ok(xlen) => {
                                            boot_display.update_progress_bar(50);
                                            boot_display.draw_saving_screen("Encrypting...");
                                            boot_display.update_progress_bar(50);
                                            let nonce = generate_trng_nonce();
                                            let salt = generate_trng_salt();
                                            let mut enc_buf = [0u8; sd_backup::MAX_XPRV_BACKUP_SIZE];
                                            match sd_backup::encrypt_xprv_backup_v3(
                                                &xprv_buf, xlen, pp_bytes, &salt, &nonce, &mut enc_buf,
                                                &mut |done, total| {
                                                    let pct = if total > 0 { 50 + (done * 20 / total) as u8 } else { 50 };
                                                    boot_display.update_progress_bar(pct);
                                                },
                                            ) {
                                                Ok(enc_len) => {
                                                    boot_display.update_progress_bar(70);
                                                    boot_display.draw_saving_screen("Writing to SD...");
                                                    boot_display.update_progress_bar(70);
                                                    // Use user-chosen filename from SdXprvFilename keyboard
                                                    let fname = ad.kspt_filename;
                                                    let write_result = write_file_to_sd(i2c, delay, &fname, &enc_buf[..enc_len]);
                                                    match write_result {
                                                        Ok(()) => {
                                                            log!("[SD-XPRV] Wrote {} bytes", enc_len);
                                                            boot_display.draw_success_screen("xprv Saved!");
                                                            sound::success(delay);
                                                            delay.delay_millis(2500);
                                                        }
                                                        Err(e) => {
                                                            log!("[SD-XPRV] Write failed: {}", e);
                                                            boot_display.draw_rejected_screen("SD write failed");
                                                            delay.delay_millis(2000);
                                                        }
                                                    }
                                                }
                                                Err(_) => {
                                                    boot_display.draw_rejected_screen("Encryption failed");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        }
                                        Err(_) => {
                                            boot_display.draw_rejected_screen("xprv derivation failed");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    zeroize_buf(&mut xprv_buf);
                                    ad.pp_input.reset();
                                    ad.app.state = crate::app::input::AppState::SeedList;
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::SdXprvFileList => {
                        if is_back {
                            ad.sd_file_scroll = 0;
                            ad.app.state = crate::app::input::AppState::SdImportMenu;
                            needs_redraw = true;
                        } else {
                            let max_vis: usize = 4;
                            let scroll_off = ad.sd_file_scroll as usize;
                            let can_page_up = scroll_off > 0;
                            let can_page_down = (scroll_off + max_vis) < ad.sd_file_count as usize;

                            if x < 40 && y >= 42 && can_page_up {
                                if ad.sd_file_scroll >= max_vis as u8 {
                                    ad.sd_file_scroll -= max_vis as u8;
                                } else {
                                    ad.sd_file_scroll = 0;
                                }
                                needs_redraw = true;
                            } else if x >= 280 && y >= 42 && can_page_down {
                                ad.sd_file_scroll += max_vis as u8;
                                needs_redraw = true;
                            } else {
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let idx = slot as usize + scroll_off;
                                    if idx < (ad.sd_file_count) as usize {
                                        ad.sd_selected_file = ad.sd_file_list[idx];
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdXprvImportPassphrase;
                                        needs_redraw = true;
                                    }
                                    break;
                                }
                            }
                            }
                        }
                    }
                    crate::app::input::AppState::SdXprvImportPassphrase => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::SdXprvFileList;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSPHRASE"); }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSPHRASE"); }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "PASSPHRASE"); }
                                6 => { // OK — read from SD, decrypt, import xprv
                                    boot_display.draw_loading_screen("Reading from SD...");
                                    let pp_bytes_len = ad.pp_input.len;
                                    // 128, matching PassphraseInput::buf, not the 64 of the seed and
                                    // xprv destinations. The read side has to hold whatever some
                                    // writer already emitted, and a shorter buffer here panicked on
                                    // the slice index before the password was ever tried. Every
                                    // consumer below takes &pp_copy[..pp_bytes_len], and the wipe
                                    // iterates the whole array, so both follow the size.
                                    let mut pp_copy = [0u8; 128];
                                    pp_copy[..pp_bytes_len].copy_from_slice(&ad.pp_input.buf[..pp_bytes_len]);

                                    let read_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &ad.sd_selected_file)?;
                                        let mut file_buf = [0u8; 256];
                                        // Zeroized on the error path too. `?` here
                                        // would abandon the buffer holding a
                                        // partially read encrypted backup, and the
                                        // Ok arm's wipe below never runs because
                                        // `file_buf` is bound by that pattern. The
                                        // reasoning is the same as the note there:
                                        // ciphertext is the input to a dictionary
                                        // attack on the passphrase, and the legacy
                                        // format shares one salt across every device.
                                        let bytes_read = match sdcard::read_file(
                                            ct, &fat32, &entry, &mut file_buf,
                                        ) {
                                            Ok(n) => n,
                                            Err(e) => {
                                                for b in file_buf.iter_mut() {
                                                    unsafe { core::ptr::write_volatile(b, 0); }
                                                }
                                                return Err(e);
                                            }
                                        };
                                        Ok((file_buf, bytes_read))
                                    });

                                    match read_result {
                                        Ok((file_buf, bytes_read)) => {
                                            boot_display.draw_loading_screen("Decrypting xprv...");
                                            let mut xprv_plain = [0u8; 120];
                                            match sd_backup::decrypt_xprv_versioned(
                                                &file_buf[..bytes_read],
                                                &pp_copy[..pp_bytes_len],
                                                &mut xprv_plain,
                                                &mut |done, total| {
                                                    let pct = if total > 0 { (done * 70 / total) as u8 } else { 0 };
                                                    boot_display.update_progress_bar(pct);
                                                },
                                            ) {
                                                Ok((xlen, legacy)) => {
                                                    match wallet::xpub::import_xprv(&xprv_plain[..xlen]) {
                                                        Ok(acct_key) => {
                                                            boot_display.update_progress_bar(75);
                                                            let raw = acct_key.to_raw();
                                                            ad.acct_key_raw.copy_from_slice(&raw);
                                                            boot_display.draw_loading_screen("Deriving addresses...");
                                                            boot_display.update_progress_bar(75);
                                                            let acct = wallet::bip32::ExtendedPrivKey::from_raw(&raw);
                                                            for idx in 0..20u16 {
                                                                if let Ok(addr_key) = wallet::bip32::derive_address_key(&acct, idx) {
                                                                    if let Ok(xpub) = addr_key.public_key_x_only() {
                                                                        ad.pubkey_cache[idx as usize].copy_from_slice(&xpub);
                                                                    }
                                                                }
                                                                boot_display.update_progress_bar((75 + ((idx as u32 + 1) * 25 / 20)) as u8);
                                                            }
                                                            // Derive change pubkeys (m/44'/111111'/0'/1/{0..4})
                                                            crate::app::signing::derive_change_pubkeys(
                                                                &raw, &mut ad.change_pubkey_cache);
                                                            use sha2::{Sha256, Digest};
                                                            let hash = Sha256::digest(acct_key.private_key_bytes());
                                                            let fp = [hash[0], hash[1], hash[2], hash[3]];
                                                            if let Some(slot_idx) = ad.seed_mgr.find_by_fingerprint(&fp, 2).or_else(|| ad.seed_mgr.find_free()) {
                                                                let slot = &mut ad.seed_mgr.slots[slot_idx];
                                                                if slot.is_empty() {
                                                                    // Constructor, see above (H-08).
                                                                    let mut key = [0u8; 32];
                                                                    key.copy_from_slice(&raw[..32]);
                                                                    let mut cc = [0u8; 32];
                                                                    cc.copy_from_slice(&raw[32..64]);
                                                                    slot.set_xprv(&key, &cc, raw[64]);
                                                                    slot.fingerprint = fp;
                                                                }
                                                                ad.seed_mgr.activate(slot_idx);
                                                                (ad.seed_loaded) = true;
                                                                (ad.pubkeys_cached) = true;
                                                                (ad.current_addr_index) = 0;
                                                                (ad.extra_pubkey_index) = 0xFFFF;
                                                                ad.word_count = 2;
                                                                log!("[SD-XPRV] Imported xprv to slot {}", slot_idx);
                                                                boot_display.draw_saving_screen("XPrv imported!");
                                                                delay.delay_millis(2000);
                                                                // A v2 xprv file carries the shared
                                                                // salt, and it also shares magic
                                                                // KAS\x02 with the raw hint blob
                                                                // (M-03), so it is the artifact most
                                                                // worth replacing. Shown after the
                                                                // success screen, since the import
                                                                // itself did succeed.
                                                                if legacy {
                                                                    log!("[SD-XPRV] Legacy format, prompting re-export");
                                                                    boot_display.draw_notice_screen(
                                                                        "Old backup format",
                                                                        "Re-export for better security");
                                                                    delay.delay_millis(2500);
                                                                }
                                                                ad.app.state = crate::app::input::AppState::SeedList;
                                                            } else {
                                                                boot_display.draw_rejected_screen("All 4 slots full!");
                                                                delay.delay_millis(2000);
                                                            }
                                                        }
                                                        Err(_) => {
                                                            boot_display.draw_rejected_screen("Invalid xprv format");
                                                            delay.delay_millis(2000);
                                                        }
                                                    }
                                                    zeroize_buf(&mut xprv_plain);
                                                }
                                                Err(_) => {
                                                    boot_display.draw_rejected_screen("Wrong password");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            log!("[SD-XPRV] Read failed: {}", e);
                                            // Show the driver's own message. It named the
                                            // real cause all along and was discarded here;
                                            // `log!` compiles out in a production build, so
                                            // the screen is the only channel.
                                            boot_display.draw_rejected_screen(e);
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    for b in pp_copy.iter_mut() {
                                        unsafe { core::ptr::write_volatile(b, 0); }
                                    }
                                    ad.pp_input.reset();
                                    // Only fall back to SdFileList if no import succeeded
                                    // (successful import already set state to SeedList)
                                    if ad.app.state == crate::app::input::AppState::SdXprvImportPassphrase {
                                        ad.app.state = crate::app::input::AppState::SdFileList;
                                    }
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::SdImportMenu => {
                        if is_back {
                            ad.sd_import_menu.reset();
                            ad.app.state = crate::app::input::AppState::ImportMenu;
                            needs_redraw = true;
                        } else if page_up_zone.contains(x, y) && ad.sd_import_menu.can_page_up() {
                            ad.sd_import_menu.page_up();
                            needs_redraw = true;
                        } else if page_down_zone.contains(x, y) && ad.sd_import_menu.can_page_down() {
                            ad.sd_import_menu.page_down();
                            needs_redraw = true;
                        } else {
                            // Chip-row list navigation
                            let mut tapped_item: Option<u8> = None;
                            for slot in 0..4u8 {
                                if list_zones[slot as usize].contains(x, y) {
                                    let abs = ad.sd_import_menu.visible_to_absolute(slot);
                                    if abs < ad.sd_import_menu.count {
                                        tapped_item = Some(abs);
                                    }
                                    break;
                                }
                            }
                            if let Some(item) = tapped_item {
                                needs_redraw = true;
                                match item {
                                    0 => {
                                        // Seed Backup — scan SD for compatible seed/xprv/key files
                                        if _bb_card_type.is_some() {
                                            boot_display.draw_loading_screen("Scanning SD...");
                                            ad.sd_file_count = 0;
                                            ad.sd_file_scroll = 0;
                                            let scan_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                                let fat32 = sdcard::mount_fat32(ct)?;
                                                // Sized to `SD_FILE_LIST_MAX`, like the .KSP
                                                // scanner below. It was 16 while the list array
                                                // was 32 and the accept cap was 8: three
                                                // different limits for one list. An 18-file card
                                                // silently lost the last two entries, which
                                                // presented as an exported xprv that could not
                                                // be imported.
                                                let mut candidates: [[u8; 11]; crate::app::data::SD_FILE_LIST_MAX] =
                                                    [[b' '; 11]; crate::app::data::SD_FILE_LIST_MAX];
                                                let mut cand_count = 0u8;
                                                let mut capped = false;
                                                sdcard::list_root_dir(ct, &fat32, |entry| {
                                                    if !entry.is_dir()
                                                        && entry.file_size > 0
                                                        && entry.file_size <= 1024
                                                        && (cand_count as usize) < crate::app::data::SD_FILE_LIST_MAX
                                                    {
                                                        candidates[cand_count as usize] = entry.name;
                                                        cand_count += 1;
                                                    } else if !entry.is_dir()
                                                        && (cand_count as usize) >= crate::app::data::SD_FILE_LIST_MAX
                                                    {
                                                        // Count only, no filename. Any cap can be
                                                        // reached, and a file dropping out of the
                                                        // list with no explanation is
                                                        // indistinguishable from a lost backup:
                                                        // that is exactly how the 16-entry cap
                                                        // presented. Kept deliberately; the
                                                        // per-file diagnostics that sat here
                                                        // during testing are gone because they
                                                        // printed filenames over USB.
                                                        capped = true;
                                                    }
                                                    true
                                                })?;
                                                if capped {
                                                    log!("[SD-IMPORT] file list truncated at {}", crate::app::data::SD_FILE_LIST_MAX);
                                                }
                                                // Stays on the stack: sd_read_block
                                                // takes &mut [u8; 512], a fixed array,
                                                // not a slice.
                                                let mut peek_buf = [0u8; 512];
                                                for c in 0..cand_count as usize {
                                                    if (ad.sd_file_count as usize) >= crate::app::data::SD_FILE_LIST_MAX { break; }
                                                    let name = &candidates[c];
                                                    if let Ok((entry, _, _)) = sdcard::find_file_in_root(ct, &fat32, name) {
                                                        let cluster = entry.first_cluster();
                                                        if cluster >= 2 {
                                                            let sector = fat32.cluster_to_sector(cluster);
                                                            if sdcard::sd_read_block(ct, sector, &mut peek_buf).is_ok() {
                                                                let sz = entry.file_size as usize;
                                                                // v3 container, any purpose. Without this the
                                                                // file browser silently omits every file the
                                                                // current firmware writes.
                                                                let is_v3 = sz >= sd_backup::V3_OVERHEAD + 1
                                                                    && peek_buf[0] == b'K' && peek_buf[1] == b'A'
                                                                    && peek_buf[2] == b'S' && peek_buf[3] == 0x04
                                                                    && peek_buf[4] == sd_backup::V3_VERSION;
                                                                let is_enc_seed = sz >= 57 && peek_buf[0] == b'K' && peek_buf[1] == b'A' && peek_buf[2] == b'S' && peek_buf[3] == 0x01;
                                                                let is_enc_xprv = sz >= 40 && peek_buf[0] == b'K' && peek_buf[1] == b'A' && peek_buf[2] == b'S' && peek_buf[3] == 0x02;
                                                                let is_plain_xprv = sz >= 100 && peek_buf[0] == b'x' && peek_buf[1] == b'p' && peek_buf[2] == b'r' && peek_buf[3] == b'v';
                                                                let is_plain_hex = (64..=66).contains(&sz) && {
                                                                    let mut ok = true;
                                                                    for b in &peek_buf[..64.min(sz)] {
                                                                        if !((*b >= b'0' && *b <= b'9') || (*b >= b'a' && *b <= b'f') || (*b >= b'A' && *b <= b'F')) {
                                                                            ok = false; break;
                                                                        }
                                                                    }
                                                                    ok
                                                                };
                                                                if is_v3 || is_enc_seed || is_enc_xprv || is_plain_xprv || is_plain_hex {
                                                                    ad.sd_file_list[ad.sd_file_count as usize] = *name;
                                                                    ad.sd_file_count += 1;
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                Ok(())
                                            });
                                            match scan_result {
                                                Ok(()) if ad.sd_file_count > 0 => {
                                                    ad.app.state = crate::app::input::AppState::SdFileList;
                                                }
                                                Ok(()) => {
                                                    boot_display.draw_rejected_screen("No compatible files");
                                                    delay.delay_millis(2000);
                                                }
                                                Err(e) => {
                                                    log!("[SD-IMPORT] Scan failed: {}", e);
                                                    boot_display.draw_rejected_screen("SD read error");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        } else {
                                            boot_display.draw_rejected_screen("No SD card detected");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    1 => {
                                        // Transaction — scan SD for .KSP files
                                        if _bb_card_type.is_some() {
                                            boot_display.draw_loading_screen("Scanning SD...");
                                            ad.sd_file_count = 0;
                                            ad.sd_file_scroll = 0;
                                            let scan_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                                let fat32 = sdcard::mount_fat32(ct)?;
                                                sdcard::list_root_dir(ct, &fat32, |entry| {
                                                    if !entry.is_dir()
                                                        && entry.file_size > 0
                                                        // Same bound as the read buffer below,
                                                        // so a file that lists is a file that
                                                        // can be read.
                                                        && (entry.file_size as usize) <= KSPT_FILE_MAX
                                                        && (ad.sd_file_count as usize) < crate::app::data::SD_FILE_LIST_MAX
                                                        && entry.name[8] == b'K'
                                                        && entry.name[9] == b'S'
                                                        && entry.name[10] == b'P'
                                                    {
                                                        ad.sd_file_list[ad.sd_file_count as usize] = entry.name;
                                                        ad.sd_file_count += 1;
                                                    }
                                                    true
                                                })?;
                                                Ok(())
                                            });
                                            match scan_result {
                                                Ok(()) if ad.sd_file_count > 0 => {
                                                    // What this flow is carrying. Without it the
                                                    // value stays at its default of ADDRESS, so the
                                                    // KSPT branch after a decrypt never runs and an
                                                    // encrypted save asks the address question. The
                                                    // other six transitions to this state are error
                                                    // returns from inside the flow, where the value
                                                    // is already correct.
                                                    ad.sd_txt_origin = crate::app::data::SD_ORIGIN_KSPT;
                                                    ad.app.state = crate::app::input::AppState::SdKsptFileList;
                                                }
                                                Ok(()) => {
                                                    boot_display.draw_rejected_screen("No .KSP files found");
                                                    delay.delay_millis(2000);
                                                }
                                                Err(e) => {
                                                    log!("[SD-KSPT] Scan failed: {}", e);
                                                    boot_display.draw_rejected_screen("SD read error");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        } else {
                                            boot_display.draw_rejected_screen("No SD card detected");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    2 => {
                                        // kpub — scan SD for .TXT files
                                        ad.txt_import_type = 0;
                                        if _bb_card_type.is_some() {
                                            boot_display.draw_loading_screen("Scanning SD...");
                                            ad.sd_file_count = 0;
                                            ad.sd_file_scroll = 0;
                                            let scan_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                                let fat32 = sdcard::mount_fat32(ct)?;
                                                sdcard::list_root_dir(ct, &fat32, |entry| {
                                                    // Same shape as the descriptor
                                                    // filter. list_root_dir does NOT
                                                    // skip deleted entries, so without
                                                    // the 0xE5 check deleted files
                                                    // appeared in this list and read
                                                    // back as garbage.
                                                    let is_hidden = entry.name[0] == b'.' || entry.name[0] == 0xE5;
                                                    let ext = [entry.name[8], entry.name[9], entry.name[10]];
                                                    let is_txt = ext == *b"TXT" || ext == *b"txt";
                                                    if !entry.is_dir()
                                                        && !is_hidden
                                                        && entry.file_size > 0
                                                        && (entry.file_size as usize) <= TXT_IMPORT_BUF
                                                        && (ad.sd_file_count as usize) < crate::app::data::SD_FILE_LIST_MAX
                                                        && is_txt
                                                    {
                                                        ad.sd_file_list[ad.sd_file_count as usize] = entry.name;
                                                        ad.sd_file_count += 1;
                                                    }
                                                    true
                                                })?;
                                                Ok(())
                                            });
                                            match scan_result {
                                                Ok(()) if ad.sd_file_count > 0 => {
                                                    ad.app.state = crate::app::input::AppState::SdKpubFileList;
                                                }
                                                Ok(()) => {
                                                    boot_display.draw_rejected_screen("No .TXT files found");
                                                    delay.delay_millis(2000);
                                                }
                                                Err(e) => {
                                                    log!("[SD-KPUB] Scan failed: {}", e);
                                                    boot_display.draw_rejected_screen("SD read error");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        } else {
                                            boot_display.draw_rejected_screen("No SD card detected");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    3 => {
                                        // Multisig Address — scan SD for .TXT files
                                        ad.txt_import_type = 1;
                                        if _bb_card_type.is_some() {
                                            boot_display.draw_loading_screen("Scanning SD...");
                                            ad.sd_file_count = 0;
                                            ad.sd_file_scroll = 0;
                                            let scan_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                                let fat32 = sdcard::mount_fat32(ct)?;
                                                sdcard::list_root_dir(ct, &fat32, |entry| {
                                                    // Same shape as the descriptor
                                                    // filter. list_root_dir does NOT
                                                    // skip deleted entries, so without
                                                    // the 0xE5 check deleted files
                                                    // appeared in this list and read
                                                    // back as garbage.
                                                    let is_hidden = entry.name[0] == b'.' || entry.name[0] == 0xE5;
                                                    let ext = [entry.name[8], entry.name[9], entry.name[10]];
                                                    let is_txt = ext == *b"TXT" || ext == *b"txt";
                                                    if !entry.is_dir()
                                                        && !is_hidden
                                                        && entry.file_size > 0
                                                        && (entry.file_size as usize) <= TXT_IMPORT_BUF
                                                        && (ad.sd_file_count as usize) < crate::app::data::SD_FILE_LIST_MAX
                                                        && is_txt
                                                    {
                                                        ad.sd_file_list[ad.sd_file_count as usize] = entry.name;
                                                        ad.sd_file_count += 1;
                                                    }
                                                    true
                                                })?;
                                                Ok(())
                                            });
                                            match scan_result {
                                                Ok(()) if ad.sd_file_count > 0 => {
                                                    ad.app.state = crate::app::input::AppState::SdKpubFileList;
                                                }
                                                Ok(()) => {
                                                    boot_display.draw_rejected_screen("No .TXT files found");
                                                    delay.delay_millis(2000);
                                                }
                                                Err(_) => {
                                                    boot_display.draw_rejected_screen("SD read error");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        } else {
                                            boot_display.draw_rejected_screen("No SD card detected");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    4 => {
                                        // Multisig Descriptor — scan SD for .TXT files
                                        ad.txt_import_type = 2;
                                        if _bb_card_type.is_some() {
                                            boot_display.draw_loading_screen("Scanning SD...");
                                            ad.sd_file_count = 0;
                                            ad.sd_file_scroll = 0;
                                            let scan_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                                let fat32 = sdcard::mount_fat32(ct)?;
                                                sdcard::list_root_dir(ct, &fat32, |entry| {
                                                    let is_hidden = entry.name[0] == b'.' || entry.name[0] == 0xE5;
                                                    let ext = [entry.name[8], entry.name[9], entry.name[10]];
                                                    let is_txt = ext == *b"TXT" || ext == *b"txt";
                                                    let is_ksp = ext == *b"KSP" || ext == *b"ksp";
                                                    if !entry.is_dir()
                                                        && !is_hidden
                                                        && entry.file_size > 0
                                                        && (entry.file_size as usize) <= TXT_IMPORT_BUF
                                                        && (ad.sd_file_count as usize) < crate::app::data::SD_FILE_LIST_MAX
                                                        && (is_txt || is_ksp)
                                                    {
                                                        ad.sd_file_list[ad.sd_file_count as usize] = entry.name;
                                                        ad.sd_file_count += 1;
                                                    }
                                                    true
                                                })?;
                                                Ok(())
                                            });
                                            match scan_result {
                                                Ok(()) if ad.sd_file_count > 0 => {
                                                    ad.app.state = crate::app::input::AppState::SdKpubFileList;
                                                }
                                                Ok(()) => {
                                                    boot_display.draw_rejected_screen("No .TXT files found");
                                                    delay.delay_millis(2000);
                                                }
                                                Err(_) => {
                                                    boot_display.draw_rejected_screen("SD read error");
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                        } else {
                                            boot_display.draw_rejected_screen("No SD card detected");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    5 => {
                                        // Covenant Restore — scan SD for .COV files
                                        // (same logic as Import menu item 3 in
                                        // menu.rs; SdFileList auto-detects the
                                        // COVB/COVI payload and shows the QR).
                                        if _bb_card_type.is_some() {
                                            boot_display.draw_loading_screen("Scanning SD...");
                                            ad.sd_file_count = 0;
                                            ad.sd_file_scroll = 0;
                                            let _ = sdcard::with_sd_card(i2c, delay, |ct| {
                                                let fat32 = sdcard::mount_fat32(ct)?;
                                                sdcard::list_root_dir(ct, &fat32, |entry| {
                                                    let is_hidden = entry.name[0] == b'.' || entry.name[0] == 0xE5 || entry.name[0] == b'_';
                                                    let ext = [entry.name[8], entry.name[9], entry.name[10]];
                                                    if !entry.is_dir()
                                                        && !is_hidden
                                                        && entry.file_size > 0
                                                        && entry.file_size <= 1024
                                                        && (ad.sd_file_count as usize) < crate::app::data::SD_FILE_LIST_MAX
                                                        && ext == *b"COV"
                                                    {
                                                        ad.sd_file_list[ad.sd_file_count as usize] = entry.name;
                                                        ad.sd_file_count += 1;
                                                    }
                                                    true
                                                })?;
                                                Ok(())
                                            });
                                            if ad.sd_file_count > 0 {
                                                ad.app.state = crate::app::input::AppState::SdFileList;
                                            } else {
                                                boot_display.draw_rejected_screen("No .COV files on SD");
                                                delay.delay_millis(1500);
                                            }
                                        } else {
                                            boot_display.draw_rejected_screen("No SD card detected");
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    crate::app::input::AppState::SdKsptFileList => {
                        if is_back {
                            ad.sd_file_scroll = 0;
                            ad.app.state = crate::app::input::AppState::SdImportMenu;
                            needs_redraw = true;
                        } else {
                            let max_vis: usize = 4;
                            let scroll_off = ad.sd_file_scroll as usize;
                            let can_page_up = scroll_off > 0;
                            let can_page_down = (scroll_off + max_vis) < ad.sd_file_count as usize;

                            if x < 40 && y >= 42 && can_page_up {
                                if ad.sd_file_scroll >= max_vis as u8 {
                                    ad.sd_file_scroll -= max_vis as u8;
                                } else {
                                    ad.sd_file_scroll = 0;
                                }
                                needs_redraw = true;
                            } else if x >= 280 && y >= 42 && can_page_down {
                                ad.sd_file_scroll += max_vis as u8;
                                needs_redraw = true;
                            } else {
                                let mut tapped: Option<usize> = None;
                                let mut tapped_delete = false;
                                for slot in 0..4u8 {
                                    if list_zones[slot as usize].contains(x, y) {
                                        let idx = slot as usize + scroll_off;
                                        if idx < (ad.sd_file_count) as usize {
                                            tapped = Some(idx);
                                            // Right 40px of card = delete zone
                                            tapped_delete = x > 228;
                                        }
                                        break;
                                    }
                                }
                                if let Some(i) = tapped {
                                    needs_redraw = true;
                                    ad.sd_selected_file = ad.sd_file_list[i];
                                    if tapped_delete {
                                        // Show delete confirmation
                                        ad.app.state = crate::app::input::AppState::SdDeleteConfirm;
                                    } else {
                                    // Read .KSP file into signed_qr_buf
                                    boot_display.draw_loading_screen("Loading TX...");
                                    let read_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &ad.sd_selected_file)?;
                                        // Heap, not stack: this array is RETURNED
                                        // from the closure, so as a fixed array it
                                        // would occupy a slot in both this frame and
                                        // handle_sd_touch's for the whole function.
                                        //
                                        // Sized to hold the encrypted form too, which
                                        // is KSPT_ENC_OVERHEAD larger than the
                                        // plaintext, and matched to the scan filter
                                        // above so a listed file is always readable.
                                        let mut buf = alloc::vec![0u8; KSPT_FILE_MAX];
                                        let n = sdcard::read_file(ct, &fat32, &entry, &mut buf[..])?;
                                        Ok((buf, n))
                                    });
                                    match read_result {
                                        Ok((buf, n)) => {
                                            // Check if encrypted (KAS\x03)
                                            if is_kspt_encrypted(&buf[..n]) {
                                                // Encrypted KSPT — need password
                                                // Store raw file in signed_qr_buf temporarily for decryption
                                                ad.signed_qr_buf[..n].copy_from_slice(&buf[..n]);
                                                ad.signed_qr_len = n;
                                                ad.kspt_filename = [b' '; 11]; // clear so save/load detection works
                                                ad.pp_input.reset();
                                                ad.app.state = crate::app::input::AppState::SdKsptEncryptPass;
                                            } else {
                                                // Plain file — detect content type
                                                ad.signed_qr_buf[..n].copy_from_slice(&buf[..n]);
                                                ad.signed_qr_len = n;
                                                ad.signed_qr_frame = 0;
                                                ad.signed_qr_nframes = 0;
                                                ad.signed_qr_large = false;
                                                ad.tx_sigs_present = 0;
                                                ad.tx_sigs_required = 0;
                                                log!("[SD-KSPT] Loaded {} bytes from SD", n);

                                                let is_descriptor = looks_like_descriptor(&buf[..n]);
                                                let is_address = n >= 10
                                                    && (&buf[..6] == b"kaspa:" || &buf[..10] == b"kaspatest:");

                                                if is_descriptor {
                                                    // One loader for both schemes: it reads `multi_hd45(` or
                                                    // `multi_hd(` from the file and sets `v45` accordingly, and it
                                                    // leaves the config untouched on failure so a bad descriptor
                                                    // cannot half-load over a good one.
                                                    //
                                                    // The three outcomes get three messages on purpose. A 45'
                                                    // descriptor loaded with no seed is NOT bad, and saying so
                                                    // would send the user to check a file that is fine.
                                                    let parsed = load_descriptor_into(&mut ad.ms_creating, &buf[..n]);
                                                    let resolved = if parsed {
                                                        crate::app::signing::resolve_ms_cosigner_index(ad)
                                                    } else {
                                                        crate::app::signing::MsResolve::Ok
                                                    };
                                                    if !parsed {
                                                        ad.ms_creating = wallet::transaction::MultisigConfig::new();
                                                    }
                                                    if parsed && resolved == crate::app::signing::MsResolve::Ok {
                                                        ad.ms_creating.build_script();
                                                        boot_display.draw_success_screen("Descriptor loaded!");
                                                        sound::success(delay);
                                                        delay.delay_millis(1000);
                                                        ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                                                    } else {
                                                        // Name the actual cause. "Bad descriptor" for a good file
                                                        // that simply has no seed to compare against is a wrong
                                                        // diagnosis, and it points the user at the file.
                                                        boot_display.draw_rejected_screen(match resolved {
                                                            crate::app::signing::MsResolve::NoSeed => "Load a seed first",
                                                            crate::app::signing::MsResolve::NotOurs => "Not your wallet",
                                                            crate::app::signing::MsResolve::Ok => "Bad descriptor",
                                                        });
                                                        delay.delay_millis(2000);
                                                        ad.app.state = crate::app::input::AppState::SdKsptFileList;
                                                    }
                                                } else if is_address {
                                                    ad.kpub_data[..n].copy_from_slice(&buf[..n]);
                                                    ad.kpub_len = n;
                                                    ad.ms_creating.active = false;
                                                    boot_display.draw_success_screen("Address loaded!");
                                                    sound::success(delay);
                                                    delay.delay_millis(1000);
                                                    ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                                                } else {
                                                    boot_display.draw_success_screen("TX loaded!");
                                                    sound::success(delay);
                                                    delay.delay_millis(1000);
                                                    ad.app.state = crate::app::input::AppState::ShowQrFrameChoice;
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            log!("[SD-KSPT] Read failed: {}", e);
                                            // Show the driver's own message. It named the
                                            // real cause all along and was discarded here;
                                            // `log!` compiles out in a production build, so
                                            // the screen is the only channel.
                                            boot_display.draw_rejected_screen(e);
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    } // close tapped_delete else
                                }
                            }
                        }
                    }
                    crate::app::input::AppState::ShowQrPopup => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ShowQrModeChoice;
                            needs_redraw = true;
                        } else {
                            // Two buttons: "Save to SD" and "Back to QR"
                            // Save to SD button zone: center-left area
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                // Save to SD → detect content type for correct extension
                                let is_descriptor = looks_like_descriptor(&ad.signed_qr_buf[..ad.signed_qr_len]);
                                if is_descriptor {
                                    let next = scan_auto_increment(i2c, delay, b"MD", b"TXT");
                                    let name = format_auto_name(b"MD", next, b"TXT");
                                    ad.kspt_filename = name;
                                    ad.pp_input.reset();
                                    for j in 0..8usize {
                                        if name[j] != b' ' {
                                            ad.pp_input.push_char(name[j]);
                                        }
                                    }
                                    ad.app.state = crate::app::input::AppState::SdMsDescFilename;
                                } else {
                                    let next = scan_auto_increment(i2c, delay, b"TX", b"KSP");
                                    let name = format_auto_name(b"TX", next, b"KSP");
                                    ad.kspt_filename = name;
                                    ad.pp_input.reset();
                                    for j in 0..8usize {
                                        if name[j] != b' ' {
                                            ad.pp_input.push_char(name[j]);
                                        }
                                    }
                                    ad.app.state = crate::app::input::AppState::SdKsptFilename;
                                }
                                needs_redraw = true;
                            }
                            // Back to QR button zone: center-right area
                            else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                ad.signed_qr_frame = 0;
                                ad.app.state = crate::app::input::AppState::ShowQR;
                                needs_redraw = true;
                            }
                        }
                    }
                    crate::app::input::AppState::SdKsptFilename => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::ShowQrPopup;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "FILENAME"); }
                                5 => { /* no space in filenames — ignore */ }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "FILENAME"); }
                                6 => {
                                    // OK — build 8.3 filename from input
                                    let name_83 = build_filename_83(&ad.pp_input.buf, ad.pp_input.len, b"KSP");
                                    ad.kspt_filename = name_83;
                                    // Check if file already exists on SD
                                    if sd_file_exists(i2c, delay, &name_83) {
                                        ad.sd_overwrite_next = crate::app::input::AppState::SdKsptEncryptAsk;
                                        ad.sd_overwrite_back = crate::app::input::AppState::SdKsptFilename;
                                        ad.app.state = crate::app::input::AppState::SdOverwriteWarning;
                                    } else {
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdKsptEncryptAsk;
                                    }
                                    // Same omission as the descriptor arm: without
                                    // this, reusing an existing .KSP filename left
                                    // the keyboard drawn over an active but
                                    // invisible overwrite warning.
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::SdKsptEncryptAsk => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::ShowQrPopup;
                        } else {
                            // Two buttons: "Yes" (encrypt) and "No" (plain)
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                // Yes — encrypt: go to password keyboard
                                ad.kspt_encrypt = true;
                                ad.pp_input.reset();
                                ad.app.state = crate::app::input::AppState::SdKsptEncryptPass;
                            } else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                // No — write plain KSPT to SD
                                ad.kspt_encrypt = false;
                                boot_display.draw_saving_screen("Saving to SD...");
                                let data = &ad.signed_qr_buf[..ad.signed_qr_len];
                                let fname = ad.kspt_filename;
                                let write_result = write_file_to_sd(i2c, delay, &fname, data);
                                sound::stop_ticking();
                                match write_result {
                                    Ok(()) => {
                                        let mut disp = [0u8; 13];
                                        let dlen = sd_backup::format_83_display(&fname, &mut disp);
                                        let name_str = core::str::from_utf8(&disp[..dlen]).unwrap_or("?");
                                        log!("[SD-KSPT] Saved {} bytes as {}", ad.signed_qr_len, name_str);
                                        boot_display.draw_success_screen("Saved!");
                                        sound::success(delay);
                                        delay.delay_millis(1500);
                                    }
                                    Err(e) => {
                                        log!("[SD-KSPT] Write failed: {}", e);
                                        boot_display.draw_rejected_screen("SD write failed");
                                        sound::beep_error(delay);
                                        delay.delay_millis(2000);
                                    }
                                }
                                ad.app.go_main_menu();
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdKpubFileList => {
                        if is_back {
                            ad.sd_file_scroll = 0;
                            ad.app.state = crate::app::input::AppState::SdImportMenu;
                            needs_redraw = true;
                        } else {
                            let max_vis: usize = 4;
                            let scroll_off = ad.sd_file_scroll as usize;
                            let can_page_up = scroll_off > 0;
                            let can_page_down = (scroll_off + max_vis) < ad.sd_file_count as usize;

                            if x < 40 && y >= 42 && can_page_up {
                                if ad.sd_file_scroll >= max_vis as u8 {
                                    ad.sd_file_scroll -= max_vis as u8;
                                } else {
                                    ad.sd_file_scroll = 0;
                                }
                                needs_redraw = true;
                            } else if x >= 280 && y >= 42 && can_page_down {
                                ad.sd_file_scroll += max_vis as u8;
                                needs_redraw = true;
                            } else {
                                let mut tapped: Option<usize> = None;
                                let mut tapped_delete = false;
                                for slot in 0..4u8 {
                                    if list_zones[slot as usize].contains(x, y) {
                                        let idx = slot as usize + scroll_off;
                                        if idx < ad.sd_file_count as usize {
                                            tapped = Some(idx);
                                            // Right ~40px of card = delete zone
                                            // (trash icon draws at start_x + card_w - 44 .. -6, same as SdFileList)
                                            tapped_delete = x > 228;
                                        }
                                        break;
                                    }
                                }
                                if let Some(i) = tapped {
                                    needs_redraw = true;
                                    ad.sd_selected_file = ad.sd_file_list[i];
                                    if tapped_delete {
                                        // Return to this same list after delete/cancel
                                        ad.sd_delete_return = crate::app::input::AppState::SdKpubFileList;
                                        ad.app.state = crate::app::input::AppState::SdDeleteConfirm;
                                    } else {
                                    let load_label = match ad.txt_import_type {
                                        0 => "Reading kpub...",
                                        1 => "Reading address...",
                                        2 => "Reading descriptor...",
                                        _ => "Reading file...",
                                    };
                                    boot_display.draw_loading_screen(load_label);
                                    let read_result = sdcard::with_sd_card(i2c, delay, |ct| {
                                        let fat32 = sdcard::mount_fat32(ct)?;
                                        let (entry, _, _) = sdcard::find_file_in_root(ct, &fat32, &ad.sd_selected_file)?;
                                        // Heap: returned from the closure, see above.
                                        // Sized by TXT_IMPORT_BUF so the largest
                                        // descriptor the parser accepts can be read.
                                        let mut buf = alloc::vec![0u8; TXT_IMPORT_BUF];
                                        let n = sdcard::read_file(ct, &fat32, &entry, &mut buf[..])?;
                                        Ok((buf, n))
                                    });
                                    match read_result {
                                        Ok((buf, n)) => {
                                            match ad.txt_import_type {
                                                0 => {
                                                    // kpub — validate content before accepting
                                                    let is_kpub_ascii = n >= 4 && &buf[..4] == b"kpub";
                                                    let is_kpub_v1raw = n == 79 && buf[0] == 0x01;
                                                    let is_encrypted = is_kspt_encrypted(&buf[..n]);
                                                    if is_encrypted {
                                                        // Encrypted kpub — go to password prompt
                                                        ad.signed_qr_buf[..n].copy_from_slice(&buf[..n]);
                                                        ad.signed_qr_len = n;
                                                        ad.sd_txt_origin = crate::app::data::SD_ORIGIN_KPUB;
                                                        // Clear so SdKsptEncryptPass detects LOAD.
                                                        // That screen decides encrypt-vs-decrypt from
                                                        // the kspt_filename extension; a stale .TXT
                                                        // left by an earlier save sent this load down
                                                        // the encrypt branch, which showed
                                                        // "Encrypting..." and produced a QR of the
                                                        // wrong bytes.
                                                        ad.kspt_filename = [b' '; 11];
                                                        ad.pp_input.reset();
                                                        ad.app.state = crate::app::input::AppState::SdKsptEncryptPass;
                                                    } else if (is_kpub_ascii || is_kpub_v1raw) && n <= wallet::xpub::KPUB_MAX_LEN {
                                                        ad.kpub_data[..n].copy_from_slice(&buf[..n]);
                                                        ad.kpub_len = n;
                                                        ad.kpub_frame = 0;
                                                        ad.kpub_nframes = 0;
                                                        ad.app.state = crate::app::input::AppState::ExportKpub;
                                                    } else {
                                                        boot_display.draw_rejected_screen("Not a valid kpub");
                                                        delay.delay_millis(2000);
                                                    }
                                                }
                                                1 => {
                                                    // Multisig address — validate content
                                                    let is_encrypted = is_kspt_encrypted(&buf[..n]);
                                                    let is_address = n >= 6
                                                        && (&buf[..6] == b"kaspa:" || (n >= 10 && &buf[..10] == b"kaspatest:"));
                                                    if is_encrypted {
                                                        // Encrypted address — go to password prompt
                                                        ad.signed_qr_buf[..n].copy_from_slice(&buf[..n]);
                                                        ad.signed_qr_len = n;
                                                        ad.sd_txt_origin = crate::app::data::SD_ORIGIN_ADDRESS;
                                                        // Clear so SdKsptEncryptPass detects LOAD.
                                                        ad.kspt_filename = [b' '; 11];
                                                        ad.pp_input.reset();
                                                        ad.app.state = crate::app::input::AppState::SdKsptEncryptPass;
                                                    } else if is_address {
                                                        let max_addr_len = wallet::xpub::KPUB_MAX_LEN
                                                            .min(buf.len())
                                                            .min(ad.signed_qr_buf.len());
                                                        if n <= max_addr_len {
                                                            ad.kpub_data[..n].copy_from_slice(&buf[..n]);
                                                            ad.kpub_len = n;
                                                            ad.ms_creating.active = false;
                                                            ad.signed_qr_buf[..n].copy_from_slice(&buf[..n]);
                                                            ad.signed_qr_len = n;
                                                            ad.signed_qr_frame = 0;
                                                            ad.signed_qr_nframes = 0;
                                                            ad.signed_qr_large = false;
                                                            boot_display.draw_success_screen("Address loaded!");
                                                            sound::success(delay);
                                                            delay.delay_millis(1000);
                                                            ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                                                        } else {
                                                            boot_display.draw_rejected_screen("Address too long");
                                                            delay.delay_millis(2000);
                                                        }
                                                    } else {
                                                        boot_display.draw_rejected_screen("Not a valid address");
                                                        delay.delay_millis(2000);
                                                    }
                                                }
                                                2 => {
                                                    // Multisig descriptor — may be plain or encrypted.
                                                    if is_kspt_encrypted(&buf[..n]) {
                                                        // Encrypted — store raw and go to password prompt.
                                                        // sd_txt_origin=2 signals "return to descriptor" after decrypt.
                                                        ad.signed_qr_buf[..n].copy_from_slice(&buf[..n]);
                                                        ad.signed_qr_len = n;
                                                        ad.sd_txt_origin = crate::app::data::SD_ORIGIN_DESCRIPTOR;
                                                        // Clear so SdKsptEncryptPass detects LOAD.
                                                        ad.kspt_filename = [b' '; 11];
                                                        ad.pp_input.reset();
                                                        ad.app.state = crate::app::input::AppState::SdKsptEncryptPass;
                                                    } else if n > 0 && n <= buf.len() {
                                                        let text = core::str::from_utf8(&buf[..n]).unwrap_or("?");
                                                        log!("[SD-DESC] Loaded: {}", text);
                                                        // One loader for both schemes: it reads `multi_hd45(` or
                                                        // `multi_hd(` from the file and sets `v45` accordingly, and it
                                                        // leaves the config untouched on failure so a bad descriptor
                                                        // cannot half-load over a good one.
                                                        //
                                                        // The three outcomes get three messages on purpose. A 45'
                                                        // descriptor loaded with no seed is NOT bad, and saying so
                                                        // would send the user to check a file that is fine.
                                                        let parsed = load_descriptor_into(&mut ad.ms_creating, &buf[..n]);
                                                        let resolved = if parsed {
                                                            crate::app::signing::resolve_ms_cosigner_index(ad)
                                                        } else {
                                                            crate::app::signing::MsResolve::Ok
                                                        };
                                                        if !parsed {
                                                            ad.ms_creating = wallet::transaction::MultisigConfig::new();
                                                        }
                                                        if parsed && resolved == crate::app::signing::MsResolve::Ok {
                                                            ad.ms_creating.build_script();
                                                            boot_display.draw_success_screen("Descriptor loaded!");
                                                            sound::success(delay);
                                                            delay.delay_millis(1000);
                                                            ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                                                        } else {
                                                            boot_display.draw_rejected_screen(match resolved {
                                                                crate::app::signing::MsResolve::NoSeed => "Load a seed first",
                                                                crate::app::signing::MsResolve::NotOurs => "Not your wallet",
                                                                crate::app::signing::MsResolve::Ok => "Bad descriptor format",
                                                            });
                                                            delay.delay_millis(2000);
                                                        }
                                                    } else {
                                                        boot_display.draw_rejected_screen("Invalid descriptor");
                                                        delay.delay_millis(2000);
                                                    }
                                                }
                                                _ => {}
                                            }
                                        }
                                        Err(e) => {
                                            log!("[SD-TXT] Read failed: {}", e);
                                            // Show the driver's own message. It named the
                                            // real cause all along and was discarded here;
                                            // `log!` compiles out in a production build, so
                                            // the screen is the only channel.
                                            boot_display.draw_rejected_screen(e);
                                            delay.delay_millis(2000);
                                        }
                                    }
                                    } // close else of `if tapped_delete`
                                }
                            }
                        }
                    }
                    crate::app::input::AppState::SdKpubFilename => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::WatchOnlyMenu;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "KPUB FILENAME"); }
                                5 => { /* no space in filenames */ }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "KPUB FILENAME"); }
                                6 => {
                                    // OK — build 8.3 filename, extension TXT
                                    let name_83 = build_filename_83(&ad.pp_input.buf, ad.pp_input.len, b"TXT");
                                    ad.kspt_filename = name_83;
                                    if sd_file_exists(i2c, delay, &name_83) {
                                        ad.sd_overwrite_next = crate::app::input::AppState::SdKpubEncryptAsk;
                                        ad.sd_overwrite_back = crate::app::input::AppState::SdKpubFilename;
                                        ad.app.state = crate::app::input::AppState::SdOverwriteWarning;
                                    } else {
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdKpubEncryptAsk;
                                    }
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::SdMsAddrFilename => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "ADDRESS FILENAME"); }
                                5 => { /* no space in filenames */ }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "ADDRESS FILENAME"); }
                                6 => {
                                    // OK — build 8.3 filename, extension TXT
                                    let name_83 = build_filename_83(&ad.pp_input.buf, ad.pp_input.len, b"TXT");
                                    ad.kspt_filename = name_83;
                                    // Check if file already exists on SD
                                    if sd_file_exists(i2c, delay, &name_83) {
                                        ad.sd_overwrite_next = crate::app::input::AppState::SdMsAddrEncryptAsk;
                                        ad.sd_overwrite_back = crate::app::input::AppState::SdMsAddrFilename;
                                        ad.app.state = crate::app::input::AppState::SdOverwriteWarning;
                                    } else {
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdMsAddrEncryptAsk;
                                    }
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::SdMsAddrEncryptAsk => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                        } else {
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                // Yes — encrypt: copy address into signed_qr_buf, reuse KSPT encrypt path
                                let addr_len = ad.kpub_len;
                                ad.signed_qr_buf[..addr_len].copy_from_slice(&ad.kpub_data[..addr_len]);
                                ad.signed_qr_len = addr_len;
                                ad.sd_txt_origin = crate::app::data::SD_ORIGIN_ADDRESS;
                                // kspt_filename already has TXT extension — SdKsptEncryptPass
                                // will detect TXT and return to MultisigDescriptor after save
                                ad.pp_input.reset();
                                ad.app.state = crate::app::input::AppState::SdKsptEncryptPass;
                            } else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                // No — write plain address to SD
                                boot_display.draw_saving_screen("Saving address...");
                                let data = &ad.kpub_data[..ad.kpub_len];
                                let fname = ad.kspt_filename;
                                let write_result = write_file_to_sd(i2c, delay, &fname, data);
                                match write_result {
                                    Ok(()) => {
                                        boot_display.draw_success_screen("Address saved!");
                                        sound::success(delay);
                                        delay.delay_millis(1500);
                                    }
                                    Err(e) => {
                                        log!("SD ms-addr write error: {}", e);
                                        boot_display.draw_rejected_screen("SD write failed");
                                        sound::beep_error(delay);
                                        delay.delay_millis(2000);
                                    }
                                }
                                ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdMsDescFilename => {
                        if is_back {
                            ad.pp_input.reset();
                            ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                            needs_redraw = true;
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "DESCRIPTOR FILENAME"); }
                                5 => { /* no space in filenames */ }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "DESCRIPTOR FILENAME"); }
                                6 => {
                                    // OK — build 8.3 filename, extension TXT
                                    let name_83 = build_filename_83(&ad.pp_input.buf, ad.pp_input.len, b"TXT");
                                    ad.kspt_filename = name_83;
                                    // Check if file already exists on SD
                                    if sd_file_exists(i2c, delay, &name_83) {
                                        ad.sd_overwrite_next = crate::app::input::AppState::SdMsDescEncryptAsk;
                                        ad.sd_overwrite_back = crate::app::input::AppState::SdMsDescFilename;
                                        ad.app.state = crate::app::input::AppState::SdOverwriteWarning;
                                    } else {
                                        ad.pp_input.reset();
                                        ad.app.state = crate::app::input::AppState::SdMsDescEncryptAsk;
                                    }
                                    // Without this the state changed but nothing
                                    // repainted, so picking an EXISTING filename
                                    // left the keyboard on screen with no way
                                    // forward: the overwrite warning was active
                                    // but invisible. The identical kpub and
                                    // multisig-address arms above both set it.
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::SdMsDescEncryptAsk => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                        } else {
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                // Yes — encrypt: descriptor is already staged in signed_qr_buf
                                // by the SD CARD button in tx.rs. Just set origin and go.
                                ad.sd_txt_origin = crate::app::data::SD_ORIGIN_DESCRIPTOR;
                                ad.pp_input.reset();
                                ad.app.state = crate::app::input::AppState::SdKsptEncryptPass;
                            } else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                // No — write plain descriptor to SD (from signed_qr_buf)
                                boot_display.draw_saving_screen("Saving descriptor...");
                                let data = &ad.signed_qr_buf[..ad.signed_qr_len];
                                let fname = ad.kspt_filename;
                                let write_result = write_file_to_sd(i2c, delay, &fname, data);
                                match write_result {
                                    Ok(()) => {
                                        boot_display.draw_success_screen("Descriptor saved!");
                                        sound::success(delay);
                                        delay.delay_millis(1500);
                                    }
                                    Err(e) => {
                                        log!("SD ms-desc write error: {}", e);
                                        boot_display.draw_rejected_screen("SD write failed");
                                        sound::beep_error(delay);
                                        delay.delay_millis(2000);
                                    }
                                }
                                ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdKsptEncryptPass => {
                        if is_back {
                            ad.pp_input.reset();
                            // If we came from file list (loading encrypted), go back to file list
                            // If we came from encrypt-ask (saving), go back to popup
                            // Detect by checking kspt_encrypt flag context:
                            // When loading, kspt_filename is still [' '; 11] or irrelevant
                            // Simplest: always go back to import menu when loading, popup when saving
                            if ad.kspt_filename[8] == b'K' && ad.kspt_filename[9] == b'S' && ad.kspt_filename[10] == b'P' {
                                // KSPT save → back to encrypt ask
                                ad.app.state = crate::app::input::AppState::SdKsptEncryptAsk;
                            } else if ad.kspt_filename[8] == b'T' && ad.kspt_filename[9] == b'X' && ad.kspt_filename[10] == b'T' {
                                // TXT encrypt → back to the relevant encrypt-ask
                                if ad.sd_txt_origin == crate::app::data::SD_ORIGIN_KPUB {
                                    ad.app.state = crate::app::input::AppState::SdKpubEncryptAsk;
                                } else if ad.sd_txt_origin == crate::app::data::SD_ORIGIN_DESCRIPTOR {
                                    ad.app.state = crate::app::input::AppState::SdMsDescEncryptAsk;
                                } else {
                                    ad.app.state = crate::app::input::AppState::SdMsAddrEncryptAsk;
                                }
                            } else {
                                // Loading an encrypted file
                                ad.app.state = crate::app::input::AppState::SdKsptFileList;
                            }
                            needs_redraw = true;
                        } else {
                            match pp_keyboard_hit(x, y, &mut ad.pp_input) {
                                2 => { ad.pp_input.next_page(); boot_display.draw_keyboard_keys_only(&ad.pp_input); }
                                4 => { ad.pp_input.backspace(); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSWORD"); }
                                5 => { ad.pp_input.push_char(b' '); boot_display.draw_keyboard_screen(&ad.pp_input, "PASSWORD"); }
                                1 => { boot_display.draw_keyboard_screen(&ad.pp_input, "PASSWORD"); }
                                6 => {
                                    // OK — check if we're encrypting (save) or decrypting (load).
                                    //
                                    // CONVENTION, and a landmine: this screen is shared by
                                    // both directions and tells them apart by whether
                                    // `kspt_filename` carries an extension. A SAVE sets the
                                    // filename first; a LOAD must CLEAR it. Every entry point
                                    // that arrives here to decrypt has to do
                                    // `ad.kspt_filename = [b' '; 11]`, or a filename left over
                                    // from an earlier save in the same session sends the load
                                    // down the encrypt branch: it shows "Encrypting...",
                                    // encrypts whatever is in signed_qr_buf, and renders a QR
                                    // of the wrong bytes. The kpub, multisig-address and
                                    // multisig-descriptor load paths all missed this.
                                    let is_ksp = ad.kspt_filename[8] == b'K' && ad.kspt_filename[9] == b'S' && ad.kspt_filename[10] == b'P';
                                    let is_txt = ad.kspt_filename[8] == b'T' && ad.kspt_filename[9] == b'X' && ad.kspt_filename[10] == b'T';
                                    if is_ksp || is_txt {
                                        // SAVING: encrypt signed_qr_buf and write to SD
                                        boot_display.draw_saving_screen("Encrypting...");
                                        let pp_bytes = &ad.pp_input.buf[..ad.pp_input.len];
                                        let nonce = generate_trng_nonce();
                                        let data_len = ad.signed_qr_len;
                                        // KSPT container v1, laid out in hw/sd_backup.rs.
                                        // Replaces the hand-rolled KAS\x03 header, whose
                                        // key came from the compile-time KSPT_SALT (M-01 on
                                        // the last path that still had it) and whose AAD
                                        // bound only the magic and the length.
                                        let salt = generate_trng_salt();
                                        let enc_size = sd_backup::KSPT_V1_OVERHEAD + data_len;
                                        // data_len is bounded by SIGNED_QR_BUF_LEN, so
                                        // enc_size lands exactly on KSPT_FILE_MAX at the
                                        // largest transaction. Previously 1,024 here while
                                        // the unencrypted branch had no cap at all, so a
                                        // transaction could be saved plain and not
                                        // encrypted, with a message that named neither.
                                        if !sd_backup::kspt_v1_entropy_ok(&salt, &nonce) {
                                            // Both come from the TRNG on every path, so all
                                            // zeros means the health check failed. Writing
                                            // here would reuse a key and a nonce across two
                                            // files, which is a total GCM break.
                                            sound::stop_ticking();
                                            boot_display.draw_rejected_screen("RNG unavailable");
                                            sound::beep_error(delay);
                                            delay.delay_millis(2000);
                                        } else if enc_size <= KSPT_FILE_MAX {
                                            let mut enc_buf = alloc::vec![0u8; KSPT_FILE_MAX];
                                            enc_buf[0..4].copy_from_slice(&sd_backup::KSPT_V1_MAGIC);
                                            enc_buf[4] = sd_backup::KSPT_V1_VERSION;
                                            enc_buf[5] = sd_backup::PURPOSE_KSPT;
                                            enc_buf[6] = sd_backup::KDF_PBKDF2_SHA256_100K;
                                            enc_buf[sd_backup::KSPT_V1_LEN_OFF] = (data_len & 0xFF) as u8;
                                            enc_buf[sd_backup::KSPT_V1_LEN_OFF + 1] = ((data_len >> 8) & 0xFF) as u8;
                                            enc_buf[sd_backup::KSPT_V1_SALT_OFF
                                                ..sd_backup::KSPT_V1_SALT_OFF + salt.len()]
                                                .copy_from_slice(&salt);
                                            enc_buf[sd_backup::KSPT_V1_NONCE_OFF
                                                ..sd_backup::KSPT_V1_NONCE_OFF + nonce.len()]
                                                .copy_from_slice(&nonce);
                                            let ct = sd_backup::KSPT_V1_CT_OFF;
                                            enc_buf[ct..ct + data_len]
                                                .copy_from_slice(&ad.signed_qr_buf[..data_len]);

                                            // PBKDF2(password, per-file salt || PURPOSE_KSPT).
                                            let aes_key = sd_backup::kspt_v1_derive_key(pp_bytes, &salt, &mut |done, total| {
                                                let pct = if total > 0 { (done * 50 / total) as u8 } else { 0 };
                                                boot_display.update_progress_bar(pct);
                                            });

                                            use aes_gcm::{Aes256Gcm, aead::{AeadInPlace, KeyInit, generic_array::GenericArray}};
                                            let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
                                            let nonce_ga = GenericArray::from_slice(&nonce);
                                            // AAD is the whole header through the salt, one
                                            // contiguous slice so it cannot be assembled in
                                            // the wrong order. The old six-byte AAD bound
                                            // neither a purpose nor a salt.
                                            let mut aad = [0u8; sd_backup::KSPT_V1_HEADER_SIZE];
                                            aad.copy_from_slice(&enc_buf[..sd_backup::KSPT_V1_HEADER_SIZE]);

                                            match cipher.encrypt_in_place_detached(
                                                nonce_ga, &aad, &mut enc_buf[ct..ct + data_len]
                                            ) {
                                                Ok(tag) => {
                                                    enc_buf[ct + data_len..ct + data_len + sd_backup::KSPT_TAG_SIZE].copy_from_slice(&tag);
                                                    boot_display.update_progress_bar(70);
                                                    boot_display.draw_saving_screen("Writing to SD...");
                                                    let fname = ad.kspt_filename;
                                                    let write_result = write_file_to_sd(i2c, delay, &fname, &enc_buf[..enc_size]);
                                                    sound::stop_ticking();
                                                    match write_result {
                                                        Ok(()) => {
                                                            boot_display.update_progress_bar(100);
                                                            let mut disp_buf = [0u8; 13];
                                                            let dlen = sd_backup::format_83_display(&fname, &mut disp_buf);
                                                            let name_str = core::str::from_utf8(&disp_buf[..dlen]).unwrap_or("?");
                                                            log!("[SD-KSPT] Encrypted {} bytes as {}", data_len, name_str);
                                                            boot_display.draw_success_screen("Saved!");
                                                            sound::success(delay);
                                                            delay.delay_millis(1500);
                                                        }
                                                        Err(e) => {
                                                            log!("[SD-KSPT] Write failed: {}", e);
                                                            boot_display.draw_rejected_screen("SD write failed");
                                                            sound::beep_error(delay);
                                                            delay.delay_millis(2000);
                                                        }
                                                    }
                                                }
                                                Err(_) => {
                                                    sound::stop_ticking();
                                                    boot_display.draw_rejected_screen("Encryption failed");
                                                    sound::beep_error(delay);
                                                    delay.delay_millis(2000);
                                                }
                                            }
                                            zeroize_buf(&mut enc_buf[..64]);
                                        } else {
                                            boot_display.draw_rejected_screen("TX too large");
                                            delay.delay_millis(2000);
                                        }
                                        ad.pp_input.reset();
                                        if is_txt {
                                            if ad.sd_txt_origin == crate::app::data::SD_ORIGIN_KPUB {
                                                ad.app.state = crate::app::input::AppState::ExportChoice;
                                            } else {
                                                ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                                            }
                                        } else {
                                            ad.app.go_main_menu();
                                        }
                                    } else {
                                        // LOADING: decrypt encrypted KSPT from signed_qr_buf
                                        boot_display.draw_loading_screen("Decrypting TX...");
                                        let pp_bytes_len = ad.pp_input.len;
                                        // 128, matching PassphraseInput::buf, not the 64 of the seed and
                                        // xprv destinations. The read side has to hold whatever some
                                        // writer already emitted, and a shorter buffer here panicked on
                                        // the slice index before the password was ever tried. Every
                                        // consumer below takes &pp_copy[..pp_bytes_len], and the wipe
                                        // iterates the whole array, so both follow the size.
                                        let mut pp_copy = [0u8; 128];
                                        pp_copy[..pp_bytes_len].copy_from_slice(&ad.pp_input.buf[..pp_bytes_len]);

                                        // Two container formats. KAS\x06 is written from
                                        // now on; KAS\x03 stays readable forever. Offsets,
                                        // AAD length and key derivation all differ, so the
                                        // format is resolved once here rather than branched
                                        // at each use below.
                                        let file_len = ad.signed_qr_len;
                                        let is_v1 = file_len >= 4
                                            && ad.signed_qr_buf[..4] == sd_backup::KSPT_V1_MAGIC;
                                        let is_legacy = file_len >= 4
                                            && ad.signed_qr_buf[0] == b'K'
                                            && ad.signed_qr_buf[1] == b'A'
                                            && ad.signed_qr_buf[2] == b'S'
                                            && ad.signed_qr_buf[3] == 0x03;
                                        let (len_off, ct_start, aad_len) = if is_v1 {
                                            (sd_backup::KSPT_V1_LEN_OFF,
                                             sd_backup::KSPT_V1_CT_OFF,
                                             sd_backup::KSPT_V1_HEADER_SIZE)
                                        } else {
                                            (sd_backup::KSPT_LEGACY_LEN_OFF,
                                             sd_backup::KSPT_LEGACY_CT_OFF,
                                             6usize)
                                        };
                                        if (is_v1 || is_legacy)
                                            && file_len >= ct_start + 1 + sd_backup::KSPT_TAG_SIZE
                                        {
                                            let data_len = ad.signed_qr_buf[len_off] as usize
                                                | ((ad.signed_qr_buf[len_off + 1] as usize) << 8);
                                            let expected = ct_start + data_len + sd_backup::KSPT_TAG_SIZE;
                                            if expected <= file_len && data_len <= KSPT_IMPORT_BUF {
                                                let tag_start = ct_start + data_len;
                                                // Copied out, not borrowed: the buffer is
                                                // written back in place further down, and a
                                                // live borrow of it here would not survive.
                                                let mut nonce_arr = [0u8; sd_backup::KSPT_NONCE_SIZE];
                                                nonce_arr.copy_from_slice(
                                                    &ad.signed_qr_buf[ct_start - sd_backup::KSPT_NONCE_SIZE..ct_start]);
                                                let mut aad_buf = [0u8; sd_backup::KSPT_V1_HEADER_SIZE];
                                                aad_buf[..aad_len].copy_from_slice(&ad.signed_qr_buf[..aad_len]);

                                                let aes_key = if is_v1 {
                                                    let mut salt = [0u8; sd_backup::V3_SALT_SIZE];
                                                    salt.copy_from_slice(
                                                        &ad.signed_qr_buf[sd_backup::KSPT_V1_SALT_OFF
                                                            ..sd_backup::KSPT_V1_SALT_OFF + sd_backup::V3_SALT_SIZE]);
                                                    sd_backup::kspt_v1_derive_key(
                                                        &pp_copy[..pp_bytes_len],
                                                        &salt,
                                                        &mut |done, total| {
                                                            let pct = if total > 0 { (done * 70 / total) as u8 } else { 0 };
                                                            boot_display.update_progress_bar(pct);
                                                        },
                                                    )
                                                } else {
                                                    sd_backup::pbkdf2_key_for_kspt(
                                                        &pp_copy[..pp_bytes_len],
                                                        &mut |done, total| {
                                                            let pct = if total > 0 { (done * 70 / total) as u8 } else { 0 };
                                                            boot_display.update_progress_bar(pct);
                                                        },
                                                    )
                                                };

                                                use aes_gcm::{Aes256Gcm, aead::{AeadInPlace, KeyInit, generic_array::GenericArray}};
                                                let cipher = Aes256Gcm::new(GenericArray::from_slice(&aes_key));
                                                let nonce_ga = GenericArray::from_slice(&nonce_arr);
                                                let tag = GenericArray::from_slice(
                                                    &ad.signed_qr_buf[tag_start..tag_start + sd_backup::KSPT_TAG_SIZE]);
                                                let aad = &aad_buf[..aad_len];

                                                // Decrypt in-place over the ciphertext area.
                                                //
                                                // Heap, not stack: at KSPT_IMPORT_BUF this
                                                // is 8 KB, and a stack slot lives for the
                                                // whole extent of its function. That is the
                                                // same mechanism that put `signed_qr_buf`
                                                // on the heap.
                                                let mut plain = alloc::vec![0u8; KSPT_IMPORT_BUF];
                                                plain[..data_len].copy_from_slice(
                                                    &ad.signed_qr_buf[ct_start..ct_start + data_len]);

                                                match cipher.decrypt_in_place_detached(
                                                    nonce_ga, aad, &mut plain[..data_len], tag
                                                ) {
                                                    Ok(()) => {
                                                        ad.signed_qr_buf[..data_len].copy_from_slice(&plain[..data_len]);
                                                        ad.signed_qr_len = data_len;
                                                        ad.signed_qr_frame = 0;
                                                        ad.signed_qr_nframes = 0;
                                                        ad.signed_qr_large = false;
                                                        ad.tx_sigs_present = 0;
                                                        ad.tx_sigs_required = 0;
                                                        log!("[SD-KSPT] Decrypted {} bytes", data_len);

                                                        // Detect content type after decryption
                                                        let is_descriptor = looks_like_descriptor(&plain[..data_len]);

                                                        if ad.sd_txt_origin == crate::app::data::SD_ORIGIN_DESCRIPTOR {
                                                            // Descriptor import path — only accept descriptors
                                                            if is_descriptor {
                                                                // One loader for both schemes: it reads `multi_hd45(` or
                                                                // `multi_hd(` from the file and sets `v45` accordingly, and it
                                                                // leaves the config untouched on failure so a bad descriptor
                                                                // cannot half-load over a good one.
                                                                //
                                                                // The three outcomes get three messages on purpose. A 45'
                                                                // descriptor loaded with no seed is NOT bad, and saying so
                                                                // would send the user to check a file that is fine.
                                                                let parsed = load_descriptor_into(&mut ad.ms_creating, &plain[..data_len]);
                                                                let resolved = if parsed {
                                                                    crate::app::signing::resolve_ms_cosigner_index(ad)
                                                                } else {
                                                                    crate::app::signing::MsResolve::Ok
                                                                };
                                                                if !parsed {
                                                                    ad.ms_creating = wallet::transaction::MultisigConfig::new();
                                                                }
                                                                if parsed && resolved == crate::app::signing::MsResolve::Ok {
                                                                    ad.ms_creating.build_script();
                                                                    boot_display.draw_success_screen("Descriptor loaded!");
                                                                    sound::success(delay);
                                                                    delay.delay_millis(1000);
                                                                    ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                                                                } else {
                                                                    // Name the actual cause. "Bad descriptor" for a good file
                                                                    // that simply has no seed to compare against is a wrong
                                                                    // diagnosis, and it points the user at the file.
                                                                    boot_display.draw_rejected_screen(match resolved {
                                                                        crate::app::signing::MsResolve::NoSeed => "Load a seed first",
                                                                        crate::app::signing::MsResolve::NotOurs => "Not your wallet",
                                                                        crate::app::signing::MsResolve::Ok => "Bad descriptor",
                                                                    });
                                                                    delay.delay_millis(2000);
                                                                    ad.app.state = crate::app::input::AppState::SdImportMenu;
                                                                }
                                                            } else {
                                                                boot_display.draw_rejected_screen("Not a descriptor");
                                                                delay.delay_millis(2000);
                                                                ad.app.state = crate::app::input::AppState::SdImportMenu;
                                                            }
                                                        } else if ad.sd_txt_origin == crate::app::data::SD_ORIGIN_KPUB {
                                                            // Kpub import path — only accept kpub content
                                                            let is_kpub_ascii = data_len >= 4 && &plain[..4] == b"kpub";
                                                            let is_kpub_v1raw = data_len == 79 && plain[0] == 0x01;
                                                            if (is_kpub_ascii || is_kpub_v1raw) && data_len <= wallet::xpub::KPUB_MAX_LEN {
                                                                ad.kpub_data[..data_len].copy_from_slice(&plain[..data_len]);
                                                                ad.kpub_len = data_len;
                                                                ad.kpub_frame = 0;
                                                                ad.kpub_nframes = 0;
                                                                boot_display.draw_success_screen("Kpub loaded!");
                                                                sound::success(delay);
                                                                delay.delay_millis(1000);
                                                                ad.app.state = crate::app::input::AppState::ExportKpub;
                                                            } else {
                                                                boot_display.draw_rejected_screen("Not a valid kpub");
                                                                delay.delay_millis(2000);
                                                                ad.app.state = crate::app::input::AppState::SdImportMenu;
                                                            }
                                                        } else if ad.sd_txt_origin == crate::app::data::SD_ORIGIN_ADDRESS {
                                                            // Address import path — only accept kaspa addresses
                                                            let is_addr = data_len >= 6
                                                                && (&plain[..6] == b"kaspa:" || (data_len >= 10 && &plain[..10] == b"kaspatest:"));
                                                            if is_addr && data_len <= wallet::xpub::KPUB_MAX_LEN {
                                                                ad.kpub_data[..data_len].copy_from_slice(&plain[..data_len]);
                                                                ad.kpub_len = data_len;
                                                                ad.ms_creating.active = false;
                                                                ad.signed_qr_buf[..data_len].copy_from_slice(&plain[..data_len]);
                                                                ad.signed_qr_len = data_len;
                                                                boot_display.draw_success_screen("Address loaded!");
                                                                sound::success(delay);
                                                                delay.delay_millis(1000);
                                                                ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                                                            } else {
                                                                boot_display.draw_rejected_screen("Not a valid address");
                                                                delay.delay_millis(2000);
                                                                ad.app.state = crate::app::input::AppState::SdImportMenu;
                                                            }
                                                        } else {
                                                            // KSPT import path — route by content
                                                            let is_address = data_len >= 6
                                                                && (&plain[..6] == b"kaspa:" || (data_len >= 10 && &plain[..10] == b"kaspatest:"));

                                                            if is_descriptor {
                                                                // One loader for both schemes: it reads `multi_hd45(` or
                                                                // `multi_hd(` from the file and sets `v45` accordingly, and it
                                                                // leaves the config untouched on failure so a bad descriptor
                                                                // cannot half-load over a good one.
                                                                //
                                                                // The three outcomes get three messages on purpose. A 45'
                                                                // descriptor loaded with no seed is NOT bad, and saying so
                                                                // would send the user to check a file that is fine.
                                                                let parsed = load_descriptor_into(&mut ad.ms_creating, &plain[..data_len]);
                                                                let resolved = if parsed {
                                                                    crate::app::signing::resolve_ms_cosigner_index(ad)
                                                                } else {
                                                                    crate::app::signing::MsResolve::Ok
                                                                };
                                                                if !parsed {
                                                                    ad.ms_creating = wallet::transaction::MultisigConfig::new();
                                                                }
                                                                if parsed && resolved == crate::app::signing::MsResolve::Ok {
                                                                    ad.ms_creating.build_script();
                                                                    boot_display.draw_success_screen("Descriptor loaded!");
                                                                    sound::success(delay);
                                                                    delay.delay_millis(1000);
                                                                    ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                                                                } else {
                                                                    // Name the actual cause. "Bad descriptor" for a good file
                                                                    // that simply has no seed to compare against is a wrong
                                                                    // diagnosis, and it points the user at the file.
                                                                    boot_display.draw_rejected_screen(match resolved {
                                                                        crate::app::signing::MsResolve::NoSeed => "Load a seed first",
                                                                        crate::app::signing::MsResolve::NotOurs => "Not your wallet",
                                                                        crate::app::signing::MsResolve::Ok => "Bad descriptor",
                                                                    });
                                                                    delay.delay_millis(2000);
                                                                    ad.app.state = crate::app::input::AppState::SdKsptFileList;
                                                                }
                                                            } else if is_address {
                                                                ad.kpub_data[..data_len].copy_from_slice(&plain[..data_len]);
                                                                ad.kpub_len = data_len;
                                                                ad.ms_creating.active = false;
                                                                boot_display.draw_success_screen("Address loaded!");
                                                                sound::success(delay);
                                                                delay.delay_millis(1000);
                                                                ad.app.state = crate::app::input::AppState::MultisigShowAddress;
                                                            } else {
                                                                boot_display.draw_success_screen("TX loaded!");
                                                                sound::success(delay);
                                                                delay.delay_millis(1000);
                                                                ad.app.state = crate::app::input::AppState::ShowQrFrameChoice;
                                                            }
                                                        }
                                                    }
                                                    Err(_) => {
                                                        boot_display.draw_rejected_screen("Wrong password");
                                                        sound::beep_error(delay);
                                                        delay.delay_millis(2000);
                                                        ad.signed_qr_len = 0;
                                                        ad.app.state = crate::app::input::AppState::SdKsptFileList;
                                                    }
                                                }
                                                zeroize_buf(&mut plain[..64]);
                                            } else {
                                                boot_display.draw_rejected_screen("Invalid file");
                                                delay.delay_millis(2000);
                                                ad.signed_qr_len = 0;
                                                ad.app.state = crate::app::input::AppState::SdKsptFileList;
                                            }
                                        } else {
                                            boot_display.draw_rejected_screen("Invalid file");
                                            delay.delay_millis(2000);
                                            ad.signed_qr_len = 0;
                                            ad.app.state = crate::app::input::AppState::SdKsptFileList;
                                        }
                                        for b in pp_copy.iter_mut() {
                                            unsafe { core::ptr::write_volatile(b, 0); }
                                        }
                                        ad.pp_input.reset();
                                    }
                                    needs_redraw = true;
                                }
                                _ => {}
                            }
                        }
                    }
                    crate::app::input::AppState::ShowQrModeChoice => {
                        if is_back {
                            ad.signed_qr_nframes = 0;
                            if ad.signed_qr_via_density {
                                ad.app.state = crate::app::input::AppState::ShowQrDensityChoice;
                            } else if ad.ms_creating.n > 0 {
                                // Descriptor QR — back to descriptor view
                                ad.app.state = crate::app::input::AppState::MultisigDescriptor;
                            } else {
                                ad.app.go_main_menu();
                            }
                        } else {
                            // "Auto Cycle" button: left
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                ad.qr_manual_frames = false;
                                ad.signed_qr_frame = 0; // start at frame 0 so the
                                // frame-0 screen clear in redraw fires and wipes the
                                // mode-choice text (Manual already resets this).
                                ad.app.state = crate::app::input::AppState::ShowQR;
                            }
                            // "Manual" button: right
                            else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                ad.qr_manual_frames = true;
                                ad.signed_qr_frame = 0;
                                ad.app.state = crate::app::input::AppState::ShowQR;
                            }
                        }
                        needs_redraw = true;
                    }
                    crate::app::input::AppState::SdOverwriteWarning => {
                        if is_back {
                            // Return to the filename keyboard that brought us here
                            ad.app.state = ad.sd_overwrite_back;
                            needs_redraw = true;
                        } else {
                            // "Yes" button — left: proceed with overwrite
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                ad.pp_input.reset();
                                ad.app.state = ad.sd_overwrite_next;
                                needs_redraw = true;
                            }
                            // "No" button — right: return to filename keyboard
                            else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                ad.app.state = ad.sd_overwrite_back;
                            }
                        }
                    }
                    crate::app::input::AppState::SdKpubEncryptAsk => {
                        if is_back {
                            ad.app.state = crate::app::input::AppState::WatchOnlyMenu;
                            needs_redraw = true;
                        } else {
                            if (30..=155).contains(&x) && (140..=185).contains(&y) {
                                // Yes — encrypt
                                let kpub_len = ad.kpub_len;
                                ad.signed_qr_buf[..kpub_len].copy_from_slice(&ad.kpub_data[..kpub_len]);
                                ad.signed_qr_len = kpub_len;
                                ad.sd_txt_origin = crate::app::data::SD_ORIGIN_KPUB;
                                ad.pp_input.reset();
                                ad.app.state = crate::app::input::AppState::SdKsptEncryptPass;
                                needs_redraw = true;
                            } else if (165..=290).contains(&x) && (140..=185).contains(&y) {
                                // No — write plain kpub to SD
                                boot_display.draw_saving_screen("Saving kpub...");
                                let data = &ad.kpub_data[..ad.kpub_len];
                                let fname = ad.kspt_filename;
                                let write_result = write_file_to_sd(i2c, delay, &fname, data);
                                match write_result {
                                    Ok(()) => {
                                        boot_display.draw_success_screen("kpub saved!");
                                        sound::success(delay);
                                        delay.delay_millis(1500);
                                    }
                                    Err(e) => {
                                        log!("SD kpub write error: {}", e);
                                        boot_display.draw_rejected_screen("SD write failed");
                                        sound::beep_error(delay);
                                        delay.delay_millis(2000);
                                    }
                                }
                                ad.app.state = crate::app::input::AppState::WatchOnlyMenu;
                                needs_redraw = true;
                            }
                        }
                    }
                    _ => { return None; }
                }
    Some(needs_redraw)
}
