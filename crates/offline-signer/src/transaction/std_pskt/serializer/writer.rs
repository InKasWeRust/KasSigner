//! One-pass hexadecimal JSON writer.

use crate::transaction::model::ScriptPublicKey;

use super::super::PskError;

/// `write_scratch_range` reads from the original JSON and hex-encodes
/// without a second round-trip.
pub(super) struct HexWriter<'a> {
    pub(super) out: &'a mut [u8],
    pub(super) pos: usize,
    pub(super) scratch: &'a [u8],
}

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

impl<'a> HexWriter<'a> {
    /// Write one raw byte, producing 2 hex chars.
    pub(super) fn byte(&mut self, b: u8) -> Result<(), PskError> {
        let Some(end) = self.pos.checked_add(2) else {
            return Err(PskError::OutputBufferTooSmall);
        };
        let destination = self
            .out
            .get_mut(self.pos..end)
            .ok_or(PskError::OutputBufferTooSmall)?;
        destination[0] = HEX_CHARS[(b >> 4) as usize];
        destination[1] = HEX_CHARS[(b & 0x0F) as usize];
        self.pos = end;
        Ok(())
    }

    /// Write a byte slice, producing `2 * slice.len()` hex chars.
    pub(super) fn bytes(&mut self, s: &[u8]) -> Result<(), PskError> {
        let Some(encoded_len) = s.len().checked_mul(2) else {
            return Err(PskError::OutputBufferTooSmall);
        };
        let Some(end) = self.pos.checked_add(encoded_len) else {
            return Err(PskError::OutputBufferTooSmall);
        };
        if end > self.out.len() {
            return Err(PskError::OutputBufferTooSmall);
        }
        for &b in s {
            self.out[self.pos] = HEX_CHARS[(b >> 4) as usize];
            self.out[self.pos + 1] = HEX_CHARS[(b & 0x0F) as usize];
            self.pos += 2;
        }
        Ok(())
    }

    /// Alias for `bytes` when emitting a JSON literal fragment
    /// (`{`, `":"`, `,`, etc.). Named differently for readability at
    /// call sites.
    #[inline]
    pub(super) fn lit(&mut self, s: &[u8]) -> Result<(), PskError> {
        self.bytes(s)
    }

    /// Splice a byte-range from scratch into the output, hex-encoded.
    /// Used for captured unknown regions during parse.
    pub(super) fn scratch_range(&mut self, start: u16, end: u16) -> Result<(), PskError> {
        let (s, e) = (start as usize, end as usize);
        let slice = self.scratch.get(s..e).ok_or(PskError::UnexpectedToken)?;
        self.bytes(slice)
    }

    /// Write a decimal u64. Max 20 digits.
    pub(super) fn u64(&mut self, mut v: u64) -> Result<(), PskError> {
        if v == 0 {
            return self.byte(b'0');
        }
        let mut buf = [0u8; 20];
        let mut i = buf.len();
        while v > 0 {
            i -= 1;
            buf[i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        self.bytes(&buf[i..])
    }

    /// Write an exact u64 as a canonical decimal JSON string.
    pub(super) fn u64_string(&mut self, value: u64) -> Result<(), PskError> {
        self.lit(b"\"")?;
        self.u64(value)?;
        self.lit(b"\"")
    }

    /// Write a hex-string field: `"<hex of bytes>"`. Useful for
    /// `transactionId`, `signature` values, etc., where the source is
    /// raw bytes that need to be lowercase-hex-stringified.
    pub(super) fn hex_string_field(&mut self, bytes: &[u8]) -> Result<(), PskError> {
        self.lit(b"\"")?;
        // The *string contents* are hex chars. Each hex char is itself
        // one byte on the wire, which then gets hex-encoded into two
        // chars. Net: each source byte becomes four chars in `out`.
        // We emit via .byte() of the ASCII hex chars.
        for &b in bytes {
            self.byte(HEX_CHARS[(b >> 4) as usize])?;
            self.byte(HEX_CHARS[(b & 0x0F) as usize])?;
        }
        self.lit(b"\"")?;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════

fn emit_script_version(w: &mut HexWriter<'_>, version: u16) -> Result<(), PskError> {
    w.byte(HEX_CHARS[((version >> 12) & 0x0F) as usize])?;
    w.byte(HEX_CHARS[((version >> 8) & 0x0F) as usize])?;
    w.byte(HEX_CHARS[((version >> 4) & 0x0F) as usize])?;
    w.byte(HEX_CHARS[(version & 0x0F) as usize])
}

fn emit_script_bytes(w: &mut HexWriter<'_>, bytes: &[u8]) -> Result<(), PskError> {
    for &byte in bytes {
        w.byte(HEX_CHARS[(byte >> 4) as usize])?;
        w.byte(HEX_CHARS[(byte & 0x0F) as usize])?;
    }
    Ok(())
}

pub(super) fn emit_script_public_key(
    w: &mut HexWriter<'_>,
    spk: &ScriptPublicKey,
) -> Result<(), PskError> {
    if spk.script_len > spk.script.len() {
        return Err(PskError::InvalidScriptLen);
    }
    w.lit(b"\"")?;
    emit_script_version(w, spk.version)?;
    emit_script_bytes(w, &spk.script[..spk.script_len])?;
    w.lit(b"\"")
}
