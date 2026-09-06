//! Pure FAT32 long-file-name accumulation and directory-entry classification.

const MAX_LFN_PARTS: usize = 4;
const UTF16_BYTES_PER_PART: usize = 26;
const CHARS_PER_PART: usize = 13;
const MAX_DISPLAY_BYTES: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectoryEntryKind {
    End,
    Deleted,
    LongName,
    Volume,
    Regular,
}

pub fn classify_directory_entry(raw: &[u8]) -> DirectoryEntryKind {
    if raw.first() == Some(&0x00) {
        DirectoryEntryKind::End
    } else if raw.first() == Some(&0xE5) {
        DirectoryEntryKind::Deleted
    } else if raw.get(11) == Some(&0x0F) {
        DirectoryEntryKind::LongName
    } else if raw.get(11).is_some_and(|attributes| attributes & 0x08 != 0) {
        DirectoryEntryKind::Volume
    } else {
        DirectoryEntryKind::Regular
    }
}

pub struct LfnAccumulator {
    display: [u8; 64],
    parts: [[u8; UTF16_BYTES_PER_PART]; MAX_LFN_PARTS],
    part_count: usize,
}

impl LfnAccumulator {
    pub const fn new() -> Self {
        Self {
            display: [0; 64],
            parts: [[0; UTF16_BYTES_PER_PART]; MAX_LFN_PARTS],
            part_count: 0,
        }
    }

    pub fn reset(&mut self) {
        self.part_count = 0;
    }

    pub fn record(&mut self, raw: &[u8]) {
        let Some(&sequence_byte) = raw.first() else {
            return;
        };
        let sequence = sequence_byte & 0x3F;
        if !(1..=MAX_LFN_PARTS as u8).contains(&sequence)
            || self.part_count >= MAX_LFN_PARTS
            || raw.len() < 32
        {
            return;
        }
        let index = (sequence - 1) as usize;
        let part = &mut self.parts[index];
        part[0..10].copy_from_slice(&raw[1..11]);
        part[10..22].copy_from_slice(&raw[14..26]);
        part[22..26].copy_from_slice(&raw[28..32]);
        self.part_count = self.part_count.max(index + 1);
    }

    pub fn display_name(&mut self, short_name: &[u8; 11]) -> (&[u8; 64], usize) {
        let mut length = self.decode_lfn();
        if length == 0 {
            length = format_83_display(short_name, &mut self.display);
        }
        (&self.display, length)
    }

    fn decode_lfn(&mut self) -> usize {
        let mut length = 0usize;
        for index in 0..self.part_count {
            length = append_part(&self.parts[index], &mut self.display, length);
        }
        length
    }
}

impl Default for LfnAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

pub fn format_83_display(name: &[u8; 11], out: &mut [u8]) -> usize {
    let base_len = trimmed_len(&name[..8]);
    out[..base_len].copy_from_slice(&name[..base_len]);
    let extension_len = trimmed_len(&name[8..]);
    if extension_len == 0 {
        return base_len;
    }
    out[base_len] = b'.';
    out[base_len + 1..base_len + 1 + extension_len].copy_from_slice(&name[8..8 + extension_len]);
    base_len + 1 + extension_len
}

fn trimmed_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(0, |index| index + 1)
}

fn append_part(
    part: &[u8; UTF16_BYTES_PER_PART],
    display: &mut [u8; 64],
    mut length: usize,
) -> usize {
    for index in 0..CHARS_PER_PART {
        let low = part[index * 2];
        let high = part[index * 2 + 1];
        if is_terminator(low, high) || length >= MAX_DISPLAY_BYTES {
            break;
        }
        if let Some(byte) = display_byte(low, high) {
            display[length] = byte;
            length += 1;
        }
    }
    length
}

fn is_terminator(low: u8, high: u8) -> bool {
    (low == 0xFF && high == 0xFF) || (low == 0 && high == 0)
}

fn display_byte(low: u8, high: u8) -> Option<u8> {
    if high > 0 {
        Some(b'_')
    } else if (0x20..0x7F).contains(&low) {
        Some(low)
    } else if low >= 0x80 {
        Some(map_latin1(low))
    } else {
        None
    }
}

fn map_latin1(byte: u8) -> u8 {
    if byte == 0xA0 {
        return b' ';
    }
    if byte < 0xE0 {
        map_latin1_upper(byte)
    } else {
        map_latin1_lower(byte)
    }
}

fn map_latin1_upper(byte: u8) -> u8 {
    match byte {
        0xC0..=0xC5 => b'A',
        0xC7 => b'C',
        0xC8..=0xCB => b'E',
        0xCC..=0xCF => b'I',
        0xD1 => b'N',
        0xD2..=0xD6 => b'O',
        0xD9..=0xDC => b'U',
        _ => b'_',
    }
}

fn map_latin1_lower(byte: u8) -> u8 {
    match byte {
        0xE0..=0xE5 => b'a',
        0xE7 => b'c',
        0xE8..=0xEB => b'e',
        0xEC..=0xEF => b'i',
        0xF1 => b'n',
        0xF2..=0xF6 => b'o',
        0xF9..=0xFC => b'u',
        _ => b'_',
    }
}
