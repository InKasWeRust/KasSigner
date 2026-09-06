//! Shared bounded discovery and complete-file reading for SD-card content.

use crate::{
    hw::sdcard,
    runtime::data::TextFileList,
};

const MAX_FILES: usize = 8;

pub fn scan_text_files(
    maximum_size: u32,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Result<TextFileList, &'static str> {
    let _ = &mut *i2c;
    let mut files = TextFileList::empty();
    sdcard::with_sd_card!(i2c, delay, |card| {
        let fat32 = sdcard::mount_fat32(card)?;
        sdcard::list_root_dir_lfn(card, &fat32, |entry, display_name, display_len| {
            capture_text_file(&mut files, maximum_size, entry, display_name, display_len)
        })?;
        Ok(())
    })?;
    Ok(files)
}

/// Read the complete file into the caller-selected buffer.
///
/// The function rejects files larger than `output`; it never truncates. UTF-8
/// BOM removal and trailing ASCII whitespace trimming happen only after the
/// complete bounded file has been read successfully.
pub fn read_text_file(
    filename: &[u8; 11],
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
    output: &mut [u8],
) -> Result<usize, &'static str> {
    let _ = &mut *i2c;
    output.fill(0);
    sdcard::with_sd_card!(i2c, delay, |card| {
        let fat32 = sdcard::mount_fat32(card)?;
        let (entry, _, _) = sdcard::find_file_in_root(card, &fat32, filename)?;
        validate_text_file_size(entry.file_size as usize, output.len())?;
        let length = sdcard::read_file(card, &fat32, &entry, output)?;
        normalize_text_content(output, length)
    })
}

pub fn scan_jpeg_files(
    file_names: &mut [[u8; 11]; MAX_FILES],
    display_names: &mut [[u8; 32]; MAX_FILES],
    display_lens: &mut [u8; MAX_FILES],
    file_count: &mut u8,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Result<u8, &'static str> {
    let _ = &mut *i2c;
    *file_count = 0;
    sdcard::with_sd_card!(i2c, delay, |card| {
        let fat32 = sdcard::mount_fat32(card)?;
        sdcard::list_root_dir_lfn(card, &fat32, |entry, display_name, display_len| {
            let index = *file_count as usize;
            if entry.is_dir() || entry.file_size == 0 || index >= MAX_FILES {
                return true;
            }
            let extension = &entry.name[8..11];
            let hidden = matches!(entry.name[0], b'.' | b'_' | 0xE5);
            let jpeg = extension.eq_ignore_ascii_case(b"JPG")
                || extension.eq_ignore_ascii_case(b"JPE");
            if hidden || !jpeg {
                return true;
            }
            file_names[index] = entry.name;
            let copy_len = display_len.min(32);
            display_names[index] = [0u8; 32];
            display_names[index][..copy_len].copy_from_slice(&display_name[..copy_len]);
            display_lens[index] = copy_len as u8;
            *file_count += 1;
            true
        })?;
        Ok(())
    })?;
    Ok(*file_count)
}

pub fn scan_short_name_files(
    file_names: &mut [[u8; 11]; MAX_FILES],
    file_count: &mut u8,
    extensions: &[[u8; 3]],
    maximum_size: u32,
    exclude_hidden: bool,
    delay: &mut esp_hal::delay::Delay,
    i2c: &mut esp_hal::i2c::master::I2c<'_, esp_hal::Blocking>,
) -> Result<u8, &'static str> {
    let _ = &mut *i2c;
    *file_count = 0;
    sdcard::with_sd_card!(i2c, delay, |card| {
        let fat32 = sdcard::mount_fat32(card)?;
        sdcard::list_root_dir(card, &fat32, |entry| {
            let index = *file_count as usize;
            if entry.is_dir()
                || entry.file_size == 0
                || entry.file_size > maximum_size
                || index >= MAX_FILES
            {
                return true;
            }
            let hidden = matches!(entry.name[0], b'.' | b'_' | 0xE5);
            let extension = [entry.name[8], entry.name[9], entry.name[10]];
            let matches_extension = extensions
                .iter()
                .any(|candidate| extension.eq_ignore_ascii_case(candidate));
            if (exclude_hidden && hidden) || !matches_extension {
                return true;
            }
            file_names[index] = entry.name;
            *file_count += 1;
            true
        })?;
        Ok(())
    })?;
    Ok(*file_count)
}

fn capture_text_file(
    files: &mut TextFileList,
    maximum_size: u32,
    entry: &sdcard::DirEntry,
    display_name: &[u8],
    display_len: usize,
) -> bool {
    let index = files.file_count as usize;
    if entry.is_dir()
        || entry.file_size == 0
        || entry.file_size > maximum_size
        || index >= MAX_FILES
    {
        return true;
    }

    let extension = &entry.name[8..11];
    let hidden = matches!(entry.name[0], b'.' | b'_' | 0xE5);
    if hidden || !extension.eq_ignore_ascii_case(b"TXT") {
        return true;
    }

    let copy_len = display_len.min(32);
    files.file_names[index] = entry.name;
    files.display_names[index] = [0u8; 32];
    files.display_names[index][..copy_len].copy_from_slice(&display_name[..copy_len]);
    files.display_lens[index] = copy_len as u8;
    files.file_count += 1;
    true
}

fn validate_text_file_size(file_size: usize, capacity: usize) -> Result<(), &'static str> {
    if file_size > capacity {
        Err("Text file exceeds buffer")
    } else {
        Ok(())
    }
}

fn normalize_text_content(output: &mut [u8], length: usize) -> Result<usize, &'static str> {
    if length > output.len() {
        return Err("Text file exceeds buffer");
    }

    let start = if length >= 3 && output[..3] == [0xEF, 0xBB, 0xBF] {
        3
    } else {
        0
    };
    let mut end = length;
    while end > start && matches!(output[end - 1], b'\n' | b'\r' | b' ' | b'\t' | 0) {
        end -= 1;
    }
    if end == start {
        output[..length].fill(0);
        return Err("Empty content");
    }

    let normalized_length = end - start;
    if start > 0 {
        output.copy_within(start..end, 0);
    }
    output[normalized_length..length].fill(0);
    Ok(normalized_length)
}

#[cfg(test)]
#[path = "unit_tests/storage_files_tests.rs"]
mod unit_tests;
