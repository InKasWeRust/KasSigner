// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! JPEG steganography façade with metadata and coefficient carriers.

mod exif;
mod jpeg;
mod payload;
mod portable;

pub use exif::{
    build_copyforward as build_exif_copyforward,
    build_template as build_exif_template,
    extract_user_comment,
    find_app1 as find_exif_app1,
    format_datetime as format_exif_datetime,
    jpeg_dimensions,
    SOFTWARE_TABLE,
};
pub use jpeg::inject_exif;
pub const STEGO_PAYLOAD_SIZE: usize = payload::PAYLOAD_SIZE;

pub fn pack_payload(
    security: StegoSecurity,
    carrier: StegoCarrier,
    indices: &[u16; 24],
    word_count: u8,
    hint: &[u8],
    descriptor: &[u8],
    portable_password: &[u8],
    device: &mut dyn crate::services::backup::BackupDevice,
    output: &mut [u8],
) -> Result<usize, &'static str> {
    payload::pack(
        security, carrier, indices, word_count, hint, descriptor, portable_password, device, output,
    ).map_err(payload::PayloadError::message)
}

pub fn unpack_device_bound_payload(
    carrier: StegoCarrier,
    input: &[u8],
    descriptor: &[u8],
    device: &mut dyn crate::services::backup::BackupDevice,
    indices: &mut [u16; 24],
    hint: &mut [u8; 64],
) -> Result<(u8, usize), &'static str> {
    payload::unpack_device_bound(carrier, input, descriptor, device, indices, hint)
        .map_err(payload::PayloadError::message)
}

pub fn unpack_portable_payload(
    carrier: StegoCarrier,
    input: &[u8],
    descriptor: &[u8],
    password: &[u8],
    indices: &mut [u16; 24],
    hint: &mut [u8; 64],
) -> Result<(u8, usize), &'static str> {
    payload::unpack_portable(carrier, input, descriptor, password, indices, hint)
        .map_err(payload::PayloadError::message)
}

pub fn validate_portable_password(password: &[u8]) -> Result<(), &'static str> {
    match portable::validate_password(password) {
        Ok(()) => Ok(()),
        Err(_) => Err("Use 8+ chars with a letter and number"),
    }
}

#[cfg(any(test, feature = "workflow-test-auto"))]
pub(crate) use payload::pack_for_test;

pub fn capacity_bits(jpeg: &[u8], key: &[u8]) -> Result<u32, &'static str> {
    signer_firmware_core::backup::stego_picture::capacity_bits(jpeg, key).map_err(signer_firmware_core::backup::stego_picture::PictureError::message)
}

pub fn embed_picture(
    jpeg: &[u8],
    payload: &[u8],
    key: &[u8],
    output: &mut [u8],
) -> Result<usize, &'static str> {
    signer_firmware_core::backup::stego_picture::embed(jpeg, payload, key, output).map_err(signer_firmware_core::backup::stego_picture::PictureError::message)
}

pub fn extract_picture(
    jpeg: &[u8],
    key: &[u8],
    output: &mut [u8],
) -> Result<usize, &'static str> {
    signer_firmware_core::backup::stego_picture::extract(jpeg, key, output).map_err(signer_firmware_core::backup::stego_picture::PictureError::message)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StegoSecurity {
    DeviceBound,
    Portable,
}

impl StegoSecurity {
    pub const fn label(self) -> &'static str {
        match self {
            Self::DeviceBound => "Device-bound",
            Self::Portable => "Portable",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StegoCarrier {
    Descriptor,
    Picture,
}

impl StegoCarrier {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Descriptor => "Descriptor",
            Self::Picture => "Picture",
        }
    }

    pub const fn description(self) -> &'static str {
        match self {
            Self::Descriptor => "Stored in photo metadata",
            Self::Picture => "Stored in compressed image data",
        }
    }

    pub const fn tradeoff(self) -> &'static str {
        match self {
            Self::Descriptor => "Lost when metadata is stripped",
            Self::Picture => "Lost when photo is re-saved",
        }
    }
}

pub const CARRIERS: [StegoCarrier; 2] = [StegoCarrier::Descriptor, StegoCarrier::Picture];

/// Preset recovery hints for JPEG stego export.
pub const HINT_PRESETS: [&str; 3] = [
    "My favorite place I lived?",
    "Name of my loved one?",
    "Song I can't stop humming?",
];
