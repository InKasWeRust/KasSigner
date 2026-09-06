//! Canonical compact KSPT generation-4 wire grammar.
//!
//! This module is allocation-free and available with `default-features = false`.
//! Host and hardware consumers provide adapters through `EncodeSource` and
//! `DecodeSink`; neither consumer owns KSPT field ordering or trailer parsing.

mod decode;
mod encode;
mod error;
mod io;
mod model;

pub use decode::{decode, decode_with_limits, validate, DecodeSink};
pub use encode::{encode, EncodeSource};
pub use error::{DecodeError, WireError};
pub use model::*;

#[cfg(feature = "host")]
pub fn encode_vec<S: EncodeSource>(source: &S) -> Result<Vec<u8>, WireError> {
    let global = source.global();
    let inputs = usize::try_from(global.input_count).map_err(|_| WireError::CountOverflow)?;
    let mut capacity = 1024usize
        .saturating_add(inputs.saturating_mul(192))
        .saturating_add(usize::from(global.output_count).saturating_mul(640))
        .saturating_add(global.payload.len());
    loop {
        let mut output = vec![0u8; capacity];
        match encode(source, &mut output) {
            Ok(length) => {
                output.truncate(length);
                return Ok(output);
            }
            Err(WireError::OutputBufferTooSmall) => {
                capacity = capacity
                    .checked_mul(2)
                    .ok_or(WireError::OutputBufferTooSmall)?;
            }
            Err(error) => return Err(error),
        }
    }
}
