//! Small pure helpers for the CoreS3 SD wire owner.

use esp_hal::{Blocking, spi::master::Spi};

use super::wire::read_exact;

pub(super) fn read_tail(
    spi: &mut Spi<'static, Blocking>,
    response: u8,
    tail: &mut [u8],
) -> Result<u8, &'static str> {
    if tail.is_empty() { return Ok(response); }
    read_exact(spi, tail).map(|_| response)
}
