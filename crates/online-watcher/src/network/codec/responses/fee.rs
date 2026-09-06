use crate::network::{
    codec::primitives::WireReader, error::NetworkError, model::fee_estimate::FeeEstimate,
};

const MAX_BLOB_BYTES: usize = 1024 * 1024;
const MAX_BUCKETS: usize = 10_000;

fn estimate_blob(data: &[u8]) -> Result<&[u8], NetworkError> {
    let mut reader = WireReader::new(data);
    if reader.read_u8()? == 255 {
        reader = WireReader::new(data);
    }
    let outer = reader.read_bytes(MAX_BLOB_BYTES)?;
    let mut outer_reader = WireReader::new(outer);
    outer_reader.read_u16()?;
    outer_reader.read_bytes(MAX_BLOB_BYTES)
}

fn decode_estimate(estimate: &[u8]) -> Result<FeeEstimate, NetworkError> {
    let mut reader = WireReader::new(estimate);
    reader.read_u16()?;
    let priority_sompi_per_gram = reader.read_f64()?;
    let priority_seconds = reader.read_f64()?;
    let (normal_sompi_per_gram, normal_seconds) = read_first_bucket(&mut reader, 1.0, 30.0)?;
    let (low_sompi_per_gram, low_seconds) = read_first_bucket(&mut reader, 1.0, 1800.0)?;
    let suggested_fee = (normal_sompi_per_gram * 2300.0).max(10_000.0) as u64;
    Ok(FeeEstimate {
        priority_sompi_per_gram,
        normal_sompi_per_gram,
        low_sompi_per_gram,
        priority_seconds,
        normal_seconds,
        low_seconds,
        suggested_fee,
    })
}

pub fn decode(data: &[u8]) -> Result<FeeEstimate, NetworkError> {
    if data.len() < 6 {
        return Ok(FeeEstimate::conservative_fallback());
    }
    decode_estimate(estimate_blob(data)?)
}

fn read_first_bucket(
    reader: &mut WireReader<'_>,
    default_rate: f64,
    default_seconds: f64,
) -> Result<(f64, f64), NetworkError> {
    let count = usize::try_from(reader.read_u32()?).map_err(|_| NetworkError::InvalidLength)?;
    if count > MAX_BUCKETS {
        return Err(NetworkError::InvalidLength);
    }
    let mut selected = (default_rate, default_seconds);
    for index in 0..count {
        let bucket = (reader.read_f64()?, reader.read_f64()?);
        if index == 0 {
            selected = bucket;
        }
    }
    Ok(selected)
}
