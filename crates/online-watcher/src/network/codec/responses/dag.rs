use crate::network::{codec::primitives::WireReader, error::NetworkError};

fn skip_dag_prefix(reader: &mut WireReader<'_>) -> Result<(), NetworkError> {
    reader.read_u8()?;
    reader.read_u32()?;
    reader.read_u16()?;
    reader.read_u8()?;
    if reader.read_u8()? == 1 {
        reader.read_u32()?;
    }
    Ok(())
}

fn skip_dag_state(reader: &mut WireReader<'_>) -> Result<(), NetworkError> {
    reader.read_u64()?;
    reader.read_u64()?;
    skip_hashes(reader)?;
    reader.read_f64()?;
    reader.read_u64()?;
    skip_hashes(reader)?;
    reader.read_exact(32)?;
    Ok(())
}

pub fn virtual_daa_score(data: &[u8]) -> Result<u64, NetworkError> {
    let mut reader = WireReader::new(data);
    skip_dag_prefix(&mut reader)?;
    skip_dag_state(&mut reader)?;
    reader.read_u64()
}

fn skip_hashes(reader: &mut WireReader<'_>) -> Result<(), NetworkError> {
    let count = usize::try_from(reader.read_u32()?).map_err(|_| NetworkError::InvalidLength)?;
    let bytes = count.checked_mul(32).ok_or(NetworkError::InvalidLength)?;
    reader.read_exact(bytes)?;
    Ok(())
}
