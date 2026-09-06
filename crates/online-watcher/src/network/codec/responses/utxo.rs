use crate::{
    account::utxo::UtxoEntry,
    network::{codec::primitives::WireReader, error::NetworkError},
};

const MAX_BLOB_BYTES: usize = 16 * 1024 * 1024;
const MAX_UTXOS: usize = 1_000_000;

fn entries_blob(data: &[u8]) -> Result<&[u8], NetworkError> {
    let mut reader = WireReader::new(data);
    if reader.read_u8()? == 255 {
        reader = WireReader::new(data);
    }
    let outer = reader.read_bytes(MAX_BLOB_BYTES)?;
    let mut outer_reader = WireReader::new(outer);
    outer_reader.read_u16()?;
    outer_reader.read_bytes(MAX_BLOB_BYTES)
}

fn decode_entries(entries_blob: &[u8]) -> Result<Vec<UtxoEntry>, NetworkError> {
    let mut reader = WireReader::new(entries_blob);
    let count = usize::try_from(reader.read_u32()?).map_err(|_| NetworkError::InvalidLength)?;
    if count > MAX_UTXOS {
        return Err(NetworkError::InvalidLength);
    }
    let mut entries = Vec::with_capacity(count);
    for index_in_response in 0..count {
        let entry_blob = reader.read_bytes(MAX_BLOB_BYTES)?;
        entries.push(decode_entry(entry_blob, index_in_response)?);
    }
    Ok(entries)
}

pub fn decode(data: &[u8]) -> Result<Vec<UtxoEntry>, NetworkError> {
    if data.len() < 6 {
        return Ok(Vec::new());
    }
    let entries = entries_blob(data)?;
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    decode_entries(entries)
}

fn decode_entry(data: &[u8], index_in_response: usize) -> Result<UtxoEntry, NetworkError> {
    let mut reader = WireReader::new(data);
    skip_entry_metadata(&mut reader)?;
    let (tx_id, index) = decode_outpoint(&mut reader, index_in_response)?;
    let (amount, script_public_key, block_daa_score, covenant_id) = decode_utxo(&mut reader)?;
    Ok(UtxoEntry {
        tx_id,
        index,
        amount,
        script_public_key,
        block_daa_score,
        covenant_id,
    })
}

fn skip_entry_metadata(reader: &mut WireReader<'_>) -> Result<(), NetworkError> {
    reader.read_u8()?;
    let metadata_tag = reader.read_u8()?;
    if metadata_tag == 1 {
        skip_present_entry_metadata(reader)?;
    }
    Ok(())
}

fn skip_present_entry_metadata(reader: &mut WireReader<'_>) -> Result<(), NetworkError> {
    reader.read_u8()?;
    reader.read_u8()?;
    reader.read_bytes(MAX_BLOB_BYTES)?;
    Ok(())
}

fn decode_outpoint(
    reader: &mut WireReader<'_>,
    index_in_response: usize,
) -> Result<(String, u32), NetworkError> {
    let outpoint = reader.read_bytes(MAX_BLOB_BYTES)?;
    if outpoint.len() < 37 {
        return Err(NetworkError::InvalidEncoding(format!(
            "entry {index_in_response}: outpoint {} bytes",
            outpoint.len()
        )));
    }
    let tx_id = hex::encode(&outpoint[1..33]);
    let index = u32::from_le_bytes(
        outpoint[33..37]
            .try_into()
            .map_err(|_| NetworkError::TruncatedPayload)?,
    );
    Ok((tx_id, index))
}

fn decode_utxo(
    reader: &mut WireReader<'_>,
) -> Result<(u64, Vec<u8>, u64, Option<String>), NetworkError> {
    let utxo_blob = reader.read_bytes(MAX_BLOB_BYTES)?;
    let mut utxo_reader = WireReader::new(utxo_blob);
    let version = utxo_reader.read_u8()?;
    let amount = utxo_reader.read_u64()?;
    utxo_reader.read_u16()?;
    let script_public_key = utxo_reader.read_bytes(MAX_BLOB_BYTES)?.to_vec();
    let block_daa_score = utxo_reader.read_u64()?;
    utxo_reader.read_bool()?;
    let covenant_id = decode_covenant_id(&mut utxo_reader, version)?;
    Ok((amount, script_public_key, block_daa_score, covenant_id))
}

fn decode_covenant_id(
    reader: &mut WireReader<'_>,
    version: u8,
) -> Result<Option<String>, NetworkError> {
    if version <= 1 || reader.read_u8()? != 1 {
        return Ok(None);
    }
    Ok(Some(hex::encode(reader.read_exact(32)?)))
}
