use super::super::{
    bit_writer::BitWriter,
    ecc::codewords::{build_matrix, finish_data_codewords, interleave_with_error_correction},
    constants::VERSION_TABLE,
    error::QrError,
    matrix::matrix::QrCode,
    matrix::version::select_version,
};

/// Encode bytes into a QR code using byte mode and ECC level L.
pub fn encode(data: &[u8]) -> Result<QrCode, QrError> {
    let version = select_version(data.len())?;
    let (_, _, data_cw, ec_cw, ec_blocks) = VERSION_TABLE[(version - 1) as usize];
    let data_count = data_cw as usize;
    let ec_count = ec_cw as usize;

    let mut data_codewords = [0u8; 160];
    let mut writer = BitWriter::new(&mut data_codewords);
    writer.write_bits(0b0100, 4);
    writer.write_bits(data.len() as u32, 8);
    for &byte in data {
        writer.write_bits(byte as u32, 8);
    }
    finish_data_codewords(&mut writer, data_count);

    let mut all_codewords = [0u8; 180];
    let total = interleave_with_error_correction(
        &data_codewords,
        data_count,
        ec_count,
        ec_blocks,
        &mut all_codewords,
    );
    Ok(build_matrix(version, &all_codewords[..total]))
}
