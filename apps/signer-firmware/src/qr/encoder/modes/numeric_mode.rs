use super::super::{
    bit_writer::BitWriter,
    ecc::codewords::{build_matrix, finish_data_codewords, interleave_with_error_correction},
    constants::VERSION_TABLE,
    error::QrError,
    matrix::matrix::QrCode,
    matrix::version::select_version_numeric,
};

/// Encode ASCII digits using QR numeric mode and ECC level L.
pub fn encode_numeric(digits: &[u8]) -> Result<QrCode, QrError> {
    let digit_count = digits.len();
    let version = select_version_numeric(digit_count)?;
    let (_, _, data_cw, ec_cw, ec_blocks) = VERSION_TABLE[(version - 1) as usize];
    let data_count = data_cw as usize;
    let ec_count = ec_cw as usize;

    let mut data_codewords = [0u8; 160];
    let mut writer = BitWriter::new(&mut data_codewords);
    writer.write_bits(0b0001, 4);
    writer.write_bits(digit_count as u32, 10);

    let mut index = 0usize;
    while index + 2 < digit_count {
        let hundreds = (digits[index] - b'0') as u32;
        let tens = (digits[index + 1] - b'0') as u32;
        let ones = (digits[index + 2] - b'0') as u32;
        writer.write_bits(hundreds * 100 + tens * 10 + ones, 10);
        index += 3;
    }
    match digit_count - index {
        2 => {
            let tens = (digits[index] - b'0') as u32;
            let ones = (digits[index + 1] - b'0') as u32;
            writer.write_bits(tens * 10 + ones, 7);
        }
        1 => writer.write_bits((digits[index] - b'0') as u32, 4),
        _ => {}
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
