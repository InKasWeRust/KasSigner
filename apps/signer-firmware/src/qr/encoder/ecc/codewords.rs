use super::super::bit_writer::BitWriter;
use super::reed_solomon;

pub(crate) fn finish_data_codewords(writer: &mut BitWriter<'_>, data_codewords: usize) {
    let total_bits = data_codewords * 8;
    let terminator_length = 4.min(total_bits.saturating_sub(writer.bit_pos));
    writer.write_bits(0, terminator_length);
    while writer.bit_pos % 8 != 0 {
        writer.write_bits(0, 1);
    }

    let mut pad_index = 0usize;
    while writer.bit_pos / 8 < data_codewords {
        writer.write_bits(if pad_index % 2 == 0 { 0xEC } else { 0x11 }, 8);
        pad_index += 1;
    }
}

pub(crate) fn interleave_with_error_correction(
    data: &[u8],
    data_codewords: usize,
    ec_codewords: usize,
    ec_blocks: u8,
    output: &mut [u8],
) -> usize {
    if ec_blocks == 1 {
        output[..data_codewords].copy_from_slice(&data[..data_codewords]);
        let mut ec = [0u8; 37];
        reed_solomon::encode(&data[..data_codewords], ec_codewords, &mut ec);
        output[data_codewords..data_codewords + ec_codewords]
            .copy_from_slice(&ec[..ec_codewords]);
    } else {
        let first_data_count = data_codewords / 2;
        let second_data_count = data_codewords - first_data_count;
        let block_ec_count = ec_codewords / 2;
        let mut first_ec = [0u8; 37];
        let mut second_ec = [0u8; 37];
        reed_solomon::encode(&data[..first_data_count], block_ec_count, &mut first_ec);
        reed_solomon::encode(
            &data[first_data_count..data_codewords],
            block_ec_count,
            &mut second_ec,
        );

        let mut position = 0usize;
        for index in 0..first_data_count.max(second_data_count) {
            if index < first_data_count {
                output[position] = data[index];
                position += 1;
            }
            if index < second_data_count {
                output[position] = data[first_data_count + index];
                position += 1;
            }
        }
        for index in 0..block_ec_count {
            output[position] = first_ec[index];
            position += 1;
            output[position] = second_ec[index];
            position += 1;
        }
    }
    data_codewords + ec_codewords
}

pub(crate) fn build_matrix(version: u8, codewords: &[u8]) -> super::super::matrix::matrix::QrCode {
    super::super::matrix::build(version, codewords)
}
