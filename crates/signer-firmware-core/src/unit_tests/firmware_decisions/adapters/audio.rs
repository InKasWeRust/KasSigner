use crate::presentation::audio::{
    boot_chime_bytes, fill_stereo_boot_chime, fill_stereo_boot_chime_chunk,
    fill_stereo_square_wave, fill_stereo_tick, BOOT_CHIME_AMPLITUDE, BOOT_CHIME_BASE_AMPLITUDE,
    BOOT_CHIME_DURATION_MS, BOOT_CHIME_SEGMENTS, BOOT_CHIME_VOLUME,
};

#[test]
fn square_wave_is_stereo_little_endian_and_periodic() {
    let mut output = [0u8; 16];
    fill_stereo_square_wave(&mut output, 8, 2, 0x1234);
    assert_eq!(&output[0..4], &[0x34, 0x12, 0x34, 0x12]);
    assert_eq!(&output[4..8], &[0x34, 0x12, 0x34, 0x12]);
    assert_eq!(&output[8..12], &[0xcc, 0xed, 0xcc, 0xed]);
    assert_eq!(&output[12..16], &[0xcc, 0xed, 0xcc, 0xed]);
}

#[test]
fn tick_bounds_the_click_and_leaves_the_tail_silent() {
    let mut output = [0xffu8; 16];
    fill_stereo_tick(&mut output, 8, 2, 100, 2);
    assert_ne!(&output[0..8], &[0u8; 8]);
    assert_eq!(&output[8..], &[0u8; 8]);
    fill_stereo_square_wave(&mut output, 8, 0, 100);
}

#[test]
fn boot_chime_matches_original_waveform_contract() {
    assert_eq!(BOOT_CHIME_VOLUME, 18);
    assert_eq!(BOOT_CHIME_BASE_AMPLITUDE, 6_000);
    assert_eq!(BOOT_CHIME_AMPLITUDE, 423);
    assert_eq!(
        BOOT_CHIME_SEGMENTS,
        [(800, 100), (1_200, 100), (1_600, 150)]
    );
    assert_eq!(BOOT_CHIME_DURATION_MS, 350);
    assert_eq!(boot_chime_bytes(48_000), 67_200);
}

#[test]
fn boot_chime_is_stereo_signed_little_endian_and_has_no_inserted_gaps() {
    const SAMPLE_RATE: u32 = 48_000;
    let mut output = std::vec![0u8; boot_chime_bytes(SAMPLE_RATE)];
    assert_eq!(
        fill_stereo_boot_chime(&mut output, SAMPLE_RATE),
        output.len()
    );

    let positive = BOOT_CHIME_AMPLITUDE.to_le_bytes();
    let negative = (-BOOT_CHIME_AMPLITUDE).to_le_bytes();
    assert_eq!(
        &output[..4],
        &[positive[0], positive[1], positive[0], positive[1]]
    );

    // Every encoded frame carries exactly the same signed sample to L and R.
    for frame in output.chunks_exact(4) {
        assert_eq!(&frame[..2], &frame[2..]);
        assert!(frame[..2] == positive || frame[..2] == negative);
    }

    // The first sample of each new frequency begins immediately at the exact
    // 100 ms / 200 ms boundary; there is no inserted zero-valued gap.
    for boundary_frame in [4_800usize, 9_600usize] {
        let offset = boundary_frame * 4;
        assert_eq!(
            &output[offset..offset + 4],
            &[positive[0], positive[1], positive[0], positive[1]]
        );
    }
}

#[test]
fn boot_chime_chunking_preserves_absolute_phase_and_silence_tail() {
    const SAMPLE_RATE: u32 = 48_000;
    let total = boot_chime_bytes(SAMPLE_RATE);
    let mut whole = std::vec![0u8; total];
    fill_stereo_boot_chime(&mut whole, SAMPLE_RATE);

    let split_frame = 5_137usize;
    let mut chunk = std::vec![0u8; 3_001 * 4];
    fill_stereo_boot_chime_chunk(&mut chunk, SAMPLE_RATE, split_frame);
    assert_eq!(
        &chunk[..],
        &whole[split_frame * 4..(split_frame + 3_001) * 4]
    );

    let mut tail = [0xa5u8; 64];
    fill_stereo_boot_chime_chunk(&mut tail, SAMPLE_RATE, 16_800);
    assert!(tail.iter().all(|byte| *byte == 0));
}
