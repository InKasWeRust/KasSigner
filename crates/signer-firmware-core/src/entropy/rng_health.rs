//! Continuous structural health tests for a 32-word hardware RNG window.

pub const HEALTH_SAMPLE_COUNT: usize = 32;
pub const MIN_ONES: u32 = 256;
pub const MAX_ONES: u32 = 768;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RngHealthError {
    StuckRegister,
    RepetitionCount,
    LowDiversity,
    AdaptiveProportion,
    StuckBits,
    CounterPattern,
    Monotonic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RngHealthReport {
    pub repeated_words: u8,
    pub distinct_words: u8,
    pub ones: u16,
    pub stuck_bits: u8,
    pub counter_pattern: bool,
    pub monotonic: bool,
}

pub fn inspect(samples: &[u32; HEALTH_SAMPLE_COUNT]) -> Result<RngHealthReport, RngHealthError> {
    if samples.iter().all(|sample| *sample == samples[0]) {
        return Err(RngHealthError::StuckRegister);
    }
    let repeated_words = samples.windows(2).filter(|pair| pair[0] == pair[1]).count() as u8;
    if repeated_words != 0 {
        return Err(RngHealthError::RepetitionCount);
    }

    let distinct_words = distinct_count(samples);
    if distinct_words != HEALTH_SAMPLE_COUNT as u8 {
        return Err(RngHealthError::LowDiversity);
    }

    let ones = samples.iter().map(|value| value.count_ones()).sum::<u32>();
    if !(MIN_ONES..=MAX_ONES).contains(&ones) {
        return Err(RngHealthError::AdaptiveProportion);
    }

    let counter_pattern = fixed_step(samples);
    if counter_pattern {
        return Err(RngHealthError::CounterPattern);
    }

    let stuck_bits = stuck_bit_count(samples);
    if stuck_bits != 0 {
        return Err(RngHealthError::StuckBits);
    }

    let monotonic = monotonic_window(samples);
    if monotonic {
        return Err(RngHealthError::Monotonic);
    }

    Ok(RngHealthReport {
        repeated_words,
        distinct_words,
        ones: ones as u16,
        stuck_bits,
        counter_pattern,
        monotonic,
    })
}

fn distinct_count(samples: &[u32; HEALTH_SAMPLE_COUNT]) -> u8 {
    let mut count = 0u8;
    for (index, sample) in samples.iter().enumerate() {
        if !samples[..index].contains(sample) {
            count = count.saturating_add(1);
        }
    }
    count
}

fn stuck_bit_count(samples: &[u32; HEALTH_SAMPLE_COUNT]) -> u8 {
    let mut stuck = 0u8;
    for bit in 0..32u32 {
        let first = (samples[0] >> bit) & 1;
        if samples.iter().all(|word| ((word >> bit) & 1) == first) {
            stuck = stuck.saturating_add(1);
        }
    }
    stuck
}

fn fixed_step(samples: &[u32; HEALTH_SAMPLE_COUNT]) -> bool {
    let first_step = samples[1].wrapping_sub(samples[0]);
    first_step != 0
        && samples
            .windows(2)
            .all(|pair| pair[1].wrapping_sub(pair[0]) == first_step)
}

fn monotonic_window(samples: &[u32; HEALTH_SAMPLE_COUNT]) -> bool {
    let mut ascending = 0u8;
    let mut descending = 0u8;
    for pair in samples.windows(2) {
        let ordering = pair[1].cmp(&pair[0]);
        ascending += u8::from(ordering.is_gt());
        descending += u8::from(ordering.is_lt());
    }
    ascending >= 30 || descending >= 30
}
