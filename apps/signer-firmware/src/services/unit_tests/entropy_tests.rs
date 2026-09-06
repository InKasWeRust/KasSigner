use crate::services::entropy::{inspect, EntropyError, HEALTH_SAMPLE_COUNT};

fn healthy_samples() -> [u32; HEALTH_SAMPLE_COUNT] {
    core::array::from_fn(|index| {
        let value = (index as u32).wrapping_mul(0x9E37_79B9) ^ 0xA5C3_17D2;
        value.rotate_left((index % 31) as u32)
    })
}

pub fn run_entropy_health_tests() -> (u32, u32) {
    let stuck = inspect(&[0xDEAD_BEEF; HEALTH_SAMPLE_COUNT]) == Err(EntropyError::StuckRegister);
    let half = core::array::from_fn(|index| 0xA55A_0000 | index as u32);
    let stuck_half = inspect(&half) == Err(EntropyError::StuckHalfWord);
    let counter = core::array::from_fn(|index| {
        0x1357_2468u32.wrapping_add((index as u32).wrapping_mul(0x0101_0101))
    });
    let counter_rejected = inspect(&counter) == Err(EntropyError::CounterPattern);
    let healthy = inspect(&healthy_samples()).is_ok();
    let passed = [stuck, stuck_half, counter_rejected, healthy]
        .into_iter()
        .map(u32::from)
        .sum();
    (passed, 4)
}

#[test]
fn structural_entropy_health_vectors_pass() {
    let (passed, total) = run_entropy_health_tests();
    assert_eq!(passed, total);
}
