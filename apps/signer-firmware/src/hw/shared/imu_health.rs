//! Board-neutral IMU entropy health checks.
//!
//! Board drivers own device setup and sampling; this module owns the identical
//! X/Y/Z low-byte diversity policy so entropy acceptance cannot drift between boards.

const HEALTHY_DISTINCT_PCT: u32 = 60;

fn mark_seen(seen: &mut [u32; 8], value: u8) -> bool {
    let word = usize::from(value >> 5);
    let bit = 1u32 << (value & 0x1f);
    if seen[word] & bit != 0 { return false; }
    seen[word] |= bit;
    true
}

/// Distinct low-byte values per X/Y/Z axis in an X,Y,Z interleaved sample.
pub(crate) fn axis_distinct(bytes: &[u8]) -> [u32; 3] {
    let mut seen = [[0u32; 8]; 3];
    let mut distinct = [0u32; 3];
    for (index, value) in bytes.iter().copied().enumerate() {
        let axis = index % 3;
        distinct[axis] += u32::from(mark_seen(&mut seen[axis], value));
    }
    distinct
}

/// Require independent diversity on every gyro axis at the point of use.
pub(crate) fn buffer_is_healthy(bytes: &[u8]) -> bool {
    let per_axis = (bytes.len() / 3) as u32;
    if per_axis < 4 || bytes.len() % 3 != 0 { return false; }
    let required = per_axis * HEALTHY_DISTINCT_PCT / 100;
    axis_distinct(bytes).into_iter().all(|count| count >= required)
}
