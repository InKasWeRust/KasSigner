/// Maximum QR version supported by the firmware encoder.
pub(super) const MAX_SIZE: usize = 41;
pub(super) const MAX_MODULES: usize = MAX_SIZE * MAX_SIZE;
pub(super) const BITMAP_BYTES: usize = (MAX_MODULES + 7) / 8;

/// Version info: version, size, data codewords, EC codewords, EC blocks.
pub(super) const VERSION_TABLE: [(u8, u8, u16, u16, u8); 6] = [
    (1, 21, 19, 7, 1),
    (2, 25, 34, 10, 1),
    (3, 29, 55, 15, 1),
    (4, 33, 80, 20, 1),
    (5, 37, 108, 26, 1),
    (6, 41, 136, 36, 2),
];

pub(super) const BYTE_CAPACITY: [usize; 6] = [17, 32, 53, 78, 106, 134];
#[cfg(not(feature = "qemu"))]
pub(super) const NUMERIC_CAPACITY: [usize; 6] = [41, 77, 127, 187, 255, 322];
