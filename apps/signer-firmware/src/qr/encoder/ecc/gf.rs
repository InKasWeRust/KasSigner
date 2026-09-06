/// Multiply two values in GF(256) using primitive polynomial 0x11D.
pub(crate) fn gf_mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }
    let mut result: u16 = 0;
    let mut aa = a as u16;
    let mut bb = b;
    for _ in 0..8 {
        if bb & 1 != 0 {
            result ^= aa;
        }
        let carry = aa & 0x80 != 0;
        aa <<= 1;
        if carry {
            aa ^= 0x11D;
        }
        bb >>= 1;
    }
    result as u8
}
