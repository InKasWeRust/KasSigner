//! SD R1/R2 status helpers layered on the wire owner.

use super::wire::command;

pub(in crate::hw::m5stack::storage::transport) fn card_status_r2(
    initialization_speed: bool,
) -> Result<[u8; 2], &'static str> {
    const CMD13: u8 = 13;
    let mut status = [0u8; 1];
    command(CMD13, 0, initialization_speed, &mut status).map(|r1| [r1, status[0]])
}

