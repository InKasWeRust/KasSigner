//! Host-testable I2C bus-recovery sequencing.

pub fn run_i2c_recovery<SetClock, SetData, Delay>(
    pulses: u8,
    mut set_clock: SetClock,
    mut set_data: SetData,
    mut delay: Delay,
) where
    SetClock: FnMut(bool),
    SetData: FnMut(bool),
    Delay: FnMut(),
{
    set_data(true);
    for _ in 0..pulses {
        set_clock(false);
        delay();
        set_clock(true);
        delay();
    }
    set_data(false);
    delay();
    set_data(true);
    delay();
}
