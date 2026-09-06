//! Bounded SD-SPI command diagnostics for live CoreS3 failures.

use esp_hal::{Blocking, spi::master::Spi};

use super::wire::transfer_byte;

const COMMAND_READY_POLLS: usize = 25_000;

pub(super) fn prepare_command(
    spi: &mut Spi<'static, Blocking>,
    reset: bool,
    cmd: u8,
    arg: u32,
    initialization_speed: bool,
) -> Result<(), &'static str> {
    if reset {
        crate::log!("[SD] CMD0 reset: pre-command ready gate bypassed");
        return Ok(());
    }
    wait_command_ready(spi, cmd, arg, initialization_speed)
}

fn wait_command_ready(
    spi: &mut Spi<'static, Blocking>,
    cmd: u8,
    arg: u32,
    initialization_speed: bool,
) -> Result<(), &'static str> {
    let mut trace = ReadyTrace::new();
    for poll in 0..COMMAND_READY_POLLS {
        let sample = transfer_byte(spi, 0xFF)?;
        trace.observe(poll, sample);
        if sample == 0xFF { return Ok(()); }
    }
    trace.log_timeout(cmd, arg, initialization_speed);
    Err("SD card busy before command")
}

pub(super) fn log_response_if_timeout(
    response: u8,
    cmd: u8,
    arg: u32,
    initialization_speed: bool,
    crc: u8,
) {
    if response == 0xFF {
        crate::log!(
            "[SD] CMD{} response timeout arg=0x{:08x} speed={} crc=0x{:02x}",
            cmd, arg, speed_label(initialization_speed), crc,
        );
    }
}

struct ReadyTrace {
    first: u8,
    last: u8,
    zero_samples: usize,
}

impl ReadyTrace {
    const fn new() -> Self { Self { first: 0xFF, last: 0xFF, zero_samples: 0 } }

    fn observe(&mut self, poll: usize, sample: u8) {
        if poll == 0 { self.first = sample; }
        self.last = sample;
        if sample == 0x00 { self.zero_samples = self.zero_samples.saturating_add(1); }
    }

    fn log_timeout(&self, cmd: u8, arg: u32, initialization_speed: bool) {
        crate::log!(
            "[SD] CMD{} pre-command ready timeout arg=0x{:08x} speed={} polls={} first=0x{:02x} last=0x{:02x} zero_samples={}",
            cmd, arg, speed_label(initialization_speed), COMMAND_READY_POLLS,
            self.first, self.last, self.zero_samples,
        );
    }
}

const fn speed_label(initialization_speed: bool) -> &'static str {
    if initialization_speed { "400kHz" } else { "data-rate" }
}
