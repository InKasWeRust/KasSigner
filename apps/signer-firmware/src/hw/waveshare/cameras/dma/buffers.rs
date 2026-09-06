extern crate alloc;

use alloc::vec::Vec;

use super::FRAME_BYTES;
use signer_firmware_core::camera::dma::copy_sample_with;

pub(super) struct FrameBuffers {
    frames: [Vec<u8>; 2],
    write_index: usize,
    write_offset: usize,
    ready: bool,
    completed_bytes: usize,
}


fn allocate_frame() -> Option<Vec<u8>> {
    let mut frame = Vec::new();
    frame.try_reserve_exact(FRAME_BYTES).ok()?;
    frame.resize(FRAME_BYTES, 0u8);
    Some(frame)
}

fn frames_in_psram(first: usize, second: usize) -> bool {
    first >= 0x3C00_0000 && second >= 0x3C00_0000
}

impl FrameBuffers {
    pub(super) fn allocate() -> Option<Self> {
        let first = allocate_frame()?;
        let second = allocate_frame()?;
        let first_address = first.as_ptr() as usize;
        let second_address = second.as_ptr() as usize;
        if !frames_in_psram(first_address, second_address) {
            crate::log!("   cam_dma: FATAL — frame buffers are not in PSRAM");
            return None;
        }
        crate::log!(
            "   cam_dma: frame0=0x{:08X} frame1=0x{:08X}",
            first_address as u32,
            second_address as u32
        );
        Some(Self {
            frames: [first, second],
            write_index: 0,
            write_offset: 0,
            ready: false,
            completed_bytes: 0,
        })
    }

    pub(super) fn reset_capture(&mut self) {
        self.write_index = 0;
        self.write_offset = 0;
    }

    pub(super) fn write_target(&mut self) -> (*mut u8, &mut usize) {
        (self.frames[self.write_index].as_mut_ptr(), &mut self.write_offset)
    }

    pub(super) fn finish_frame(&mut self) -> (usize, bool) {
        let captured = self.write_offset;
        let complete = captured >= FRAME_BYTES * 98 / 100;
        if complete {
            self.write_index ^= 1;
            self.ready = true;
            self.completed_bytes = captured.min(FRAME_BYTES);
        }
        self.write_offset = 0;
        (captured, complete)
    }

    pub(super) fn completed(&self) -> Option<&[u8]> {
        self.ready
            .then(|| self.frames[self.write_index ^ 1].as_slice())
    }

    pub(super) fn copy_entropy_sample(&self, output: &mut [u8]) -> usize {
        let source = self.frames[self.write_index ^ 1].as_ptr();
        copy_sample_with(output, self.ready, self.completed_bytes, |index| unsafe {
            core::ptr::read_volatile(source.add(index))
        })
    }

    pub(super) fn clear_availability(&mut self) {
        self.ready = false;
        self.completed_bytes = 0;
    }

    pub(super) fn diagnostics(&self) -> (usize, usize) {
        (self.write_offset, self.write_index)
    }
}
