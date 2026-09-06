use super::{
    buffers::FrameBuffers,
    descriptors::DescriptorRing,
    registers,
    FRAME_BYTES,
};

pub(super) struct CameraDma {
    descriptors: DescriptorRing,
    frames: FrameBuffers,
    started: bool,
    frame_count: u32,
}

impl CameraDma {
    pub(super) fn allocate() -> Option<Self> {
        Some(Self {
            descriptors: DescriptorRing::new(),
            frames: FrameBuffers::allocate()?,
            started: false,
            frame_count: 0,
        })
    }

    pub(super) fn configure(&mut self) {
        registers::configure();
    }

    pub(super) fn start(&mut self) {
        if self.started {
            return;
        }
        self.started = true;
        self.frames.reset_capture();
        let first_descriptor = self.descriptors.configure();
        registers::start(first_descriptor);
        crate::log!("   cam_dma: capture started");
    }

    fn drain_completed_descriptors(&mut self) {
        let (target, offset) = self.frames.write_target();
        self.descriptors.drain_into(target, offset, FRAME_BYTES);
    }

    pub(super) fn poll(&mut self) -> bool {
        self.drain_completed_descriptors();
        if !registers::poll_end_of_frame() {
            return false;
        }
        self.drain_completed_descriptors();

        let (captured, complete) = self.frames.finish_frame();
        self.frame_count = self.frame_count.wrapping_add(1);
        if self.frame_count <= 5 {
            crate::log!(
                "   cam_dma: frame #{} — {} bytes{}",
                self.frame_count,
                captured,
                if complete { "" } else { " (partial, skipped)" }
            );
        }
        complete
    }

    pub(super) fn completed_frame(&self) -> Option<&[u8]> {
        self.frames.completed()
    }

    pub(super) fn copy_entropy_sample(&self, output: &mut [u8]) -> usize {
        self.frames.copy_entropy_sample(output)
    }

    pub(super) fn stop(&mut self) {
        registers::stop();
        self.started = false;
        self.frames.clear_availability();
    }

    pub(super) fn log_status(&self) {
        let (interrupt, link, camera_control) = registers::status();
        let (offset, write_index) = self.frames.diagnostics();
        crate::log!(
            "   cam_dma: INT=0x{:08X} LINK=0x{:08X} CAM_CTRL1=0x{:08X} off={} widx={}",
            interrupt,
            link,
            camera_control,
            offset,
            write_index
        );
    }
}
