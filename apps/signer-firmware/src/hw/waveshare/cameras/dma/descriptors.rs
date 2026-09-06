use signer_firmware_core::camera::dma::{DescriptorAction, descriptor_action};

pub(super) const BOUNCE_SIZE: usize = 4032;

#[derive(Copy, Clone)]
#[repr(C, align(4))]
struct Descriptor {
    control: u32,
    buffer_address: u32,
    next: u32,
}

impl Descriptor {
    const EMPTY: Self = Self {
        control: 0,
        buffer_address: 0,
        next: 0,
    };
}

pub(super) struct DescriptorRing {
    bounce: [[u8; BOUNCE_SIZE]; 2],
    descriptors: [Descriptor; 2],
}

impl DescriptorRing {
    pub(super) const fn new() -> Self {
        Self {
            bounce: [[0u8; BOUNCE_SIZE]; 2],
            descriptors: [Descriptor::EMPTY; 2],
        }
    }

    pub(super) fn configure(&mut self) -> u32 {
        let first = core::ptr::addr_of!(self.descriptors[0]) as u32;
        let second = core::ptr::addr_of!(self.descriptors[1]) as u32;
        self.descriptors[0] = Descriptor {
            control: hardware_owned_control(),
            buffer_address: self.bounce[0].as_ptr() as u32,
            next: second,
        };
        self.descriptors[1] = Descriptor {
            control: hardware_owned_control(),
            buffer_address: self.bounce[1].as_ptr() as u32,
            next: first,
        };
        first
    }

    pub(super) fn drain_into(
        &mut self,
        destination: *mut u8,
        offset: &mut usize,
        capacity: usize,
    ) {
        for index in 0..self.descriptors.len() {
            self.drain_one(index, destination, offset, capacity);
        }
    }

    fn drain_one(
        &mut self,
        index: usize,
        destination: *mut u8,
        offset: &mut usize,
        capacity: usize,
    ) {
        let descriptor = core::ptr::addr_of_mut!(self.descriptors[index]);
        let control = unsafe {
            core::ptr::read_volatile(core::ptr::addr_of!((*descriptor).control))
        };
        match descriptor_action(control, *offset, capacity) {
            DescriptorAction::Skip => return,
            DescriptorAction::Recycle => {}
            DescriptorAction::Copy(length) => {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        self.bounce[index].as_ptr(),
                        destination.add(*offset),
                        length,
                    );
                }
                *offset += length;
            }
        }
        unsafe {
            core::ptr::write_volatile(
                core::ptr::addr_of_mut!((*descriptor).control),
                hardware_owned_control(),
            );
        }
    }
}

const fn hardware_owned_control() -> u32 {
    (1 << 31) | (BOUNCE_SIZE as u32 & 0xFFF)
}
