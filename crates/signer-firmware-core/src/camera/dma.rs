//! Pure planning and bounded-copy helpers for camera DMA adapters.

pub fn plan_decode_submission(
    width: usize,
    height: usize,
    input_len: usize,
    state_is_idle: bool,
    buffer_available: bool,
    buffer_len: usize,
) -> Option<usize> {
    let length = width.checked_mul(height)?;
    if input_len < length || !state_is_idle || !buffer_available || length > buffer_len {
        return None;
    }
    Some(length)
}

pub fn copy_sample_with<Read>(
    output: &mut [u8],
    ready: bool,
    available: usize,
    mut read: Read,
) -> usize
where
    Read: FnMut(usize) -> u8,
{
    if !ready || available == 0 || output.is_empty() {
        return 0;
    }
    let length = output.len().min(available);
    for (index, byte) in output[..length].iter_mut().enumerate() {
        *byte = read(index);
    }
    length
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescriptorAction {
    Skip,
    Recycle,
    Copy(usize),
}

pub fn descriptor_action(control: u32, offset: usize, capacity: usize) -> DescriptorAction {
    if (control >> 31) & 1 != 0 {
        return DescriptorAction::Skip;
    }
    let length = ((control >> 12) & 0x0fff) as usize;
    if length == 0 || offset.saturating_add(length) > capacity {
        return DescriptorAction::Recycle;
    }
    DescriptorAction::Copy(length)
}
