//! Pure block-transfer validation, address calculation, and FIFO decisions.

pub const SECTOR_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferPlanError {
    AddressOverflow,
    SizeOverflow,
    BufferTooSmall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferPlan {
    pub address: u32,
    pub total_bytes: usize,
    pub count: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferMode {
    Empty,
    Single,
    Multi,
}

pub const fn transfer_mode(count: u32) -> TransferMode {
    match count {
        0 => TransferMode::Empty,
        1 => TransferMode::Single,
        _ => TransferMode::Multi,
    }
}

pub fn plan_transfer(
    high_capacity: bool,
    block: u32,
    count: u32,
    buffer_len: usize,
) -> Result<TransferPlan, TransferPlanError> {
    let address = if high_capacity {
        block
    } else {
        block
            .checked_mul(SECTOR_BYTES as u32)
            .ok_or(TransferPlanError::AddressOverflow)?
    };
    let total_bytes_u32 = count
        .checked_mul(SECTOR_BYTES as u32)
        .ok_or(TransferPlanError::SizeOverflow)?;
    let total_bytes =
        usize::try_from(total_bytes_u32).map_err(|_| TransferPlanError::SizeOverflow)?;
    if total_bytes > buffer_len {
        return Err(TransferPlanError::BufferTooSmall);
    }
    Ok(TransferPlan {
        address,
        total_bytes,
        count,
    })
}

pub fn sector_bounds(index: u32, count: u32) -> Option<(usize, usize)> {
    if index >= count {
        return None;
    }
    let start = usize::try_from(index).ok()?.checked_mul(SECTOR_BYTES)?;
    Some((start, start.checked_add(SECTOR_BYTES)?))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FifoReadAction {
    Error,
    ReadWord,
    Complete,
    Incomplete,
    Wait,
}

pub const fn plan_read(
    interrupts: u32,
    fifo_empty: bool,
    bytes_read: usize,
    total_bytes: usize,
    error_mask: u32,
    transfer_done_mask: u32,
) -> FifoReadAction {
    if interrupts & error_mask != 0 {
        FifoReadAction::Error
    } else if !fifo_empty && bytes_read < total_bytes {
        FifoReadAction::ReadWord
    } else if interrupts & transfer_done_mask != 0 {
        if bytes_read >= total_bytes {
            FifoReadAction::Complete
        } else {
            FifoReadAction::Incomplete
        }
    } else {
        FifoReadAction::Wait
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FifoWriteAction {
    Error,
    WriteWord,
    Complete,
    Wait,
}

pub const fn plan_write(
    interrupts: u32,
    fifo_full: bool,
    bytes_written: usize,
    total_bytes: usize,
    error_mask: u32,
    transfer_done_mask: u32,
) -> FifoWriteAction {
    if interrupts & error_mask != 0 {
        FifoWriteAction::Error
    } else if interrupts & transfer_done_mask != 0 {
        FifoWriteAction::Complete
    } else if !fifo_full && bytes_written < total_bytes {
        FifoWriteAction::WriteWord
    } else {
        FifoWriteAction::Wait
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FifoTransferError {
    Hardware,
    Incomplete,
    Timeout,
    Alignment,
}

impl FifoTransferError {
    pub const fn message(
        self,
        hardware: &'static str,
        incomplete: &'static str,
        timeout: &'static str,
        alignment: &'static str,
    ) -> &'static str {
        match self {
            Self::Hardware => hardware,
            Self::Incomplete => incomplete,
            Self::Timeout => timeout,
            Self::Alignment => alignment,
        }
    }
}

pub trait FifoReadIo {
    fn interrupts(&mut self) -> u32;
    fn fifo_empty(&mut self) -> bool;
    fn read_word(&mut self) -> u32;
    fn clear_interrupts(&mut self, mask: u32);
}

pub trait FifoWriteIo {
    fn interrupts(&mut self) -> u32;
    fn fifo_full(&mut self) -> bool;
    fn write_word(&mut self, word: u32);
    fn clear_interrupts(&mut self, mask: u32);
}

pub fn drive_fifo_read<I: FifoReadIo>(
    io: &mut I,
    output: &mut [u8],
    total_bytes: usize,
    limit: u32,
    error_mask: u32,
    done_mask: u32,
) -> Result<(), FifoTransferError> {
    let mut bytes_read = 0usize;
    for _ in 0..limit {
        let interrupts = io.interrupts();
        match plan_read(
            interrupts,
            io.fifo_empty(),
            bytes_read,
            total_bytes,
            error_mask,
            done_mask,
        ) {
            FifoReadAction::Error => {
                io.clear_interrupts(interrupts);
                return Err(FifoTransferError::Hardware);
            }
            FifoReadAction::ReadWord => {
                bytes_read += unpack_word_le(io.read_word(), output, bytes_read);
            }
            FifoReadAction::Complete => {
                io.clear_interrupts(done_mask);
                return Ok(());
            }
            FifoReadAction::Incomplete => {
                io.clear_interrupts(done_mask);
                return Err(FifoTransferError::Incomplete);
            }
            FifoReadAction::Wait => {}
        }
    }
    Err(FifoTransferError::Timeout)
}

pub fn drive_fifo_write<I: FifoWriteIo>(
    io: &mut I,
    input: &[u8],
    total_bytes: usize,
    limit: u32,
    error_mask: u32,
    done_mask: u32,
) -> Result<(), FifoTransferError> {
    let mut bytes_written = 0usize;
    for _ in 0..limit {
        let interrupts = io.interrupts();
        match plan_write(
            interrupts,
            io.fifo_full(),
            bytes_written,
            total_bytes,
            error_mask,
            done_mask,
        ) {
            FifoWriteAction::Error => {
                io.clear_interrupts(interrupts);
                return Err(FifoTransferError::Hardware);
            }
            FifoWriteAction::WriteWord => {
                let word =
                    pack_word_le(input, bytes_written).ok_or(FifoTransferError::Alignment)?;
                io.write_word(word);
                bytes_written += 4;
            }
            FifoWriteAction::Complete => {
                io.clear_interrupts(done_mask);
                return if bytes_written == total_bytes {
                    Ok(())
                } else {
                    Err(FifoTransferError::Incomplete)
                };
            }
            FifoWriteAction::Wait => {}
        }
    }
    Err(FifoTransferError::Timeout)
}

pub fn write_words<Write>(input: &[u8], mut write: Write) -> Result<(), FifoTransferError>
where
    Write: FnMut(u32),
{
    for offset in (0..input.len()).step_by(4) {
        let word = pack_word_le(input, offset).ok_or(FifoTransferError::Alignment)?;
        write(word);
    }
    Ok(())
}

pub fn unpack_word_le(word: u32, output: &mut [u8], offset: usize) -> usize {
    let available = output.len().saturating_sub(offset).min(4);
    for index in 0..available {
        output[offset + index] = ((word >> (index * 8)) & 0xff) as u8;
    }
    available
}

pub fn pack_word_le(input: &[u8], offset: usize) -> Option<u32> {
    let bytes = input.get(offset..offset.checked_add(4)?)?;
    Some(
        u32::from(bytes[0])
            | (u32::from(bytes[1]) << 8)
            | (u32::from(bytes[2]) << 16)
            | (u32::from(bytes[3]) << 24),
    )
}
