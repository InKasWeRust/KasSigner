use crate::storage::fifo::{
    drive_fifo_read, drive_fifo_write, pack_word_le, plan_read, plan_transfer, plan_write,
    sector_bounds, transfer_mode, unpack_word_le, write_words, FifoReadAction, FifoReadIo,
    FifoTransferError, FifoWriteAction, FifoWriteIo, TransferMode, TransferPlanError, SECTOR_BYTES,
};

#[test]
fn transfer_planning_checks_address_size_buffer_bounds_and_mode() {
    let high = plan_transfer(true, 7, 2, SECTOR_BYTES * 2).unwrap();
    assert_eq!((high.address, high.total_bytes, high.count), (7, 1024, 2));
    let standard = plan_transfer(false, 7, 1, SECTOR_BYTES).unwrap();
    assert_eq!(standard.address, 7 * 512);
    assert_eq!(
        plan_transfer(false, u32::MAX, 1, SECTOR_BYTES),
        Err(TransferPlanError::AddressOverflow)
    );
    assert_eq!(
        plan_transfer(true, 0, 2, SECTOR_BYTES),
        Err(TransferPlanError::BufferTooSmall)
    );
    assert_eq!(sector_bounds(0, 2), Some((0, 512)));
    assert_eq!(sector_bounds(1, 2), Some((512, 1024)));
    assert_eq!(sector_bounds(2, 2), None);
    assert_eq!(transfer_mode(0), TransferMode::Empty);
    assert_eq!(transfer_mode(1), TransferMode::Single);
    assert_eq!(transfer_mode(2), TransferMode::Multi);
}

#[test]
fn fifo_read_planning_prioritizes_errors_data_and_completion() {
    const ERROR: u32 = 1;
    const DONE: u32 = 2;
    assert_eq!(
        plan_read(ERROR | DONE, false, 0, 4, ERROR, DONE),
        FifoReadAction::Error
    );
    assert_eq!(
        plan_read(0, false, 0, 4, ERROR, DONE),
        FifoReadAction::ReadWord
    );
    assert_eq!(
        plan_read(DONE, false, 0, 4, ERROR, DONE),
        FifoReadAction::ReadWord
    );
    assert_eq!(
        plan_read(DONE, true, 4, 4, ERROR, DONE),
        FifoReadAction::Complete
    );
    assert_eq!(
        plan_read(DONE, true, 0, 4, ERROR, DONE),
        FifoReadAction::Incomplete
    );
    assert_eq!(plan_read(0, true, 0, 4, ERROR, DONE), FifoReadAction::Wait);
}

#[test]
fn fifo_write_planning_covers_error_backpressure_and_done() {
    const ERROR: u32 = 1;
    const DONE: u32 = 2;
    assert_eq!(
        plan_write(ERROR, false, 0, 4, ERROR, DONE),
        FifoWriteAction::Error
    );
    assert_eq!(
        plan_write(DONE, false, 0, 4, ERROR, DONE),
        FifoWriteAction::Complete
    );
    assert_eq!(
        plan_write(0, false, 0, 4, ERROR, DONE),
        FifoWriteAction::WriteWord
    );
    assert_eq!(
        plan_write(0, true, 0, 4, ERROR, DONE),
        FifoWriteAction::Wait
    );
    assert_eq!(
        plan_write(0, false, 4, 4, ERROR, DONE),
        FifoWriteAction::Wait
    );
}

#[derive(Clone, Copy)]
struct ReadStep {
    interrupts: u32,
    empty: bool,
    word: u32,
}

struct ReadIo<'a> {
    steps: &'a [ReadStep],
    index: usize,
    current: ReadStep,
    cleared: std::vec::Vec<u32>,
}

impl<'a> ReadIo<'a> {
    fn new(steps: &'a [ReadStep]) -> Self {
        Self {
            steps,
            index: 0,
            current: ReadStep {
                interrupts: 0,
                empty: true,
                word: 0,
            },
            cleared: std::vec::Vec::new(),
        }
    }
}

impl FifoReadIo for ReadIo<'_> {
    fn interrupts(&mut self) -> u32 {
        self.current = self.steps[self.index.min(self.steps.len() - 1)];
        self.index += 1;
        self.current.interrupts
    }

    fn fifo_empty(&mut self) -> bool {
        self.current.empty
    }
    fn read_word(&mut self) -> u32 {
        self.current.word
    }
    fn clear_interrupts(&mut self, mask: u32) {
        self.cleared.push(mask);
    }
}

#[derive(Clone, Copy)]
struct WriteStep {
    interrupts: u32,
    full: bool,
}

struct WriteIo<'a> {
    steps: &'a [WriteStep],
    index: usize,
    current: WriteStep,
    words: std::vec::Vec<u32>,
    cleared: std::vec::Vec<u32>,
}

impl<'a> WriteIo<'a> {
    fn new(steps: &'a [WriteStep]) -> Self {
        Self {
            steps,
            index: 0,
            current: WriteStep {
                interrupts: 0,
                full: true,
            },
            words: std::vec::Vec::new(),
            cleared: std::vec::Vec::new(),
        }
    }
}

impl FifoWriteIo for WriteIo<'_> {
    fn interrupts(&mut self) -> u32 {
        self.current = self.steps[self.index.min(self.steps.len() - 1)];
        self.index += 1;
        self.current.interrupts
    }

    fn fifo_full(&mut self) -> bool {
        self.current.full
    }
    fn write_word(&mut self, word: u32) {
        self.words.push(word);
    }
    fn clear_interrupts(&mut self, mask: u32) {
        self.cleared.push(mask);
    }
}

#[test]
fn fifo_drivers_cover_success_error_incomplete_timeout_and_alignment() {
    const ERROR: u32 = 1;
    const DONE: u32 = 2;
    let read_steps = [
        ReadStep {
            interrupts: 0,
            empty: false,
            word: 0x0403_0201,
        },
        ReadStep {
            interrupts: DONE,
            empty: true,
            word: 0,
        },
    ];
    let mut read_io = ReadIo::new(&read_steps);
    let mut output = [0u8; 4];
    assert_eq!(
        drive_fifo_read(&mut read_io, &mut output, 4, 2, ERROR, DONE),
        Ok(())
    );
    assert_eq!(output, [1, 2, 3, 4]);
    assert_eq!(read_io.cleared, [DONE]);

    let mut error_io = ReadIo::new(&[ReadStep {
        interrupts: ERROR,
        empty: true,
        word: 0,
    }]);
    assert_eq!(
        drive_fifo_read(&mut error_io, &mut output, 4, 1, ERROR, DONE),
        Err(FifoTransferError::Hardware)
    );
    let mut incomplete_io = ReadIo::new(&[ReadStep {
        interrupts: DONE,
        empty: true,
        word: 0,
    }]);
    assert_eq!(
        drive_fifo_read(&mut incomplete_io, &mut output, 4, 1, ERROR, DONE),
        Err(FifoTransferError::Incomplete)
    );
    let mut timeout_io = ReadIo::new(&[ReadStep {
        interrupts: 0,
        empty: true,
        word: 0,
    }]);
    assert_eq!(
        drive_fifo_read(&mut timeout_io, &mut output, 4, 1, ERROR, DONE),
        Err(FifoTransferError::Timeout)
    );

    let write_steps = [
        WriteStep {
            interrupts: 0,
            full: false,
        },
        WriteStep {
            interrupts: DONE,
            full: true,
        },
    ];
    let mut write_io = WriteIo::new(&write_steps);
    assert_eq!(
        drive_fifo_write(&mut write_io, &[1, 2, 3, 4], 4, 2, ERROR, DONE),
        Ok(())
    );
    assert_eq!(write_io.words, [0x0403_0201]);
    assert_eq!(write_io.cleared, [DONE]);

    let mut write_error = WriteIo::new(&[WriteStep {
        interrupts: ERROR,
        full: true,
    }]);
    assert_eq!(
        drive_fifo_write(&mut write_error, &[1, 2, 3, 4], 4, 1, ERROR, DONE),
        Err(FifoTransferError::Hardware)
    );
    let mut write_incomplete = WriteIo::new(&[WriteStep {
        interrupts: DONE,
        full: true,
    }]);
    assert_eq!(
        drive_fifo_write(&mut write_incomplete, &[1, 2, 3, 4], 4, 1, ERROR, DONE),
        Err(FifoTransferError::Incomplete)
    );
    let mut write_timeout = WriteIo::new(&[WriteStep {
        interrupts: 0,
        full: true,
    }]);
    assert_eq!(
        drive_fifo_write(&mut write_timeout, &[1, 2, 3, 4], 4, 1, ERROR, DONE),
        Err(FifoTransferError::Timeout)
    );
    let mut write_alignment = WriteIo::new(&[WriteStep {
        interrupts: 0,
        full: false,
    }]);
    assert_eq!(
        drive_fifo_write(&mut write_alignment, &[1, 2, 3], 3, 1, ERROR, DONE),
        Err(FifoTransferError::Alignment)
    );
}

#[test]
fn fifo_word_conversion_and_prefill_are_little_endian_and_bounds_safe() {
    let input = [1u8, 2, 3, 4, 5];
    assert_eq!(pack_word_le(&input, 0), Some(0x0403_0201));
    assert_eq!(pack_word_le(&input, 2), None);
    assert_eq!(pack_word_le(&input, usize::MAX), None);

    let mut output = [0u8; 5];
    assert_eq!(unpack_word_le(0x0403_0201, &mut output, 0), 4);
    assert_eq!(&output[..4], &[1, 2, 3, 4]);
    assert_eq!(unpack_word_le(0x0807_0605, &mut output, 4), 1);
    assert_eq!(output[4], 5);
    assert_eq!(unpack_word_le(0, &mut output, usize::MAX), 0);

    let mut words = std::vec::Vec::new();
    assert_eq!(
        write_words(&[1, 2, 3, 4, 5, 6, 7, 8], |word| words.push(word)),
        Ok(())
    );
    assert_eq!(words, [0x0403_0201, 0x0807_0605]);
    assert_eq!(
        write_words(&[1, 2, 3], |_| {}),
        Err(FifoTransferError::Alignment)
    );
    assert_eq!(FifoTransferError::Hardware.message("h", "i", "t", "a"), "h");
    assert_eq!(
        FifoTransferError::Incomplete.message("h", "i", "t", "a"),
        "i"
    );
    assert_eq!(FifoTransferError::Timeout.message("h", "i", "t", "a"), "t");
    assert_eq!(
        FifoTransferError::Alignment.message("h", "i", "t", "a"),
        "a"
    );
}
