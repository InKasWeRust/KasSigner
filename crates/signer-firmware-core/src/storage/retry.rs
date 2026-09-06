//! Pure bounded-retry and register-polling policy for hardware adapters.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub log_attempts: u32,
}

impl RetryPolicy {
    pub const fn new(max_attempts: u32, log_attempts: u32) -> Self {
        Self {
            max_attempts,
            log_attempts,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryAction {
    Success,
    Retry { should_log: bool },
    Exhausted,
    Abort,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetryFailure {
    Exhausted,
    Aborted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenPollError {
    Unexpected,
    Timeout,
}

impl TokenPollError {
    pub const fn message(self, unexpected: &'static str, timeout: &'static str) -> &'static str {
        match self {
            Self::Unexpected => unexpected,
            Self::Timeout => timeout,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegisterPollError {
    Error,
    Timeout,
}

impl RegisterPollError {
    pub const fn message(self, error: &'static str, timeout: &'static str) -> &'static str {
        match self {
            Self::Error => error,
            Self::Timeout => timeout,
        }
    }
}

/// Classify one response. `retry_response=None` permits retrying any non-success response.
pub const fn classify_response(
    attempt: u32,
    response: u8,
    success_response: u8,
    retry_response: Option<u8>,
    policy: RetryPolicy,
) -> RetryAction {
    let should_abort = match retry_response {
        Some(retry) => retry != response,
        None => false,
    };

    if response == success_response {
        RetryAction::Success
    } else if should_abort {
        RetryAction::Abort
    } else if attempt.saturating_add(1) >= policy.max_attempts {
        RetryAction::Exhausted
    } else {
        RetryAction::Retry {
            should_log: attempt < policy.log_attempts,
        }
    }
}

/// Execute a bounded response retry while keeping the loop and state transitions host-testable.
pub fn run_response_retry<Command, OnRetry>(
    policy: RetryPolicy,
    success_response: u8,
    retry_response: Option<u8>,
    mut command: Command,
    mut on_retry: OnRetry,
) -> Result<u32, RetryFailure>
where
    Command: FnMut(u32) -> u8,
    OnRetry: FnMut(u32, u8, bool),
{
    for attempt in 0..policy.max_attempts {
        let response = command(attempt);
        match classify_response(attempt, response, success_response, retry_response, policy) {
            RetryAction::Success => return Ok(attempt),
            RetryAction::Retry { should_log } => on_retry(attempt, response, should_log),
            RetryAction::Abort => return Err(RetryFailure::Aborted),
            RetryAction::Exhausted => return Err(RetryFailure::Exhausted),
        }
    }
    Err(RetryFailure::Exhausted)
}

/// Poll an SPI-style busy byte until it becomes non-zero or the bound expires.
pub fn poll_not_busy<Read>(limit: u32, mut read: Read) -> bool
where
    Read: FnMut() -> u8,
{
    for _ in 0..limit {
        if read() != 0x00 {
            return true;
        }
    }
    false
}

/// Poll for an SD data token while distinguishing idle bytes from protocol errors.
pub fn poll_read_token<Read>(limit: u32, mut read: Read) -> Result<(), TokenPollError>
where
    Read: FnMut() -> u8,
{
    for _ in 0..limit {
        match read() {
            0xFE => return Ok(()),
            0xFF => {}
            _ => return Err(TokenPollError::Unexpected),
        }
    }
    Err(TokenPollError::Timeout)
}

/// Poll a status register until either an error bit or completion bit appears.
pub fn poll_register<Read>(
    limit: u32,
    error_mask: u32,
    done_mask: u32,
    mut read: Read,
) -> Result<u32, RegisterPollError>
where
    Read: FnMut() -> u32,
{
    for _ in 0..limit {
        let status = read();
        if status & error_mask != 0 {
            return Err(RegisterPollError::Error);
        }
        if status & done_mask != 0 {
            return Ok(status);
        }
    }
    Err(RegisterPollError::Timeout)
}

/// Poll until the selected register bits clear.
pub fn poll_bits_clear<Read>(limit: u32, mask: u32, mut read: Read) -> bool
where
    Read: FnMut() -> u32,
{
    for _ in 0..limit {
        if read() & mask == 0 {
            return true;
        }
    }
    false
}

/// Validate the four-byte CMD8 echo payload without board I/O.
pub const fn validate_cmd8_echo(response: [u8; 4]) -> bool {
    response[2] == 0x01 && response[3] == 0xAA
}

/// Interpret the CCS bit from the first OCR byte.
pub const fn ocr_is_high_capacity(first_byte: u8) -> bool {
    first_byte & 0x40 != 0
}

/// Validate an SD data-response token.
pub const fn write_response_accepted(response: u8) -> bool {
    response & 0x1F == 0x05
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SdHostCommandError {
    HardwareLocked,
    ResponseTimeout,
    ResponseCrc,
    Timeout,
}

impl SdHostCommandError {
    pub const fn message(
        self,
        hardware_locked: &'static str,
        response_timeout: &'static str,
        response_crc: &'static str,
        timeout: &'static str,
    ) -> &'static str {
        match self {
            Self::HardwareLocked => hardware_locked,
            Self::ResponseTimeout => response_timeout,
            Self::ResponseCrc => response_crc,
            Self::Timeout => timeout,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SdHostCommandPoll {
    pub limit: u32,
    pub require_crc: bool,
    pub hardware_locked_mask: u32,
    pub command_done_mask: u32,
    pub response_timeout_mask: u32,
    pub response_crc_mask: u32,
}

pub fn poll_sdhost_command<ReadStatus, ReadResponse, Clear>(
    poll: SdHostCommandPoll,
    mut read_status: ReadStatus,
    mut read_response: ReadResponse,
    mut clear: Clear,
) -> Result<u32, SdHostCommandError>
where
    ReadStatus: FnMut() -> u32,
    ReadResponse: FnMut() -> u32,
    Clear: FnMut(u32),
{
    for _ in 0..poll.limit {
        let status = read_status();
        if status & poll.hardware_locked_mask != 0 {
            clear(poll.hardware_locked_mask);
            return Err(SdHostCommandError::HardwareLocked);
        }
        if status & poll.command_done_mask == 0 {
            continue;
        }
        clear(poll.command_done_mask);
        if status & poll.response_timeout_mask != 0 {
            clear(poll.response_timeout_mask);
            return Err(SdHostCommandError::ResponseTimeout);
        }
        if status & poll.response_crc_mask != 0 {
            clear(poll.response_crc_mask);
            if poll.require_crc {
                return Err(SdHostCommandError::ResponseCrc);
            }
        }
        return Ok(read_response());
    }
    Err(SdHostCommandError::Timeout)
}

pub fn poll_r1_response<Read>(limit: u32, mut read: Read) -> Option<u8>
where
    Read: FnMut() -> u8,
{
    for _ in 0..limit {
        let response = read();
        if response & 0x80 == 0 {
            return Some(response);
        }
    }
    None
}

pub fn poll_ready_response<Attempt, Delay>(
    limit: u32,
    mut attempt: Attempt,
    mut delay: Delay,
) -> Option<u32>
where
    Attempt: FnMut() -> Option<u32>,
    Delay: FnMut(),
{
    for _ in 0..limit {
        if let Some(response) = attempt() {
            if response & (1 << 31) != 0 {
                return Some(response);
            }
        }
        delay();
    }
    None
}
