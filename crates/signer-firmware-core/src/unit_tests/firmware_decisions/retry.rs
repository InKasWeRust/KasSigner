use crate::storage::retry::{
    classify_response, ocr_is_high_capacity, poll_bits_clear, poll_not_busy, poll_r1_response,
    poll_read_token, poll_ready_response, poll_register, poll_sdhost_command, run_response_retry,
    validate_cmd8_echo, write_response_accepted, RegisterPollError, RetryAction, RetryFailure,
    RetryPolicy, SdHostCommandError, SdHostCommandPoll, TokenPollError,
};

#[test]
fn retry_policy_covers_success_logging_exhaustion_and_abort() {
    let policy = RetryPolicy::new(3, 1);
    assert_eq!(
        classify_response(0, 1, 1, None, policy),
        RetryAction::Success
    );
    assert_eq!(
        classify_response(0, 0xff, 1, None, policy),
        RetryAction::Retry { should_log: true },
    );
    assert_eq!(
        classify_response(1, 0xff, 1, None, policy),
        RetryAction::Retry { should_log: false },
    );
    assert_eq!(
        classify_response(2, 0xff, 1, None, policy),
        RetryAction::Exhausted
    );
    assert_eq!(
        classify_response(0, 2, 0, Some(1), policy),
        RetryAction::Abort
    );
    assert_eq!(
        classify_response(0, 1, 0, Some(1), policy),
        RetryAction::Retry { should_log: true }
    );
}

#[test]
fn retry_runner_owns_attempt_state_and_reports_every_terminal_outcome() {
    let mut responses = [0xff, 0xff, 0x01].into_iter();
    let mut retries = std::vec::Vec::new();
    let success = run_response_retry(
        RetryPolicy::new(4, 1),
        0x01,
        None,
        |_| responses.next().unwrap(),
        |attempt, response, should_log| retries.push((attempt, response, should_log)),
    );
    assert_eq!(success, Ok(2));
    assert_eq!(retries, [(0, 0xff, true), (1, 0xff, false)]);

    assert_eq!(
        run_response_retry(RetryPolicy::new(3, 0), 0, Some(1), |_| 2, |_, _, _| {}),
        Err(RetryFailure::Aborted),
    );
    assert_eq!(
        run_response_retry(RetryPolicy::new(2, 0), 0, None, |_| 1, |_, _, _| {}),
        Err(RetryFailure::Exhausted),
    );
    assert_eq!(
        run_response_retry(RetryPolicy::new(0, 0), 0, None, |_| 0, |_, _, _| {}),
        Err(RetryFailure::Exhausted),
    );
}

#[test]
fn bounded_pollers_cover_success_protocol_error_and_timeout() {
    let mut busy = [0, 0, 1].into_iter();
    assert!(poll_not_busy(3, || busy.next().unwrap()));
    assert!(!poll_not_busy(2, || 0));

    let mut token = [0xff, 0xfe].into_iter();
    assert_eq!(poll_read_token(2, || token.next().unwrap()), Ok(()));
    assert_eq!(poll_read_token(1, || 0x0b), Err(TokenPollError::Unexpected));
    assert_eq!(poll_read_token(2, || 0xff), Err(TokenPollError::Timeout));
    assert_eq!(TokenPollError::Unexpected.message("bad", "late"), "bad");
    assert_eq!(TokenPollError::Timeout.message("bad", "late"), "late");

    let mut statuses = [0, 0x20].into_iter();
    assert_eq!(
        poll_register(2, 0x10, 0x20, || statuses.next().unwrap()),
        Ok(0x20)
    );
    assert_eq!(
        poll_register(1, 0x10, 0x20, || 0x10),
        Err(RegisterPollError::Error)
    );
    assert_eq!(
        poll_register(1, 0x10, 0x20, || 0),
        Err(RegisterPollError::Timeout)
    );
    assert_eq!(RegisterPollError::Error.message("bad", "late"), "bad");
    assert_eq!(RegisterPollError::Timeout.message("bad", "late"), "late");

    let mut reset = [1, 0].into_iter();
    assert!(poll_bits_clear(2, 1, || reset.next().unwrap()));
    assert!(!poll_bits_clear(1, 1, || 1));
}

#[test]
fn sd_response_helpers_cover_protocol_boundaries() {
    assert!(validate_cmd8_echo([0, 0, 1, 0xaa]));
    assert!(!validate_cmd8_echo([0, 0, 2, 0xaa]));
    assert!(!validate_cmd8_echo([0, 0, 1, 0xab]));
    assert!(ocr_is_high_capacity(0x40));
    assert!(!ocr_is_high_capacity(0x3f));
    assert!(write_response_accepted(0x05));
    assert!(write_response_accepted(0xe5));
    assert!(!write_response_accepted(0x0b));
}

#[test]
fn zero_attempt_policy_exhausts_without_underflow() {
    assert_eq!(
        classify_response(0, 1, 0, Some(1), RetryPolicy::new(0, 0)),
        RetryAction::Exhausted,
    );
}

const CONST_CLASSIFIED_RETRY: RetryAction =
    classify_response(0, 1, 0, Some(1), RetryPolicy::new(3, 1));

#[test]
fn retry_classification_remains_const_evaluable_on_stable_rust() {
    assert_eq!(
        CONST_CLASSIFIED_RETRY,
        RetryAction::Retry { should_log: true }
    );
}

#[test]
fn sdhost_command_poller_classifies_completion_and_protocol_errors() {
    let poll = |limit, require_crc| SdHostCommandPoll {
        limit,
        require_crc,
        hardware_locked_mask: 1,
        command_done_mask: 2,
        response_timeout_mask: 4,
        response_crc_mask: 8,
    };
    let mut cleared = std::vec::Vec::new();
    assert_eq!(
        poll_sdhost_command(
            poll(2, true),
            {
                let mut statuses = [0, 2].into_iter();
                move || statuses.next().unwrap()
            },
            || 0x1234,
            |mask| cleared.push(mask),
        ),
        Ok(0x1234),
    );
    assert_eq!(cleared, [2]);

    assert_eq!(
        poll_sdhost_command(poll(1, true), || 1, || 0, |_| {}),
        Err(SdHostCommandError::HardwareLocked),
    );
    assert_eq!(
        poll_sdhost_command(poll(1, true), || 2 | 4, || 0, |_| {}),
        Err(SdHostCommandError::ResponseTimeout),
    );
    assert_eq!(
        poll_sdhost_command(poll(1, true), || 2 | 8, || 0, |_| {}),
        Err(SdHostCommandError::ResponseCrc),
    );
    assert_eq!(
        poll_sdhost_command(poll(1, false), || 2 | 8, || 7, |_| {}),
        Ok(7),
    );
    assert_eq!(
        poll_sdhost_command(poll(1, false), || 0, || 0, |_| {}),
        Err(SdHostCommandError::Timeout),
    );
    assert_eq!(
        SdHostCommandError::HardwareLocked.message("h", "t", "c", "x"),
        "h"
    );
    assert_eq!(
        SdHostCommandError::ResponseTimeout.message("h", "t", "c", "x"),
        "t"
    );
    assert_eq!(
        SdHostCommandError::ResponseCrc.message("h", "t", "c", "x"),
        "c"
    );
    assert_eq!(SdHostCommandError::Timeout.message("h", "t", "c", "x"), "x");
}

#[test]
fn response_pollers_cover_r1_and_operating_condition_boundaries() {
    let mut r1 = [0xff, 0x01].into_iter();
    assert_eq!(poll_r1_response(2, || r1.next().unwrap()), Some(0x01));
    assert_eq!(poll_r1_response(1, || 0xff), None);

    let mut attempts = [None, Some(1 << 31)].into_iter();
    let mut delays = 0;
    assert_eq!(
        poll_ready_response(2, || attempts.next().unwrap(), || delays += 1),
        Some(1 << 31),
    );
    assert_eq!(delays, 1);
    assert_eq!(poll_ready_response(1, || Some(0), || {}), None);
}
