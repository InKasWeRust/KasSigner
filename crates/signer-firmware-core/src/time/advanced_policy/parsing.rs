//! Text parsing for advanced signing-policy values.

use super::{PolicyError, SigningWindow, UtcDateTime, MAX_WEEKLY_WINDOWS};

pub fn parse_utc_yyyymmddhhmm(input: &[u8]) -> Result<UtcDateTime, PolicyError> {
    if input.len() != 12 || input.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(PolicyError::InvalidFormat);
    }
    let year = decimal4(&input[0..4])?;
    let month = decimal2(&input[4..6])? as u8;
    let day = decimal2(&input[6..8])? as u8;
    let hour = decimal2(&input[8..10])? as u8;
    let minute = decimal2(&input[10..12])? as u8;
    let value = UtcDateTime::new(year, month, day, hour, minute, 0);
    value.validate()?;
    Ok(value)
}

/// Parses `MON 08:10-08:25;MON 21:33-21:43` (up to four windows).
/// Windows are sorted into canonical weekday/start order and overlaps fail.
pub fn parse_weekly_windows(
    input: &[u8],
) -> Result<([SigningWindow; MAX_WEEKLY_WINDOWS], u8), PolicyError> {
    let (mut windows, count) = parse_window_list(input)?;
    sort_windows(&mut windows, count);
    reject_adjacent_overlaps(&windows, count)?;
    Ok((windows, count as u8))
}

fn parse_window_list(
    input: &[u8],
) -> Result<([SigningWindow; MAX_WEEKLY_WINDOWS], usize), PolicyError> {
    let mut windows = [SigningWindow::EMPTY; MAX_WEEKLY_WINDOWS];
    let mut count = 0usize;
    for raw in input.split(|byte| *byte == b';') {
        let part = trim_ascii(raw);
        if part.is_empty() {
            return Err(PolicyError::InvalidFormat);
        }
        if count >= MAX_WEEKLY_WINDOWS {
            return Err(PolicyError::TooManyWindows);
        }
        windows[count] = parse_window(part)?;
        count += 1;
    }
    if count == 0 {
        Err(PolicyError::InvalidFormat)
    } else {
        Ok((windows, count))
    }
}

fn sort_windows(windows: &mut [SigningWindow; MAX_WEEKLY_WINDOWS], count: usize) {
    for index in 1..count {
        let current = windows[index];
        let mut cursor = index;
        while cursor > 0 && window_key(current) < window_key(windows[cursor - 1]) {
            windows[cursor] = windows[cursor - 1];
            cursor -= 1;
        }
        windows[cursor] = current;
    }
}

fn reject_adjacent_overlaps(
    windows: &[SigningWindow; MAX_WEEKLY_WINDOWS],
    count: usize,
) -> Result<(), PolicyError> {
    if windows[..count]
        .windows(2)
        .any(|pair| windows_overlap(pair[0], pair[1]))
    {
        Err(PolicyError::OverlappingWindow)
    } else {
        Ok(())
    }
}

fn parse_window(input: &[u8]) -> Result<SigningWindow, PolicyError> {
    if input.len() < 14 || !input[3].is_ascii_whitespace() {
        return Err(PolicyError::InvalidFormat);
    }
    let weekday = parse_weekday(&input[..3])?;
    let (start_minute, end_minute) = parse_time_range(trim_ascii(&input[3..]))?;
    let value = SigningWindow {
        weekday,
        start_minute,
        end_minute,
    };
    value.validate()?;
    Ok(value)
}

fn parse_time_range(input: &[u8]) -> Result<(u16, u16), PolicyError> {
    if input.len() != 11 || input[2] != b':' || input[5] != b'-' || input[8] != b':' {
        return Err(PolicyError::InvalidFormat);
    }
    let start = parse_hhmm(&input[0..2], &input[3..5])?;
    let end = parse_hhmm(&input[6..8], &input[9..11])?;
    Ok((start, end))
}

fn parse_hhmm(hour: &[u8], minute: &[u8]) -> Result<u16, PolicyError> {
    let hour = decimal2(hour)?;
    let minute = decimal2(minute)?;
    if hour > 23 || minute > 59 {
        return Err(PolicyError::InvalidWindow);
    }
    Ok(hour * 60 + minute)
}

fn parse_weekday(input: &[u8]) -> Result<u8, PolicyError> {
    if eq_ascii_case(input, b"MON") {
        Ok(0)
    } else if eq_ascii_case(input, b"TUE") {
        Ok(1)
    } else if eq_ascii_case(input, b"WED") {
        Ok(2)
    } else if eq_ascii_case(input, b"THU") {
        Ok(3)
    } else if eq_ascii_case(input, b"FRI") {
        Ok(4)
    } else if eq_ascii_case(input, b"SAT") {
        Ok(5)
    } else if eq_ascii_case(input, b"SUN") {
        Ok(6)
    } else {
        Err(PolicyError::InvalidFormat)
    }
}

pub(super) fn windows_overlap(left: SigningWindow, right: SigningWindow) -> bool {
    left.weekday == right.weekday
        && left.start_minute < right.end_minute
        && right.start_minute < left.end_minute
}

const fn window_key(value: SigningWindow) -> u32 {
    value.weekday as u32 * 2_000 + value.start_minute as u32
}

fn decimal2(input: &[u8]) -> Result<u16, PolicyError> {
    if input.len() != 2 || input.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(PolicyError::InvalidFormat);
    }
    Ok(u16::from(input[0] - b'0') * 10 + u16::from(input[1] - b'0'))
}

fn decimal4(input: &[u8]) -> Result<u16, PolicyError> {
    if input.len() != 4 || input.iter().any(|byte| !byte.is_ascii_digit()) {
        return Err(PolicyError::InvalidFormat);
    }
    Ok(u16::from(input[0] - b'0') * 1000
        + u16::from(input[1] - b'0') * 100
        + u16::from(input[2] - b'0') * 10
        + u16::from(input[3] - b'0'))
}

fn trim_ascii(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(|byte| byte.is_ascii_whitespace()) {
        input = &input[1..];
    }
    while input.last().is_some_and(|byte| byte.is_ascii_whitespace()) {
        input = &input[..input.len() - 1];
    }
    input
}

fn eq_ascii_case(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}
