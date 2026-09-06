//! Immutable advanced transaction-signing policy primitives.
//!
//! The firmware persists these values in an authenticated device-bound record.
//! This module deliberately contains only pure policy/date parsing and
//! evaluation so hardware adapters and UI code cannot drift on enforcement.

mod parsing;

pub use parsing::{parse_utc_yyyymmddhhmm, parse_weekly_windows};

pub const MAX_WEEKLY_WINDOWS: usize = 4;
pub const MIN_YEAR: u16 = 2000;
pub const MAX_YEAR: u16 = 2099;
const SECONDS_PER_DAY: u64 = 86_400;
const MINUTES_PER_DAY: u16 = 1_440;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UtcDateTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

impl UtcDateTime {
    pub const fn new(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Self {
        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }

    pub fn validate(self) -> Result<(), PolicyError> {
        if self.year < MIN_YEAR || self.year > MAX_YEAR {
            return Err(PolicyError::DateOutOfRange);
        }
        if self.month == 0 || self.month > 12 {
            return Err(PolicyError::InvalidDate);
        }
        let max_day = days_in_month(self.year, self.month);
        if self.day == 0
            || self.day > max_day
            || self.hour > 23
            || self.minute > 59
            || self.second > 59
        {
            return Err(PolicyError::InvalidDate);
        }
        Ok(())
    }

    pub fn to_unix_seconds(self) -> Result<u64, PolicyError> {
        self.validate()?;
        let days = days_before_year(self.year)
            + days_before_month(self.year, self.month)
            + u64::from(self.day - 1);
        Ok(days * SECONDS_PER_DAY
            + u64::from(self.hour) * 3_600
            + u64::from(self.minute) * 60
            + u64::from(self.second))
    }

    pub fn from_unix_seconds(unix: u64) -> Result<Self, PolicyError> {
        let max = UtcDateTime::new(MAX_YEAR, 12, 31, 23, 59, 59).to_unix_seconds()?;
        let min = UtcDateTime::new(MIN_YEAR, 1, 1, 0, 0, 0).to_unix_seconds()?;
        if unix < min || unix > max {
            return Err(PolicyError::DateOutOfRange);
        }
        let mut days = unix / SECONDS_PER_DAY;
        let seconds = unix % SECONDS_PER_DAY;
        let mut year = 1970u16;
        loop {
            let year_days = if is_leap_year(year) { 366 } else { 365 };
            if days < year_days {
                break;
            }
            days -= year_days;
            year += 1;
        }
        let mut month = 1u8;
        loop {
            let month_days = u64::from(days_in_month(year, month));
            if days < month_days {
                break;
            }
            days -= month_days;
            month += 1;
        }
        Ok(Self {
            year,
            month,
            day: days as u8 + 1,
            hour: (seconds / 3_600) as u8,
            minute: ((seconds % 3_600) / 60) as u8,
            second: (seconds % 60) as u8,
        })
    }

    /// Monday=0 through Sunday=6.
    pub fn weekday_monday0(self) -> Result<u8, PolicyError> {
        let days = self.to_unix_seconds()? / SECONDS_PER_DAY;
        // 1970-01-01 was Thursday; Monday-indexed Thursday is 3.
        Ok(((days + 3) % 7) as u8)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningWindow {
    pub weekday: u8,
    pub start_minute: u16,
    pub end_minute: u16,
}

impl SigningWindow {
    pub const EMPTY: Self = Self {
        weekday: 0,
        start_minute: 0,
        end_minute: 0,
    };

    pub fn validate(self) -> Result<(), PolicyError> {
        if self.weekday > 6
            || self.start_minute >= self.end_minute
            || self.end_minute > MINUTES_PER_DAY
        {
            return Err(PolicyError::InvalidWindow);
        }
        Ok(())
    }

    pub const fn contains(self, weekday: u8, minute: u16) -> bool {
        self.weekday == weekday && minute >= self.start_minute && minute < self.end_minute
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SigningPolicy {
    pub not_before_unix: u64,
    pub weekly_enabled: bool,
    pub weekly_count: u8,
    pub windows: [SigningWindow; MAX_WEEKLY_WINDOWS],
    /// Authenticated monotonic floor used to detect RTC rollback.
    pub rtc_floor_unix: u64,
}

impl SigningPolicy {
    pub const fn disabled() -> Self {
        Self {
            not_before_unix: 0,
            weekly_enabled: false,
            weekly_count: 0,
            windows: [SigningWindow::EMPTY; MAX_WEEKLY_WINDOWS],
            rtc_floor_unix: 0,
        }
    }

    pub const fn has_not_before(self) -> bool {
        self.not_before_unix != 0
    }
    pub const fn has_time_policy(self) -> bool {
        self.not_before_unix != 0 || self.weekly_enabled
    }

    /// Whether transaction authorization still needs a live RTC reading.
    /// A standalone no-sign-before lock is permanently matured once the
    /// authenticated monotonic floor proves the target was reached. Weekly
    /// windows always need current wall-clock time.
    pub const fn requires_clock(self) -> bool {
        self.weekly_enabled
            || (self.not_before_unix != 0 && self.rtc_floor_unix < self.not_before_unix)
    }

    pub fn validate(self) -> Result<(), PolicyError> {
        validate_window_shape(self)?;
        validate_windows(self)?;
        validate_policy_times(self)
    }

    pub fn evaluate(self, now_unix: u64) -> SigningDecision {
        if self.validate().is_err() {
            return SigningDecision::PolicyInvalid;
        }
        if self.rtc_floor_unix != 0 && now_unix < self.rtc_floor_unix {
            return SigningDecision::ClockRollback;
        }
        if self.not_before_unix != 0 && now_unix < self.not_before_unix {
            return SigningDecision::BeforeNotBefore;
        }
        if self.weekly_enabled {
            let Ok(now) = UtcDateTime::from_unix_seconds(now_unix) else {
                return SigningDecision::ClockInvalid;
            };
            let Ok(weekday) = now.weekday_monday0() else {
                return SigningDecision::ClockInvalid;
            };
            let minute = u16::from(now.hour) * 60 + u16::from(now.minute);
            let allowed = self.windows[..self.weekly_count as usize]
                .iter()
                .any(|window| window.contains(weekday, minute));
            if !allowed {
                return SigningDecision::OutsideWeeklyWindow;
            }
        }
        SigningDecision::Allowed
    }
}

fn validate_window_shape(policy: SigningPolicy) -> Result<(), PolicyError> {
    let count = usize::from(policy.weekly_count);
    if count > MAX_WEEKLY_WINDOWS {
        return Err(PolicyError::TooManyWindows);
    }
    if policy.weekly_enabled != (count != 0) {
        return Err(PolicyError::InvalidWindow);
    }
    if policy.windows[count..]
        .iter()
        .any(|window| *window != SigningWindow::EMPTY)
    {
        return Err(PolicyError::InvalidWindow);
    }
    Ok(())
}

fn validate_windows(policy: SigningPolicy) -> Result<(), PolicyError> {
    let count = usize::from(policy.weekly_count);
    for index in 0..count {
        policy.windows[index].validate()?;
        if policy.windows[index + 1..count]
            .iter()
            .any(|other| parsing::windows_overlap(policy.windows[index], *other))
        {
            return Err(PolicyError::OverlappingWindow);
        }
    }
    Ok(())
}

fn validate_policy_times(policy: SigningPolicy) -> Result<(), PolicyError> {
    if policy.not_before_unix != 0 {
        UtcDateTime::from_unix_seconds(policy.not_before_unix)?;
    }
    if policy.rtc_floor_unix != 0 {
        UtcDateTime::from_unix_seconds(policy.rtc_floor_unix)?;
    }
    Ok(())
}

impl Default for SigningPolicy {
    fn default() -> Self {
        Self::disabled()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningDecision {
    Allowed,
    ClockInvalid,
    ClockRollback,
    BeforeNotBefore,
    OutsideWeeklyWindow,
    PolicyInvalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    InvalidDate,
    DateOutOfRange,
    InvalidWindow,
    TooManyWindows,
    OverlappingWindow,
    InvalidFormat,
    NotFuture,
}

const fn is_leap_year(year: u16) -> bool {
    year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
}

const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn days_before_year(year: u16) -> u64 {
    let y = u64::from(year - 1);
    let before = y * 365 + y / 4 - y / 100 + y / 400;
    let base_y = 1969u64;
    let base = base_y * 365 + base_y / 4 - base_y / 100 + base_y / 400;
    before - base
}

fn days_before_month(year: u16, month: u8) -> u64 {
    let mut total = 0u64;
    let mut current = 1u8;
    while current < month {
        total += days_in_month(year, current) as u64;
        current += 1;
    }
    total
}
