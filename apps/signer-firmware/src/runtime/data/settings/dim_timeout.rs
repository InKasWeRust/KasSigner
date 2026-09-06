//! User-selectable inactivity delay before the display enters dim mode.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ScreenDimTimeout {
    Seconds30 = 0,
    Minute1 = 1,
    Minutes2 = 2,
    Minutes5 = 3,
    Never = 4,
}

impl ScreenDimTimeout {
    pub const DEFAULT: Self = Self::Seconds30;

    pub const fn from_code(code: u8) -> Self {
        match code {
            1 => Self::Minute1,
            2 => Self::Minutes2,
            3 => Self::Minutes5,
            4 => Self::Never,
            _ => Self::Seconds30,
        }
    }

    pub const fn code(self) -> u8 { self as u8 }

    pub const fn next(self) -> Self {
        match self {
            Self::Seconds30 => Self::Minute1,
            Self::Minute1 => Self::Minutes2,
            Self::Minutes2 => Self::Minutes5,
            Self::Minutes5 => Self::Never,
            Self::Never => Self::Seconds30,
        }
    }

    pub const fn previous(self) -> Self {
        match self {
            Self::Seconds30 => Self::Never,
            Self::Minute1 => Self::Seconds30,
            Self::Minutes2 => Self::Minute1,
            Self::Minutes5 => Self::Minutes2,
            Self::Never => Self::Minutes5,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Seconds30 => "30 sec",
            Self::Minute1 => "1 min",
            Self::Minutes2 => "2 min",
            Self::Minutes5 => "5 min",
            Self::Never => "Never",
        }
    }

    /// Event-loop idle ticks are nominally one millisecond each. Long-running
    /// operations feed liveness separately and do not advance ordinary idle UI
    /// interaction, so this remains a stable user-facing inactivity policy.
    pub const fn ticks(self) -> Option<u32> {
        match self {
            Self::Seconds30 => Some(30_000),
            Self::Minute1 => Some(60_000),
            Self::Minutes2 => Some(120_000),
            Self::Minutes5 => Some(300_000),
            Self::Never => None,
        }
    }
}

