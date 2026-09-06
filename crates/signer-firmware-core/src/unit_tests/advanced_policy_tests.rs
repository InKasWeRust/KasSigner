use crate::advanced_policy::*;

#[test]
fn utc_round_trip_and_known_weekday() {
    let value = UtcDateTime::new(2026, 8, 10, 8, 10, 0); // Monday
    let unix = value.to_unix_seconds().unwrap();
    assert_eq!(UtcDateTime::from_unix_seconds(unix).unwrap(), value);
    assert_eq!(value.weekday_monday0().unwrap(), 0);
}

#[test]
fn weekly_parser_canonicalizes_and_rejects_overlap() {
    let (windows, count) = parse_weekly_windows(b"MON 21:33-21:43; MON 08:10-08:25").unwrap();
    assert_eq!(count, 2);
    assert_eq!(windows[0].start_minute, 8 * 60 + 10);
    assert_eq!(windows[1].start_minute, 21 * 60 + 33);
    assert_eq!(
        parse_weekly_windows(b"MON 08:10-08:25;MON 08:20-08:30"),
        Err(PolicyError::OverlappingWindow)
    );
}

#[test]
fn policy_fails_closed_outside_windows_and_on_rollback() {
    let (windows, count) = parse_weekly_windows(b"MON 08:10-08:25;MON 21:33-21:43").unwrap();
    let monday = UtcDateTime::new(2026, 8, 10, 8, 15, 0)
        .to_unix_seconds()
        .unwrap();
    let mut policy = SigningPolicy::disabled();
    policy.weekly_enabled = true;
    policy.weekly_count = count;
    policy.windows = windows;
    policy.rtc_floor_unix = monday - 60;
    assert_eq!(policy.evaluate(monday), SigningDecision::Allowed);
    assert_eq!(
        policy.evaluate(monday - 120),
        SigningDecision::ClockRollback
    );
    assert_eq!(
        policy.evaluate(monday + 20 * 60),
        SigningDecision::OutsideWeeklyWindow
    );
}

#[test]
fn not_before_is_inclusive() {
    let target = UtcDateTime::new(2027, 1, 1, 0, 0, 0)
        .to_unix_seconds()
        .unwrap();
    let mut policy = SigningPolicy::disabled();
    policy.not_before_unix = target;
    assert_eq!(
        policy.evaluate(target - 1),
        SigningDecision::BeforeNotBefore
    );
    assert_eq!(policy.evaluate(target), SigningDecision::Allowed);
}

#[test]
fn policy_rejects_nonempty_unused_window_slots() {
    let mut policy = SigningPolicy::disabled();
    policy.windows[0] = SigningWindow {
        weekday: 0,
        start_minute: 60,
        end_minute: 120,
    };
    assert_eq!(policy.validate(), Err(PolicyError::InvalidWindow));
}

#[test]
fn standalone_not_before_stops_requiring_clock_after_authenticated_maturity() {
    let target = UtcDateTime::new(2027, 1, 1, 0, 0, 0)
        .to_unix_seconds()
        .unwrap();
    let mut policy = SigningPolicy::disabled();
    policy.not_before_unix = target;
    policy.rtc_floor_unix = target - 1;
    assert!(policy.requires_clock());
    policy.rtc_floor_unix = target;
    assert!(!policy.requires_clock());

    let (windows, count) = parse_weekly_windows(b"MON 08:10-08:25").unwrap();
    policy.weekly_enabled = true;
    policy.weekly_count = count;
    policy.windows = windows;
    assert!(policy.requires_clock());
}

#[test]
fn utc_parser_covers_boundaries_leap_days_and_invalid_formats() {
    assert_eq!(
        parse_utc_yyyymmddhhmm(b"202802290705").unwrap(),
        UtcDateTime::new(2028, 2, 29, 7, 5, 0),
    );
    for invalid in [
        b"20280229070".as_slice(),
        b"2028AA290705".as_slice(),
        b"202702290705".as_slice(),
        b"202813010000".as_slice(),
        b"202801012460".as_slice(),
    ] {
        assert!(parse_utc_yyyymmddhhmm(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn weekly_parser_covers_every_weekday_and_format_rejections() {
    let (windows, count) =
        parse_weekly_windows(b"SUN 23:00-23:59;SAT 06:00-06:30;FRI 05:00-05:30;THU 04:00-04:30")
            .unwrap();
    assert_eq!(count, 4);
    assert_eq!(windows[0].weekday, 3);
    assert_eq!(windows[3].weekday, 6);

    for day in [b"MON", b"TUE", b"WED", b"THU", b"FRI", b"SAT", b"SUN"] {
        let mut text = [0u8; 15];
        text[..3].copy_from_slice(day);
        text[3..].copy_from_slice(b" 00:00-00:01");
        assert!(parse_weekly_windows(&text).is_ok());
    }

    for invalid in [
        b"".as_slice(),
        b"XXX 08:00-09:00".as_slice(),
        b"MON08:00-09:00".as_slice(),
        b"MON 8:00-09:00".as_slice(),
        b"MON 24:00-24:30".as_slice(),
        b"MON 08:60-09:00".as_slice(),
        b"MON 09:00-08:00".as_slice(),
        b"MON 08:00-09:00;TUE 08:00-09:00;WED 08:00-09:00;THU 08:00-09:00;FRI 08:00-09:00"
            .as_slice(),
    ] {
        assert!(parse_weekly_windows(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn signing_policy_validation_covers_shape_overlap_and_time_ranges() {
    let mut policy = SigningPolicy::disabled();
    policy.weekly_enabled = true;
    assert_eq!(policy.validate(), Err(PolicyError::InvalidWindow));

    policy.weekly_count = (MAX_WEEKLY_WINDOWS + 1) as u8;
    assert_eq!(policy.validate(), Err(PolicyError::TooManyWindows));

    let (windows, count) = parse_weekly_windows(b"MON 08:00-09:00;TUE 08:00-09:00").unwrap();
    policy = SigningPolicy::disabled();
    policy.weekly_enabled = true;
    policy.weekly_count = count;
    policy.windows = windows;
    assert!(policy.validate().is_ok());

    policy.windows[1] = SigningWindow {
        weekday: 0,
        start_minute: 8 * 60 + 30,
        end_minute: 9 * 60 + 30,
    };
    assert_eq!(policy.validate(), Err(PolicyError::OverlappingWindow));

    policy = SigningPolicy::disabled();
    policy.not_before_unix = 1;
    assert_eq!(policy.validate(), Err(PolicyError::DateOutOfRange));
    policy.not_before_unix = 0;
    policy.rtc_floor_unix = 1;
    assert_eq!(policy.validate(), Err(PolicyError::DateOutOfRange));
}

#[test]
fn datetime_validation_and_conversion_cover_range_edges() {
    assert_eq!(
        UtcDateTime::new(1999, 12, 31, 23, 59, 59).validate(),
        Err(PolicyError::DateOutOfRange),
    );
    assert_eq!(
        UtcDateTime::new(2100, 1, 1, 0, 0, 0).validate(),
        Err(PolicyError::DateOutOfRange),
    );
    for invalid in [
        UtcDateTime::new(2026, 0, 1, 0, 0, 0),
        UtcDateTime::new(2026, 13, 1, 0, 0, 0),
        UtcDateTime::new(2026, 4, 31, 0, 0, 0),
        UtcDateTime::new(2026, 1, 1, 24, 0, 0),
        UtcDateTime::new(2026, 1, 1, 0, 60, 0),
        UtcDateTime::new(2026, 1, 1, 0, 0, 60),
    ] {
        assert_eq!(invalid.validate(), Err(PolicyError::InvalidDate));
    }
    let min = UtcDateTime::new(MIN_YEAR, 1, 1, 0, 0, 0)
        .to_unix_seconds()
        .unwrap();
    let max = UtcDateTime::new(MAX_YEAR, 12, 31, 23, 59, 59)
        .to_unix_seconds()
        .unwrap();
    assert_eq!(UtcDateTime::from_unix_seconds(min).unwrap().year, MIN_YEAR);
    assert_eq!(UtcDateTime::from_unix_seconds(max).unwrap().year, MAX_YEAR);
    assert_eq!(
        UtcDateTime::from_unix_seconds(min - 1),
        Err(PolicyError::DateOutOfRange)
    );
    assert_eq!(
        UtcDateTime::from_unix_seconds(max + 1),
        Err(PolicyError::DateOutOfRange)
    );
}

#[test]
fn signing_policy_presence_helpers_and_default_match_disabled_policy() {
    let default = SigningPolicy::default();
    assert_eq!(default, SigningPolicy::disabled());
    assert!(!default.has_not_before());
    assert!(!default.has_time_policy());

    let mut with_not_before = default;
    with_not_before.not_before_unix = 1;
    assert!(with_not_before.has_not_before());
    assert!(with_not_before.has_time_policy());

    let mut weekly = default;
    weekly.weekly_enabled = true;
    assert!(!weekly.has_not_before());
    assert!(weekly.has_time_policy());
}

#[test]
fn signing_window_boundaries_and_policy_clock_errors_cover_short_circuits() {
    let window = SigningWindow {
        weekday: 2,
        start_minute: 60,
        end_minute: 120,
    };
    assert_eq!(window.validate(), Ok(()));
    assert!(window.contains(2, 60));
    assert!(window.contains(2, 119));
    assert!(!window.contains(1, 60));
    assert!(!window.contains(2, 59));
    assert!(!window.contains(2, 120));

    assert_eq!(
        SigningWindow {
            weekday: 7,
            ..window
        }
        .validate(),
        Err(PolicyError::InvalidWindow)
    );
    assert_eq!(
        SigningWindow {
            start_minute: 120,
            end_minute: 120,
            ..window
        }
        .validate(),
        Err(PolicyError::InvalidWindow)
    );
    assert_eq!(
        SigningWindow {
            start_minute: 121,
            end_minute: 120,
            ..window
        }
        .validate(),
        Err(PolicyError::InvalidWindow)
    );
    assert_eq!(
        SigningWindow {
            end_minute: 1_441,
            ..window
        }
        .validate(),
        Err(PolicyError::InvalidWindow)
    );

    let mut policy = SigningPolicy::disabled();
    policy.weekly_enabled = true;
    policy.weekly_count = 1;
    policy.windows[0] = SigningWindow {
        weekday: 0,
        start_minute: 0,
        end_minute: 1,
    };
    let before_supported_range = UtcDateTime::new(MIN_YEAR, 1, 1, 0, 0, 0)
        .to_unix_seconds()
        .unwrap()
        - 1;
    assert_eq!(
        policy.evaluate(before_supported_range),
        SigningDecision::ClockInvalid
    );

    policy.weekly_enabled = false;
    assert_eq!(
        policy.evaluate(before_supported_range),
        SigningDecision::PolicyInvalid
    );
}

#[test]
fn weekly_parser_covers_case_whitespace_delimiters_and_adjacent_nonoverlap() {
    let (windows, count) = parse_weekly_windows(b"  mon 08:00-09:00 ; TuE 09:00-10:00  ").unwrap();
    assert_eq!(count, 2);
    assert_eq!(windows[0].weekday, 0);
    assert_eq!(windows[1].weekday, 1);

    let adjacent = parse_weekly_windows(b"MON 08:00-09:00;MON 09:00-10:00").unwrap();
    assert_eq!(adjacent.1, 2);

    for invalid in [
        b"MON 0800-09:00".as_slice(),
        b"MON 08:0009:00".as_slice(),
        b"MON 08:00/09:00".as_slice(),
        b"MON 08:00-0900".as_slice(),
        b"MON 0a:00-09:00".as_slice(),
        b"MON 08:0a-09:00".as_slice(),
        b"MON 08:00-0a:00".as_slice(),
        b"MON 08:00-09:0a".as_slice(),
        b"MO 08:00-09:00".as_slice(),
    ] {
        assert!(parse_weekly_windows(invalid).is_err(), "{invalid:?}");
    }
}

#[test]
fn datetime_day_month_and_leap_boundaries_are_exact() {
    assert_eq!(UtcDateTime::new(2000, 2, 29, 0, 0, 0).validate(), Ok(()));
    assert_eq!(
        UtcDateTime::new(2001, 2, 29, 0, 0, 0).validate(),
        Err(PolicyError::InvalidDate)
    );
    assert_eq!(UtcDateTime::new(2096, 2, 29, 23, 59, 59).validate(), Ok(()));
    assert_eq!(
        UtcDateTime::new(2099, 2, 29, 0, 0, 0).validate(),
        Err(PolicyError::InvalidDate)
    );
    assert_eq!(
        UtcDateTime::new(2026, 1, 0, 0, 0, 0).validate(),
        Err(PolicyError::InvalidDate)
    );
    assert_eq!(
        UtcDateTime::new(2026, 1, 32, 0, 0, 0).validate(),
        Err(PolicyError::InvalidDate)
    );

    for value in [
        UtcDateTime::new(2000, 1, 1, 0, 0, 0),
        UtcDateTime::new(2000, 12, 31, 23, 59, 59),
        UtcDateTime::new(2028, 2, 29, 12, 34, 56),
        UtcDateTime::new(2099, 12, 31, 23, 59, 59),
    ] {
        let seconds = value.to_unix_seconds().unwrap();
        assert_eq!(UtcDateTime::from_unix_seconds(seconds).unwrap(), value);
    }
}

#[test]
fn requires_clock_and_unsorted_window_short_circuits_are_explicit() {
    let disabled = SigningPolicy::disabled();
    assert!(!disabled.requires_clock());

    let mut weekly = disabled;
    weekly.weekly_enabled = true;
    weekly.weekly_count = 1;
    weekly.windows[0] = SigningWindow {
        weekday: 0,
        start_minute: 60,
        end_minute: 120,
    };
    assert!(weekly.requires_clock());

    let mut pending_not_before = disabled;
    pending_not_before.not_before_unix = 100;
    pending_not_before.rtc_floor_unix = 99;
    assert!(pending_not_before.requires_clock());
    pending_not_before.rtc_floor_unix = 100;
    assert!(!pending_not_before.requires_clock());

    let mut reverse_disjoint = disabled;
    reverse_disjoint.weekly_enabled = true;
    reverse_disjoint.weekly_count = 2;
    reverse_disjoint.windows[0] = SigningWindow {
        weekday: 0,
        start_minute: 600,
        end_minute: 660,
    };
    reverse_disjoint.windows[1] = SigningWindow {
        weekday: 0,
        start_minute: 480,
        end_minute: 540,
    };
    assert_eq!(reverse_disjoint.validate(), Ok(()));

    assert_eq!(
        parse_weekly_windows(b"MONX08:00-09:00"),
        Err(PolicyError::InvalidFormat),
    );
    for invalid in [
        b"MON 08.00-09:00".as_slice(),
        b"MON 08:00/09:00".as_slice(),
        b"MON 08:00-09.00".as_slice(),
        b"MON 08:00-09:00X".as_slice(),
    ] {
        assert_eq!(
            parse_weekly_windows(invalid),
            Err(PolicyError::InvalidFormat)
        );
    }
}
