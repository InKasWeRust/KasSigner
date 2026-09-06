use crate::entropy::{
    frame_noise::{
        is_live, should_retry_camera_window, CameraEntropyReport, CameraEntropyTracker, FrameNoise,
        MAX_CAMERA_HEALTH_WINDOWS, MAX_CONSECUTIVE_STALE_DELTAS, MIN_AC_FOR_ENTROPY_X100,
        MIN_CAPTURED_FRAMES, MIN_CHANGED_FOR_ENTROPY, MIN_LIVE_DELTAS,
    },
    rng_health::{inspect, RngHealthError, HEALTH_SAMPLE_COUNT},
};

fn noisy_frame(seed: u8) -> [u8; 256] {
    let mut frame = [0u8; 256];
    for (index, value) in frame.iter_mut().enumerate() {
        let x = index as u8;
        *value = x
            .wrapping_mul(73)
            .wrapping_add(seed.wrapping_mul(x.rotate_left(3)))
            .wrapping_add(seed);
    }
    frame
}

#[test]
fn camera_noise_rejects_frozen_and_global_shift_but_accepts_temporal_noise() {
    let frozen = FrameNoise {
        sampled: 256,
        changed: 0,
        mad_x100: 0,
        distinct: 1,
        mean_shift_x100: 0,
        ac_x100: 0,
    };
    assert!(!is_live(&frozen));
    let global = FrameNoise {
        sampled: 256,
        changed: MIN_CHANGED_FOR_ENTROPY,
        mad_x100: 500,
        distinct: 32,
        mean_shift_x100: 500,
        ac_x100: 0,
    };
    assert!(!is_live(&global));
    let temporal = FrameNoise {
        sampled: 256,
        changed: MIN_CHANGED_FOR_ENTROPY,
        mad_x100: MIN_AC_FOR_ENTROPY_X100 + 10,
        distinct: 2,
        mean_shift_x100: 0,
        ac_x100: MIN_AC_FOR_ENTROPY_X100 + 10,
    };
    assert!(is_live(&temporal));
}

#[test]
fn camera_tracker_requires_a_live_sequence_and_detects_stale_runs() {
    let mut healthy = CameraEntropyTracker::new();
    assert_eq!(healthy.observe(&noisy_frame(1)), None);
    for seed in 2..=7 {
        let noise = healthy.observe(&noisy_frame(seed)).expect("delta");
        assert!(is_live(&noise));
    }
    let report = healthy.report();
    assert_eq!(report.frames_captured, 7);
    assert_eq!(report.deltas_observed, 6);
    assert!(report.live_deltas >= 5);
    assert!(report.healthy());

    let mut frozen = CameraEntropyTracker::new();
    let frame = noisy_frame(9);
    assert_eq!(frozen.observe(&frame), None);
    for _ in 0..6 {
        assert!(!is_live(&frozen.observe(&frame).unwrap()));
    }
    let frozen_report = frozen.report();
    assert_eq!(frozen_report.live_deltas, 0);
    assert!(frozen_report.max_consecutive_stale_deltas >= 2);
    assert!(!frozen_report.healthy());
    assert_eq!(CameraEntropyTracker::new().observe(&[0u8; 255]), None);
}

fn healthy_rng_window() -> [u32; HEALTH_SAMPLE_COUNT] {
    [
        0xA3C5_1F27,
        0x6D91_E842,
        0xF072_3B5C,
        0x19AE_C7D4,
        0x82F6_4A31,
        0x5B0D_97E8,
        0xC14A_6F23,
        0x37D8_B592,
        0xE65C_108F,
        0x4A93_D761,
        0xB708_2ED5,
        0x2F61_C49A,
        0x91DB_7534,
        0x0CE7_A862,
        0xD439_1B5E,
        0x68A2_F30D,
        0x7E15_C894,
        0xB36F_20A7,
        0x25C8_7D31,
        0xDA04_96E2,
        0x4F72_B81C,
        0x83AD_5E60,
        0x1BC6_F439,
        0xC950_27AE,
        0x56E1_9C73,
        0xF38A_40D6,
        0x0D74_BE21,
        0xA16F_358C,
        0x79C2_E504,
        0x34B8_1FD7,
        0xE20D_6A59,
        0x8C57_B432,
    ]
}

#[test]
fn rng_health_accepts_structure_free_window_and_reports_metrics() {
    let report = inspect(&healthy_rng_window()).expect("healthy RNG vector");
    assert_eq!(report.repeated_words, 0);
    assert_eq!(report.distinct_words, 32);
    assert_eq!(report.stuck_bits, 0);
    assert!(!report.counter_pattern);
    assert!(!report.monotonic);
}

#[test]
fn rng_health_rejects_repetition_low_diversity_bias_stuck_bits_and_counters() {
    assert_eq!(
        inspect(&[0xDEAD_BEEF; HEALTH_SAMPLE_COUNT]),
        Err(RngHealthError::StuckRegister)
    );

    let mut repeated = healthy_rng_window();
    repeated[7] = repeated[6];
    assert_eq!(inspect(&repeated), Err(RngHealthError::RepetitionCount));

    let mut low_diversity = [0u32; HEALTH_SAMPLE_COUNT];
    for (i, value) in low_diversity.iter_mut().enumerate() {
        *value = if i.is_multiple_of(2) {
            0xAAAA_5555
        } else {
            0x5555_AAAA
        };
    }
    assert_eq!(inspect(&low_diversity), Err(RngHealthError::LowDiversity));

    let mut biased = healthy_rng_window();
    for (i, value) in biased.iter_mut().enumerate() {
        *value = 1u32 << (i % 32);
    }
    assert_eq!(inspect(&biased), Err(RngHealthError::AdaptiveProportion));

    let mut stuck_bit = healthy_rng_window();
    for value in &mut stuck_bit {
        *value &= 0x7fff_ffff;
    }
    assert_eq!(inspect(&stuck_bit), Err(RngHealthError::StuckBits));

    let counter =
        core::array::from_fn(|index| 0x1357_2468u32.wrapping_add((index as u32) * 0x0101_0101));
    assert_eq!(inspect(&counter), Err(RngHealthError::CounterPattern));

    let monotonic = [
        0x0667_1AD1,
        0x06CB_0FB3,
        0x07A0_CA6E,
        0x0822_E8F3,
        0x1641_9F82,
        0x17FC_695A,
        0x1A3D_1FA7,
        0x1C80_317F,
        0x23B8_C1E9,
        0x32E7_0629,
        0x37F8_A88B,
        0x3924_56DE,
        0x3B8F_AA18,
        0x3EB1_3B90,
        0x4668_5257,
        0x6B65_A6A4,
        0x6C03_1199,
        0x815E_F6D1,
        0x8B81_48F6,
        0x8B9D_2434,
        0x8FAD_C1A6,
        0x972A_8469,
        0x9A1D_E644,
        0xA3B1_799D,
        0xA65E_D389,
        0xAD3C_2D6D,
        0xB38A_088C,
        0xB74D_0FB1,
        0xBC89_60A9,
        0xBD9C_66B3,
        0xBDD6_40FB,
        0xE465_E150,
    ];
    assert_eq!(inspect(&monotonic), Err(RngHealthError::Monotonic));
}

#[test]
fn camera_entropy_thresholds_and_health_dimensions_are_exact() {
    assert_eq!(MIN_CHANGED_FOR_ENTROPY, 16);
    assert_eq!(MIN_AC_FOR_ENTROPY_X100, 20);

    let healthy = CameraEntropyReport {
        frames_captured: MIN_CAPTURED_FRAMES,
        deltas_observed: MIN_CAPTURED_FRAMES.saturating_sub(1),
        live_deltas: MIN_LIVE_DELTAS,
        max_consecutive_stale_deltas: MAX_CONSECUTIVE_STALE_DELTAS,
    };
    assert!(healthy.healthy());
    assert!(!CameraEntropyReport {
        frames_captured: MIN_CAPTURED_FRAMES - 1,
        ..healthy
    }
    .healthy());
    assert!(!CameraEntropyReport {
        live_deltas: MIN_LIVE_DELTAS - 1,
        ..healthy
    }
    .healthy());
    assert!(!CameraEntropyReport {
        max_consecutive_stale_deltas: MAX_CONSECUTIVE_STALE_DELTAS + 1,
        ..healthy
    }
    .healthy());
}

#[test]
fn camera_health_window_retry_policy_is_bounded_and_never_accepts_unhealthy_evidence() {
    assert_eq!(MAX_CAMERA_HEALTH_WINDOWS, 3);
    let unhealthy = CameraEntropyReport {
        frames_captured: 8,
        deltas_observed: 7,
        live_deltas: 3,
        max_consecutive_stale_deltas: 3,
    };
    assert!(!unhealthy.healthy());
    assert!(should_retry_camera_window(0, unhealthy));
    assert!(should_retry_camera_window(1, unhealthy));
    assert!(!should_retry_camera_window(2, unhealthy));

    let healthy = CameraEntropyReport {
        frames_captured: MIN_CAPTURED_FRAMES,
        deltas_observed: MIN_CAPTURED_FRAMES - 1,
        live_deltas: MIN_LIVE_DELTAS,
        max_consecutive_stale_deltas: MAX_CONSECUTIVE_STALE_DELTAS,
    };
    assert!(healthy.healthy());
    assert!(!should_retry_camera_window(0, healthy));
}

#[test]
fn camera_tracker_reports_exact_distinct_change_and_shift_statistics() {
    let baseline = [0u8; 256];
    let current = core::array::from_fn::<u8, 256, _>(|index| index as u8);
    let mut tracker = CameraEntropyTracker::new();
    assert_eq!(tracker.observe(&baseline), None);
    let noise = tracker.observe(&current).expect("second frame delta");
    assert_eq!(
        noise,
        FrameNoise {
            sampled: 256,
            changed: 255,
            mad_x100: 12_750,
            distinct: 256,
            mean_shift_x100: 12_750,
            ac_x100: 0,
        },
    );
}

#[test]
fn camera_tracker_counts_repeated_sample_values_once() {
    let baseline = [0u8; 256];
    let current = core::array::from_fn::<u8, 256, _>(|index| (index % 4) as u8);

    let mut tracker = CameraEntropyTracker::new();
    assert_eq!(tracker.observe(&baseline), None);
    let noise = tracker.observe(&current).expect("second frame delta");

    assert_eq!(noise.sampled, 256);
    assert_eq!(noise.distinct, 4);
}

#[test]
fn camera_tracker_samples_the_declared_stride_and_rejects_short_followup_frames() {
    let baseline = [0u8; 512];
    let mut current = [0xffu8; 512];
    for index in 0..256 {
        current[index * 2] = index as u8;
    }

    let mut tracker = CameraEntropyTracker::new();
    assert_eq!(tracker.observe(&baseline), None);
    let noise = tracker.observe(&current).expect("strided delta");
    assert_eq!(noise.changed, 255);
    assert_eq!(noise.distinct, 256);
    assert_eq!(noise.mad_x100, 12_750);
    assert_eq!(noise.mean_shift_x100, 12_750);
    assert_eq!(noise.ac_x100, 0);

    let before = tracker.report();
    assert_eq!(tracker.observe(&[0u8; 255]), None);
    assert_eq!(tracker.report(), before);
}

#[test]
fn rng_health_detects_stuck_one_bits_and_descending_monotonic_windows() {
    let mut stuck_one = healthy_rng_window();
    for value in &mut stuck_one {
        *value |= 0x8000_0000;
    }
    assert_eq!(inspect(&stuck_one), Err(RngHealthError::StuckBits));

    let ascending = [
        0x0667_1AD1,
        0x06CB_0FB3,
        0x07A0_CA6E,
        0x0822_E8F3,
        0x1641_9F82,
        0x17FC_695A,
        0x1A3D_1FA7,
        0x1C80_317F,
        0x23B8_C1E9,
        0x32E7_0629,
        0x37F8_A88B,
        0x3924_56DE,
        0x3B8F_AA18,
        0x3EB1_3B90,
        0x4668_5257,
        0x6B65_A6A4,
        0x6C03_1199,
        0x815E_F6D1,
        0x8B81_48F6,
        0x8B9D_2434,
        0x8FAD_C1A6,
        0x972A_8469,
        0x9A1D_E644,
        0xA3B1_799D,
        0xA65E_D389,
        0xAD3C_2D6D,
        0xB38A_088C,
        0xB74D_0FB1,
        0xBC89_60A9,
        0xBD9C_66B3,
        0xBDD6_40FB,
        0xE465_E150,
    ];
    let descending = core::array::from_fn::<u32, HEALTH_SAMPLE_COUNT, _>(|index| {
        ascending[HEALTH_SAMPLE_COUNT - 1 - index]
    });
    assert_eq!(inspect(&descending), Err(RngHealthError::Monotonic));
}

#[test]
fn camera_entropy_tracker_default_matches_new_state() {
    let mut tracker = CameraEntropyTracker::default();
    assert_eq!(tracker.observe(&[0u8; 255]), None);
}
