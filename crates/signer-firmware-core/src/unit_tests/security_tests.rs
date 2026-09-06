use crate::{
    entropy::frame_noise::CameraEntropyReport,
    security::{
        authorize_transaction_signing, device_identity_words_usable, timing_observations_usable,
        validate_seed_entropy, SeedEntropyError, SeedEntropyEvidence, SigningAuthorization,
        SigningAuthorizationError,
    },
};

#[test]
fn signing_authorization_fails_closed_for_every_missing_precondition() {
    let valid = SigningAuthorization {
        seed_loaded: true,
        review_authorized: true,
        reviewed_inputs: 2,
        transaction_inputs: 2,
        signing_input_index: 1,
    };
    assert_eq!(authorize_transaction_signing(valid), Ok(()));
    let cases = [
        (
            SigningAuthorization {
                seed_loaded: false,
                ..valid
            },
            SigningAuthorizationError::SeedUnavailable,
        ),
        (
            SigningAuthorization {
                review_authorized: false,
                ..valid
            },
            SigningAuthorizationError::ReviewIncomplete,
        ),
        (
            SigningAuthorization {
                reviewed_inputs: 0,
                transaction_inputs: 0,
                ..valid
            },
            SigningAuthorizationError::NoInputs,
        ),
        (
            SigningAuthorization {
                reviewed_inputs: 1,
                transaction_inputs: 0,
                ..valid
            },
            SigningAuthorizationError::NoInputs,
        ),
        (
            SigningAuthorization {
                reviewed_inputs: 1,
                ..valid
            },
            SigningAuthorizationError::InputCountMismatch,
        ),
        (
            SigningAuthorization {
                signing_input_index: 2,
                ..valid
            },
            SigningAuthorizationError::InputOutOfRange,
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(authorize_transaction_signing(input), Err(expected));
    }
}

#[test]
fn seed_entropy_requires_every_independent_evidence_source() {
    let valid = SeedEntropyEvidence {
        camera: CameraEntropyReport {
            frames_captured: 8,
            deltas_observed: 7,
            live_deltas: 7,
            max_consecutive_stale_deltas: 0,
        },
        hardware_rng_healthy: true,
        device_identity_mixed: true,
        timing_mixed: true,
    };
    assert_eq!(validate_seed_entropy(valid), Ok(()));
    assert_eq!(
        validate_seed_entropy(SeedEntropyEvidence {
            camera: CameraEntropyReport {
                frames_captured: 8,
                deltas_observed: 7,
                live_deltas: 0,
                max_consecutive_stale_deltas: 7
            },
            ..valid
        }),
        Err(SeedEntropyError::CameraUnavailable)
    );
    assert_eq!(
        validate_seed_entropy(SeedEntropyEvidence {
            hardware_rng_healthy: false,
            ..valid
        }),
        Err(SeedEntropyError::HardwareRngUnavailable)
    );
    assert_eq!(
        validate_seed_entropy(SeedEntropyEvidence {
            device_identity_mixed: false,
            ..valid
        }),
        Err(SeedEntropyError::DeviceIdentityUnavailable)
    );
    assert_eq!(
        validate_seed_entropy(SeedEntropyEvidence {
            timing_mixed: false,
            ..valid
        }),
        Err(SeedEntropyError::TimingUnavailable)
    );
}

#[test]
fn entropy_source_observations_reject_stuck_or_unavailable_hardware() {
    assert!(!timing_observations_usable((0, 0), (0, 0)));
    assert!(!timing_observations_usable((5, 9), (5, 9)));
    assert!(timing_observations_usable((0, 0), (0, 1)));
    assert!(timing_observations_usable((1, 0), (0, 0)));
    assert!(timing_observations_usable((5, 9), (5, 10)));
    assert!(!device_identity_words_usable(&[]));
    assert!(!device_identity_words_usable(&[0, 0, u32::MAX]));
    assert!(device_identity_words_usable(&[0, 0x1234_5678, u32::MAX]));
}
