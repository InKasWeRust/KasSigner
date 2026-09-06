use crate::protocol::pskt::{
    error::PsktWireError,
    wire::{decode_root, decode_root_for_review, format_wire_error, ErrorStyle},
};

fn clone_error(error: &PsktWireError) -> PsktWireError {
    match error {
        PsktWireError::UnknownFormat => PsktWireError::UnknownFormat,
        PsktWireError::OuterHex(message) => PsktWireError::OuterHex(message.clone()),
        PsktWireError::TooShort => PsktWireError::TooShort,
        PsktWireError::MagicMismatch => PsktWireError::MagicMismatch,
        PsktWireError::InnerHex(message) => PsktWireError::InnerHex(message.clone()),
        PsktWireError::Json(message) => PsktWireError::Json(message.clone()),
    }
}

#[test]
fn wire_error_formatting_covers_standard_and_review_styles() {
    let cases = [
        (
            PsktWireError::UnknownFormat,
            "Not a PSKT/PSKB payload",
            "Not a PSKT/PSKB payload",
        ),
        (
            PsktWireError::OuterHex("bad".into()),
            "outer hex: bad",
            "Bad outer hex: bad",
        ),
        (
            PsktWireError::TooShort,
            "payload too short",
            "Payload too short",
        ),
        (
            PsktWireError::MagicMismatch,
            "wire magic does not match detected format",
            "wire magic does not match detected format",
        ),
        (
            PsktWireError::InnerHex("bad".into()),
            "inner hex: bad",
            "Bad inner hex: bad",
        ),
        (
            PsktWireError::Json("bad".into()),
            "JSON parse: bad",
            "JSON parse: bad",
        ),
    ];

    for (error, standard, review) in cases {
        assert_eq!(
            format_wire_error(clone_error(&error), ErrorStyle::Standard),
            standard,
        );
        assert_eq!(format_wire_error(error, ErrorStyle::Review), review);
    }
}

#[test]
fn exact_four_byte_magic_is_not_misclassified_as_a_short_outer_envelope() {
    let standard = decode_root("50534b54").unwrap_err();
    assert_ne!(standard, "payload too short");
    assert!(standard.starts_with("JSON parse:") || standard.starts_with("inner hex:"));

    let review = decode_root_for_review("50534b42").unwrap_err();
    assert_ne!(review, "Payload too short");
    assert!(review.starts_with("JSON parse:") || review.starts_with("Bad inner hex:"));
}
