use crate::{PsktParsed, TxInputFormat};

#[test]
fn pskt_format_and_default_state_accessors_are_covered() {
    assert!(!TxInputFormat::KsptCompact.is_pskt());
    assert!(TxInputFormat::PsktPskb.is_pskt());
    assert!(TxInputFormat::PsktSingle.is_pskt());

    let parsed = PsktParsed::default();
    assert_eq!(parsed.unknowns_count, 0);
    assert_eq!(parsed.json_len, 0);
    assert!(!parsed.output_has_covenant_binding_field(0));
}

#[test]
fn covenant_binding_presence_tracks_valid_output_bits_only() {
    let mut parsed = PsktParsed::empty();

    parsed.mark_output_covenant_binding_field(0);
    parsed.mark_output_covenant_binding_field(15);
    parsed.mark_output_covenant_binding_field(16);
    parsed.mark_output_covenant_binding_field(usize::MAX);

    assert!(parsed.output_has_covenant_binding_field(0));
    assert!(parsed.output_has_covenant_binding_field(15));
    assert!(!parsed.output_has_covenant_binding_field(14));
    assert!(!parsed.output_has_covenant_binding_field(16));
    assert!(!parsed.output_has_covenant_binding_field(usize::MAX));
    assert_eq!(
        parsed.output_covenant_binding_present,
        (1u16 << 0) | (1u16 << 15)
    );
}
