use super::*;

struct OneInputSource {
    output_script: Vec<u8>,
}

impl OneInputSource {
    fn new() -> Self {
        Self {
            output_script: vec![0x51],
        }
    }
}

impl EncodeSource for OneInputSource {
    fn global(&self) -> Global<'_> {
        Global {
            flags: FLAG_SIGNED_OR_COMPLETE,
            version: 2,
            input_count: 1,
            output_count: 1,
            locktime: 7,
            subnetwork_id: [0x11; 20],
            gas: 9,
            payload: &[],
        }
    }

    fn input(&self, _index: usize) -> Input<'_> {
        Input {
            previous_tx_id: [0x22; 32],
            previous_index: 3,
            amount: 100,
            sequence: 4,
            sig_op_count: 1,
            script_version: 0,
            script: &[0x20, 0x33, 0xac],
        }
    }

    fn signature_count(&self, _input: usize) -> usize {
        1
    }
    fn signature(&self, _input: usize, _slot: usize) -> Signature {
        Signature {
            position: 0,
            sighash: 0x01,
            bytes: [0x44; 64],
        }
    }
    fn redeem(&self, _input: usize) -> &[u8] {
        &[]
    }
    fn output(&self, _index: usize) -> Output<'_> {
        Output {
            amount: 90,
            script_version: 0,
            script: &self.output_script,
        }
    }
    fn network(&self) -> u8 {
        1
    }
    fn stealth(&self) -> Option<[u8; 32]> {
        None
    }
    fn input_derivation(&self, _index: usize) -> Option<Derivation> {
        None
    }
    fn output_derivation(&self, _index: usize) -> Option<Derivation> {
        None
    }
    fn input_ms45(&self, _index: usize) -> Option<Ms45Derivation> {
        None
    }
    fn output_ms45(&self, _index: usize) -> Option<Ms45Derivation> {
        None
    }
    fn covenant(&self, _index: usize) -> Option<Covenant> {
        None
    }
}

fn one_input_transaction_body() -> Vec<u8> {
    let mut wire = encode_vec(&OneInputSource::new()).expect("one-input canonical vector");
    assert_eq!(&wire[wire.len() - 2..], &[NETWORK_MARKER, 1]);
    wire.truncate(wire.len() - 2);
    wire
}

fn one_input_with_trailers(trailers: &[u8]) -> Vec<u8> {
    let mut wire = one_input_transaction_body();
    wire.extend_from_slice(trailers);
    wire
}

fn derivation_trailer(marker: u8, position: u8, branch: u8, index: u32) -> Vec<u8> {
    let mut trailer = vec![marker, position, branch];
    trailer.extend_from_slice(&index.to_le_bytes());
    trailer
}

fn ms45_trailer(marker: u8, position: u8, cosigner: u32, chain: u32, index: u32) -> Vec<u8> {
    let mut trailer = vec![marker, position];
    trailer.extend_from_slice(&cosigner.to_le_bytes());
    trailer.extend_from_slice(&chain.to_le_bytes());
    trailer.extend_from_slice(&index.to_le_bytes());
    trailer
}

fn covenant_trailer(position: u8, authorizing_input: u16, id: u8) -> Vec<u8> {
    let mut trailer = vec![COVENANT_MARKER, position];
    trailer.extend_from_slice(&authorizing_input.to_le_bytes());
    trailer.extend_from_slice(&[id; 32]);
    trailer
}

fn assert_wire_error(wire: &[u8], expected: WireError) {
    assert_eq!(
        decode(wire, &mut CaptureSink::default()),
        Err(DecodeError::Wire(expected))
    );
}

#[test]
fn canonical_decoder_rejects_header_capacity_and_required_trailer_boundaries() {
    assert_wire_error(&[], WireError::BufferTooShort);

    let mut wire = encode_vec(&VectorSource::minimal(1)).expect("minimal vector");
    wire[0] ^= 0x01;
    assert_wire_error(&wire, WireError::InvalidMagic);

    let mut wire = encode_vec(&VectorSource::minimal(1)).expect("minimal vector");
    wire[4] = GENERATION_CURRENT.wrapping_sub(1);
    assert_wire_error(&wire, WireError::UnsupportedVersion);

    let mut wire = encode_vec(&VectorSource::minimal(1)).expect("minimal vector");
    wire[5] = 0x80;
    assert_wire_error(&wire, WireError::InvalidFlags);

    let mut wire = encode_vec(&VectorSource::minimal(1)).expect("minimal vector");
    wire[8..12].copy_from_slice(&1u32.to_le_bytes());
    assert_wire_error(&wire, WireError::CountOverflow);

    let body = one_input_transaction_body();
    assert_wire_error(&body, WireError::MissingNetwork);

    assert_wire_error(
        &one_input_with_trailers(&[NETWORK_MARKER, 0]),
        WireError::InvalidNetwork,
    );
    assert_wire_error(
        &one_input_with_trailers(&[NETWORK_MARKER, 1, NETWORK_MARKER, 1]),
        WireError::InvalidNetwork,
    );
    assert_wire_error(
        &one_input_with_trailers(&[NETWORK_MARKER, 1, b'Z']),
        WireError::TrailingData,
    );
}

#[test]
fn canonical_decoder_rejects_signature_and_script_boundaries() {
    const SIGNATURE_COUNT_OFFSET: usize = 110;
    const SIGNATURE_POSITION_OFFSET: usize = 111;
    const SIGNATURE_SIGHASH_OFFSET: usize = 112;

    let mut wire = encode_vec(&OneInputSource::new()).expect("one-input vector");
    wire[SIGNATURE_COUNT_OFFSET] = (MAX_SIGNATURE_RECORDS as u8) + 1;
    assert_wire_error(&wire, WireError::TooManySignatures);

    let mut wire = encode_vec(&OneInputSource::new()).expect("one-input vector");
    wire[SIGNATURE_SIGHASH_OFFSET] = 0;
    assert_wire_error(&wire, WireError::InvalidSigHashType);

    struct TwoSignatureSource(OneInputSource);
    impl EncodeSource for TwoSignatureSource {
        fn global(&self) -> Global<'_> {
            self.0.global()
        }
        fn input(&self, index: usize) -> Input<'_> {
            self.0.input(index)
        }
        fn signature_count(&self, _input: usize) -> usize {
            2
        }
        fn signature(&self, _input: usize, slot: usize) -> Signature {
            Signature {
                position: slot as u8,
                sighash: 0x01,
                bytes: [0x44; 64],
            }
        }
        fn redeem(&self, input: usize) -> &[u8] {
            self.0.redeem(input)
        }
        fn output(&self, index: usize) -> Output<'_> {
            self.0.output(index)
        }
        fn network(&self) -> u8 {
            self.0.network()
        }
        fn stealth(&self) -> Option<[u8; 32]> {
            None
        }
        fn input_derivation(&self, _index: usize) -> Option<Derivation> {
            None
        }
        fn output_derivation(&self, _index: usize) -> Option<Derivation> {
            None
        }
        fn input_ms45(&self, _index: usize) -> Option<Ms45Derivation> {
            None
        }
        fn output_ms45(&self, _index: usize) -> Option<Ms45Derivation> {
            None
        }
        fn covenant(&self, _index: usize) -> Option<Covenant> {
            None
        }
    }
    let mut wire =
        encode_vec(&TwoSignatureSource(OneInputSource::new())).expect("two-signature vector");
    // Second record follows position+sighash+64-byte signature = 66 bytes.
    wire[SIGNATURE_POSITION_OFFSET + 66] = wire[SIGNATURE_POSITION_OFFSET];
    assert_wire_error(&wire, WireError::DuplicateSignaturePosition);

    let mut wire = encode_vec(&VectorSource::minimal(MAX_SCRIPT_SIZE)).expect("max script vector");
    // header (6) + global (45) + output amount/version (10)
    let script_prefix = 61usize;
    assert_eq!(wire[script_prefix], EXTENDED_SCRIPT_LENGTH);
    wire[script_prefix + 1..script_prefix + 3]
        .copy_from_slice(&((MAX_SCRIPT_SIZE + 1) as u16).to_le_bytes());
    assert_wire_error(&wire, WireError::ScriptTooLong);
}

#[test]
fn canonical_decoder_rejects_duplicate_and_out_of_range_trailers() {
    let network = [NETWORK_MARKER, 1];

    let mut trailers = network.to_vec();
    trailers.push(STEALTH_MARKER);
    trailers.extend_from_slice(&[0x11; 32]);
    trailers.push(STEALTH_MARKER);
    trailers.extend_from_slice(&[0x22; 32]);
    assert_wire_error(
        &one_input_with_trailers(&trailers),
        WireError::InvalidTrailer,
    );

    for trailer in [
        derivation_trailer(INPUT_DERIVATION_MARKER, 1, 0, 0),
        derivation_trailer(OUTPUT_DERIVATION_MARKER, 1, 0, 0),
        derivation_trailer(INPUT_DERIVATION_MARKER, 0, 2, 0),
        derivation_trailer(OUTPUT_DERIVATION_MARKER, 0, 0, 0x8000_0000),
    ] {
        let mut trailers = network.to_vec();
        trailers.extend_from_slice(&trailer);
        assert_wire_error(
            &one_input_with_trailers(&trailers),
            WireError::InvalidTrailer,
        );
    }

    for marker in [INPUT_DERIVATION_MARKER, OUTPUT_DERIVATION_MARKER] {
        let first = derivation_trailer(marker, 0, 0, 7);
        let mut trailers = network.to_vec();
        trailers.extend_from_slice(&first);
        trailers.extend_from_slice(&first);
        assert_wire_error(
            &one_input_with_trailers(&trailers),
            WireError::InvalidTrailer,
        );
    }

    for trailer in [
        ms45_trailer(MS45_INPUT_MARKER, 1, 0, 0, 0),
        ms45_trailer(MS45_OUTPUT_MARKER, 1, 0, 0, 0),
        ms45_trailer(MS45_INPUT_MARKER, 0, 0, 2, 0),
        ms45_trailer(MS45_INPUT_MARKER, 0, 0x8000_0000, 0, 0),
        ms45_trailer(MS45_OUTPUT_MARKER, 0, 0, 0, 0x8000_0000),
    ] {
        let mut trailers = network.to_vec();
        trailers.extend_from_slice(&trailer);
        assert_wire_error(
            &one_input_with_trailers(&trailers),
            WireError::InvalidTrailer,
        );
    }

    for marker in [MS45_INPUT_MARKER, MS45_OUTPUT_MARKER] {
        let first = ms45_trailer(marker, 0, 2, 0, 7);
        let mut trailers = network.to_vec();
        trailers.extend_from_slice(&first);
        trailers.extend_from_slice(&first);
        assert_wire_error(
            &one_input_with_trailers(&trailers),
            WireError::InvalidTrailer,
        );
    }

    for trailer in [covenant_trailer(1, 0, 0x11), covenant_trailer(0, 1, 0x11)] {
        let mut trailers = network.to_vec();
        trailers.extend_from_slice(&trailer);
        assert_wire_error(
            &one_input_with_trailers(&trailers),
            WireError::InvalidTrailer,
        );
    }

    let covenant = covenant_trailer(0, 0, 0x11);
    let mut trailers = network.to_vec();
    trailers.extend_from_slice(&covenant);
    trailers.extend_from_slice(&covenant);
    assert_wire_error(
        &one_input_with_trailers(&trailers),
        WireError::InvalidTrailer,
    );
}
