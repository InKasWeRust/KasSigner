mod decode_boundaries;
mod encode_boundaries;
mod sink_boundaries;

use crate::wire::kspt::*;

struct VectorSource {
    output_script: Vec<u8>,
    full_trailers: bool,
}

impl VectorSource {
    fn minimal(output_len: usize) -> Self {
        Self {
            output_script: vec![0x51; output_len],
            full_trailers: false,
        }
    }
}

impl EncodeSource for VectorSource {
    fn global(&self) -> Global<'_> {
        Global {
            flags: FLAG_SIGNED_OR_COMPLETE,
            version: 2,
            input_count: if self.full_trailers { 1 } else { 0 },
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
        self.full_trailers.then_some([0x55; 32])
    }
    fn input_derivation(&self, _index: usize) -> Option<Derivation> {
        self.full_trailers.then_some(Derivation {
            branch: 0,
            index: 500,
        })
    }
    fn output_derivation(&self, _index: usize) -> Option<Derivation> {
        self.full_trailers.then_some(Derivation {
            branch: 1,
            index: 501,
        })
    }
    fn input_ms45(&self, _index: usize) -> Option<Ms45Derivation> {
        self.full_trailers.then_some(Ms45Derivation {
            cosigner: 2,
            chain: 0,
            index: 17,
        })
    }
    fn output_ms45(&self, _index: usize) -> Option<Ms45Derivation> {
        self.full_trailers.then_some(Ms45Derivation {
            cosigner: 2,
            chain: 1,
            index: 18,
        })
    }
    fn covenant(&self, _index: usize) -> Option<Covenant> {
        self.full_trailers.then_some(Covenant {
            authorizing_input: 0,
            id: [0x66; 32],
        })
    }
}

#[derive(Default)]
struct CaptureSink {
    flags: u8,
    network: u8,
    input_derivation: Option<Derivation>,
    output_derivation: Option<Derivation>,
    input_ms45: Option<Ms45Derivation>,
    output_ms45: Option<Ms45Derivation>,
    stealth: Option<[u8; 32]>,
    covenant: Option<Covenant>,
}

impl DecodeSink for CaptureSink {
    type Error = ();
    fn global(&mut self, value: Global<'_>) -> Result<(), Self::Error> {
        self.flags = value.flags;
        Ok(())
    }
    fn input(
        &mut self,
        _index: u32,
        _value: Input<'_>,
        _signature_count: u8,
    ) -> Result<(), Self::Error> {
        Ok(())
    }
    fn signature(&mut self, _input: u32, _slot: u8, _value: Signature) -> Result<(), Self::Error> {
        Ok(())
    }
    fn redeem(&mut self, _input: u32, _value: &[u8]) -> Result<(), Self::Error> {
        Ok(())
    }
    fn output(&mut self, _index: u8, _value: Output<'_>) -> Result<(), Self::Error> {
        Ok(())
    }
    fn network(&mut self, code: u8) -> Result<(), Self::Error> {
        self.network = code;
        Ok(())
    }
    fn stealth(&mut self, tweak: [u8; 32]) -> Result<(), Self::Error> {
        self.stealth = Some(tweak);
        Ok(())
    }
    fn input_derivation(&mut self, _input: u8, value: Derivation) -> Result<(), Self::Error> {
        self.input_derivation = Some(value);
        Ok(())
    }
    fn output_derivation(&mut self, _output: u8, value: Derivation) -> Result<(), Self::Error> {
        self.output_derivation = Some(value);
        Ok(())
    }
    fn input_ms45(&mut self, _input: u8, value: Ms45Derivation) -> Result<(), Self::Error> {
        self.input_ms45 = Some(value);
        Ok(())
    }
    fn output_ms45(&mut self, _output: u8, value: Ms45Derivation) -> Result<(), Self::Error> {
        self.output_ms45 = Some(value);
        Ok(())
    }
    fn covenant(
        &mut self,
        _output: u8,
        authorizing_input: u16,
        id: [u8; 32],
    ) -> Result<(), Self::Error> {
        self.covenant = Some(Covenant {
            authorizing_input,
            id,
        });
        Ok(())
    }
}

#[test]
fn canonical_codec_round_trips_every_v4_trailer() {
    let source = VectorSource {
        output_script: vec![0x51],
        full_trailers: true,
    };
    let wire = encode_vec(&source).expect("canonical encode");
    let mut sink = CaptureSink::default();
    let envelope = decode(&wire, &mut sink).expect("canonical decode");

    assert_eq!(envelope.flags, FLAG_SIGNED_OR_COMPLETE);
    assert_eq!(sink.network, 1);
    assert_eq!(
        sink.input_ms45,
        Some(Ms45Derivation {
            cosigner: 2,
            chain: 0,
            index: 17
        })
    );
    assert_eq!(
        sink.output_ms45,
        Some(Ms45Derivation {
            cosigner: 2,
            chain: 1,
            index: 18
        })
    );
    assert_eq!(sink.stealth, Some([0x55; 32]));
    assert_eq!(
        sink.covenant,
        Some(Covenant {
            authorizing_input: 0,
            id: [0x66; 32]
        })
    );
    assert_eq!(
        sink.input_derivation,
        Some(Derivation {
            branch: 0,
            index: 500
        })
    );
    assert_eq!(
        sink.output_derivation,
        Some(Derivation {
            branch: 1,
            index: 501
        })
    );
}

#[test]
fn canonical_validate_enters_every_v4_null_sink_trailer_callback() {
    let source = VectorSource {
        output_script: vec![0x51],
        full_trailers: true,
    };
    let wire = encode_vec(&source).expect("canonical full-trailer encode");
    assert_eq!(
        validate(&wire),
        Ok(DecodedEnvelope {
            flags: FLAG_SIGNED_OR_COMPLETE
        }),
    );
}

#[test]
fn canonical_encoder_owns_trailer_order() {
    let source = VectorSource {
        output_script: vec![0x51],
        full_trailers: true,
    };
    let wire = encode_vec(&source).expect("canonical encode");
    let mut expected = vec![NETWORK_MARKER, 1, MS45_INPUT_MARKER, 0];
    expected.extend_from_slice(&2u32.to_le_bytes());
    expected.extend_from_slice(&0u32.to_le_bytes());
    expected.extend_from_slice(&17u32.to_le_bytes());
    expected.extend_from_slice(&[MS45_OUTPUT_MARKER, 0]);
    expected.extend_from_slice(&2u32.to_le_bytes());
    expected.extend_from_slice(&1u32.to_le_bytes());
    expected.extend_from_slice(&18u32.to_le_bytes());
    expected.push(STEALTH_MARKER);
    expected.extend_from_slice(&[0x55; 32]);
    expected.extend_from_slice(&[COVENANT_MARKER, 0]);
    expected.extend_from_slice(&0u16.to_le_bytes());
    expected.extend_from_slice(&[0x66; 32]);
    expected.extend_from_slice(&[INPUT_DERIVATION_MARKER, 0, 0]);
    expected.extend_from_slice(&500u32.to_le_bytes());
    expected.extend_from_slice(&[OUTPUT_DERIVATION_MARKER, 0, 1]);
    expected.extend_from_slice(&501u32.to_le_bytes());
    assert!(wire.ends_with(&expected));
}

#[test]
fn canonical_extended_script_length_marker_is_ff() {
    for length in [255usize, 512] {
        let wire = encode_vec(&VectorSource::minimal(length)).expect("extended script encode");
        // header (6) + global (45) + output value/version (10)
        let prefix = 61usize;
        assert_eq!(wire[prefix], EXTENDED_SCRIPT_LENGTH);
        assert_eq!(
            u16::from_le_bytes([wire[prefix + 1], wire[prefix + 2]]),
            length as u16
        );
        let mut sink = CaptureSink::default();
        decode(&wire, &mut sink).expect("extended script decode");
    }
}

#[test]
fn canonical_codec_rejects_hardened_derivation() {
    struct BadDerivation(VectorSource);
    impl EncodeSource for BadDerivation {
        fn global(&self) -> Global<'_> {
            self.0.global()
        }
        fn input(&self, index: usize) -> Input<'_> {
            self.0.input(index)
        }
        fn signature_count(&self, input: usize) -> usize {
            self.0.signature_count(input)
        }
        fn signature(&self, input: usize, slot: usize) -> Signature {
            self.0.signature(input, slot)
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
            Some(Derivation {
                branch: 0,
                index: 0x8000_0000,
            })
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
    let source = BadDerivation(VectorSource {
        output_script: vec![0x51],
        full_trailers: true,
    });
    assert_eq!(encode_vec(&source), Err(WireError::InvalidTrailer));
}

#[test]
fn canonical_decoder_rejects_consumer_counts_before_rest_of_global_prefix() {
    let limits = DecodeLimits::new(16, 16, 1024);

    let mut excessive_inputs = [0u8; 12];
    excessive_inputs[..4].copy_from_slice(&MAGIC);
    excessive_inputs[4] = GENERATION_CURRENT;
    excessive_inputs[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        decode_with_limits(&excessive_inputs, &mut CaptureSink::default(), limits),
        Err(DecodeError::Wire(WireError::TooManyInputs)),
    );

    let mut excessive_outputs = [0u8; 13];
    excessive_outputs[..4].copy_from_slice(&MAGIC);
    excessive_outputs[4] = GENERATION_CURRENT;
    excessive_outputs[8..12].copy_from_slice(&1u32.to_le_bytes());
    excessive_outputs[12] = 17;
    assert_eq!(
        decode_with_limits(&excessive_outputs, &mut CaptureSink::default(), limits),
        Err(DecodeError::Wire(WireError::TooManyOutputs)),
    );
}

#[test]
fn canonical_decoder_applies_consumer_limits_before_variable_length_consumption() {
    let mut excessive_inputs = [0u8; 51];
    excessive_inputs[..4].copy_from_slice(&MAGIC);
    excessive_inputs[4] = GENERATION_CURRENT;
    excessive_inputs[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    excessive_inputs[12] = 1;
    let limits = DecodeLimits::new(16, 16, 1024);
    assert_eq!(
        decode_with_limits(&excessive_inputs, &mut CaptureSink::default(), limits),
        Err(DecodeError::Wire(WireError::TooManyInputs)),
    );

    let mut oversized_payload = [0u8; 51];
    oversized_payload[..4].copy_from_slice(&MAGIC);
    oversized_payload[4] = GENERATION_CURRENT;
    oversized_payload[8..12].copy_from_slice(&1u32.to_le_bytes());
    oversized_payload[12] = 1;
    oversized_payload[49..51].copy_from_slice(&1025u16.to_le_bytes());
    assert_eq!(
        decode_with_limits(&oversized_payload, &mut CaptureSink::default(), limits),
        Err(DecodeError::Wire(WireError::PayloadTooLong)),
    );
}
