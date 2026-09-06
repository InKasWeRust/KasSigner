use super::*;

struct EncoderBoundarySource {
    output_script: Vec<u8>,
    input_script: Vec<u8>,
    redeem: Vec<u8>,
    payload: Vec<u8>,
    flags: u8,
    network: u8,
    signature_count: usize,
    duplicate_signatures: bool,
    sighash: u8,
    derivation: Option<Derivation>,
    ms45: Option<Ms45Derivation>,
}

impl EncoderBoundarySource {
    fn new() -> Self {
        Self {
            output_script: vec![0x51],
            input_script: vec![0x51],
            redeem: Vec::new(),
            payload: Vec::new(),
            flags: FLAG_SIGNED_OR_COMPLETE,
            network: 1,
            signature_count: 1,
            duplicate_signatures: false,
            sighash: 0x01,
            derivation: None,
            ms45: None,
        }
    }
}

impl EncodeSource for EncoderBoundarySource {
    fn global(&self) -> Global<'_> {
        Global {
            flags: self.flags,
            version: 2,
            input_count: 1,
            output_count: 1,
            locktime: 0,
            subnetwork_id: [0; 20],
            gas: 0,
            payload: &self.payload,
        }
    }

    fn input(&self, _index: usize) -> Input<'_> {
        Input {
            previous_tx_id: [0x22; 32],
            previous_index: 0,
            amount: 10,
            sequence: 0,
            sig_op_count: 1,
            script_version: 0,
            script: &self.input_script,
        }
    }

    fn signature_count(&self, _input: usize) -> usize {
        self.signature_count
    }
    fn signature(&self, _input: usize, slot: usize) -> Signature {
        Signature {
            position: if self.duplicate_signatures {
                0
            } else {
                slot as u8
            },
            sighash: self.sighash,
            bytes: [0x33; 64],
        }
    }
    fn redeem(&self, _input: usize) -> &[u8] {
        &self.redeem
    }
    fn output(&self, _index: usize) -> Output<'_> {
        Output {
            amount: 9,
            script_version: 0,
            script: &self.output_script,
        }
    }
    fn network(&self) -> u8 {
        self.network
    }
    fn stealth(&self) -> Option<[u8; 32]> {
        None
    }
    fn input_derivation(&self, _index: usize) -> Option<Derivation> {
        self.derivation
    }
    fn output_derivation(&self, _index: usize) -> Option<Derivation> {
        None
    }
    fn input_ms45(&self, _index: usize) -> Option<Ms45Derivation> {
        self.ms45
    }
    fn output_ms45(&self, _index: usize) -> Option<Ms45Derivation> {
        None
    }
    fn covenant(&self, _index: usize) -> Option<Covenant> {
        None
    }
}

#[test]
fn canonical_encoder_rejects_every_resource_and_signature_boundary() {
    let source = EncoderBoundarySource::new();
    assert_eq!(
        encode(&source, &mut []),
        Err(WireError::OutputBufferTooSmall)
    );

    let mut source = EncoderBoundarySource::new();
    source.flags = 0x80;
    assert_eq!(encode_vec(&source), Err(WireError::InvalidFlags));

    let mut source = EncoderBoundarySource::new();
    source.payload = vec![0; usize::from(u16::MAX) + 1];
    assert_eq!(encode_vec(&source), Err(WireError::CountOverflow));

    let mut source = EncoderBoundarySource::new();
    source.network = 0;
    assert_eq!(encode_vec(&source), Err(WireError::InvalidNetwork));

    let mut source = EncoderBoundarySource::new();
    source.signature_count = MAX_SIGNATURE_RECORDS + 1;
    assert_eq!(encode_vec(&source), Err(WireError::TooManySignatures));

    let mut source = EncoderBoundarySource::new();
    source.signature_count = 2;
    source.duplicate_signatures = true;
    assert_eq!(
        encode_vec(&source),
        Err(WireError::DuplicateSignaturePosition)
    );

    let mut source = EncoderBoundarySource::new();
    source.sighash = 0;
    assert_eq!(encode_vec(&source), Err(WireError::InvalidSigHashType));

    let mut source = EncoderBoundarySource::new();
    source.input_script = vec![0x51; MAX_SCRIPT_SIZE + 1];
    assert_eq!(encode_vec(&source), Err(WireError::ScriptTooLong));

    let mut source = EncoderBoundarySource::new();
    source.output_script = vec![0x51; MAX_SCRIPT_SIZE + 1];
    assert_eq!(encode_vec(&source), Err(WireError::ScriptTooLong));

    let mut source = EncoderBoundarySource::new();
    source.redeem = vec![0x51; usize::from(u16::MAX) + 1];
    assert_eq!(encode_vec(&source), Err(WireError::RedeemTooLong));
}

#[test]
fn canonical_encoder_rejects_each_derivation_component_boundary() {
    for derivation in [
        Derivation {
            branch: 2,
            index: 0,
        },
        Derivation {
            branch: 0,
            index: 0x8000_0000,
        },
    ] {
        let mut source = EncoderBoundarySource::new();
        source.derivation = Some(derivation);
        assert_eq!(encode_vec(&source), Err(WireError::InvalidTrailer));
    }

    for ms45 in [
        Ms45Derivation {
            cosigner: 0,
            chain: 2,
            index: 0,
        },
        Ms45Derivation {
            cosigner: 0x8000_0000,
            chain: 0,
            index: 0,
        },
        Ms45Derivation {
            cosigner: 0,
            chain: 0,
            index: 0x8000_0000,
        },
    ] {
        let mut source = EncoderBoundarySource::new();
        source.ms45 = Some(ms45);
        assert_eq!(encode_vec(&source), Err(WireError::InvalidTrailer));
    }
}

#[test]
fn canonical_wire_predicate_boundaries_are_characterized() {
    for sighash in [0x01, 0x02, 0x04, 0x81, 0x82, 0x84] {
        assert!(valid_sighash(sighash));
    }
    for sighash in [0x00, 0x03, 0x80, 0xff] {
        assert!(!valid_sighash(sighash));
    }

    assert!(!valid_network(0));
    assert!(valid_network(1));
    assert!(valid_network(4));
    assert!(!valid_network(5));

    assert!(valid_derivation(Derivation {
        branch: 0,
        index: 0
    }));
    assert!(valid_derivation(Derivation {
        branch: 1,
        index: 0x7fff_ffff
    }));
    assert!(!valid_derivation(Derivation {
        branch: 2,
        index: 0
    }));
    assert!(!valid_derivation(Derivation {
        branch: 0,
        index: 0x8000_0000
    }));

    assert!(valid_ms45(Ms45Derivation {
        cosigner: 0,
        chain: 0,
        index: 0
    }));
    assert!(!valid_ms45(Ms45Derivation {
        cosigner: 0,
        chain: 2,
        index: 0
    }));
    assert!(!valid_ms45(Ms45Derivation {
        cosigner: 0x8000_0000,
        chain: 0,
        index: 0
    }));
    assert!(!valid_ms45(Ms45Derivation {
        cosigner: 0,
        chain: 0,
        index: 0x8000_0000
    }));
}

#[test]
fn canonical_encode_vec_retries_large_valid_redeem_and_validate_reports_wire_errors() {
    let mut source = EncoderBoundarySource::new();
    source.redeem = vec![0x51; 5_000];
    let wire = encode_vec(&source).expect("heap encoder grows for large valid redeem");
    assert_eq!(
        validate(&wire),
        Ok(DecodedEnvelope {
            flags: FLAG_SIGNED_OR_COMPLETE
        })
    );

    let mut invalid = wire;
    invalid[0] ^= 0x01;
    assert_eq!(validate(&invalid), Err(WireError::InvalidMagic));
}

#[test]
fn canonical_encoder_rejects_input_trailer_positions_above_u8_range() {
    struct WideInputSource(EncoderBoundarySource);

    impl EncodeSource for WideInputSource {
        fn global(&self) -> Global<'_> {
            let mut global = self.0.global();
            global.input_count = 257;
            global.output_count = 0;
            global
        }
        fn input(&self, index: usize) -> Input<'_> {
            self.0.input(index)
        }
        fn signature_count(&self, _input: usize) -> usize {
            0
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
        fn input_derivation(&self, index: usize) -> Option<Derivation> {
            (index == 256).then_some(Derivation {
                branch: 0,
                index: 0,
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

    assert_eq!(
        encode_vec(&WideInputSource(EncoderBoundarySource::new())),
        Err(WireError::CountOverflow),
    );
}
