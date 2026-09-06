use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SinkStep {
    Global,
    Input,
    Signature,
    Redeem,
    Output,
    Network,
    Stealth,
    InputDerivation,
    OutputDerivation,
    InputMs45,
    OutputMs45,
    Covenant,
}

struct FailingSink {
    fail_at: SinkStep,
}

impl FailingSink {
    fn check(&self, step: SinkStep) -> Result<(), SinkStep> {
        if self.fail_at == step {
            Err(step)
        } else {
            Ok(())
        }
    }
}

impl DecodeSink for FailingSink {
    type Error = SinkStep;

    fn global(&mut self, _value: Global<'_>) -> Result<(), Self::Error> {
        self.check(SinkStep::Global)
    }

    fn input(
        &mut self,
        _index: u32,
        _value: Input<'_>,
        _signature_count: u8,
    ) -> Result<(), Self::Error> {
        self.check(SinkStep::Input)
    }

    fn signature(&mut self, _input: u32, _slot: u8, _value: Signature) -> Result<(), Self::Error> {
        self.check(SinkStep::Signature)
    }

    fn redeem(&mut self, _input: u32, _value: &[u8]) -> Result<(), Self::Error> {
        self.check(SinkStep::Redeem)
    }

    fn output(&mut self, _index: u8, _value: Output<'_>) -> Result<(), Self::Error> {
        self.check(SinkStep::Output)
    }

    fn network(&mut self, _code: u8) -> Result<(), Self::Error> {
        self.check(SinkStep::Network)
    }

    fn stealth(&mut self, _tweak: [u8; 32]) -> Result<(), Self::Error> {
        self.check(SinkStep::Stealth)
    }

    fn input_derivation(&mut self, _input: u8, _value: Derivation) -> Result<(), Self::Error> {
        self.check(SinkStep::InputDerivation)
    }

    fn output_derivation(&mut self, _output: u8, _value: Derivation) -> Result<(), Self::Error> {
        self.check(SinkStep::OutputDerivation)
    }

    fn input_ms45(&mut self, _input: u8, _value: Ms45Derivation) -> Result<(), Self::Error> {
        self.check(SinkStep::InputMs45)
    }

    fn output_ms45(&mut self, _output: u8, _value: Ms45Derivation) -> Result<(), Self::Error> {
        self.check(SinkStep::OutputMs45)
    }

    fn covenant(
        &mut self,
        _output: u8,
        _authorizing_input: u16,
        _id: [u8; 32],
    ) -> Result<(), Self::Error> {
        self.check(SinkStep::Covenant)
    }
}

#[test]
fn canonical_decoder_propagates_every_sink_boundary() {
    let wire = encode_vec(&VectorSource {
        output_script: vec![0x51],
        full_trailers: true,
    })
    .expect("canonical full-trailer vector");
    for step in [
        SinkStep::Global,
        SinkStep::Input,
        SinkStep::Signature,
        SinkStep::Redeem,
        SinkStep::Output,
        SinkStep::Network,
        SinkStep::InputMs45,
        SinkStep::OutputMs45,
        SinkStep::Stealth,
        SinkStep::Covenant,
        SinkStep::InputDerivation,
        SinkStep::OutputDerivation,
    ] {
        let mut sink = FailingSink { fail_at: step };
        assert_eq!(
            decode(&wire, &mut sink),
            Err(DecodeError::Sink(step)),
            "{step:?}"
        );
    }
}
