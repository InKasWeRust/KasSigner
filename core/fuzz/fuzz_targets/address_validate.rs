// KasSigner — Air-gapped offline signing device for Kaspa
// License: GPL-3.0
//
// Target body lives in core/src/fuzz_api.rs so the host smoke loop and
// libFuzzer drive identical code.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    kassigner_core::fuzz_api::address_validate(data);
});
