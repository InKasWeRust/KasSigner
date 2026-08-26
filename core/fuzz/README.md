# kassigner-core fuzzing

Two layers over the same target bodies (`core/src/fuzz_api.rs`, one
function per parser, each total over arbitrary input and asserting the
bounds a successful parse guarantees the firmware):

1. **`cargo test` smoke loop**, `core/src/fuzz_smoke.rs`. Runs on stable,
   everywhere, in about a second: seeds minted by the crate's own
   serializers, structural edge cases, and a fixed 3000-step mutation
   schedule per target. This is what CI runs on every push.
2. **cargo-fuzz / libFuzzer**, this directory. Coverage-guided, needs
   nightly and `cargo install cargo-fuzz`.

## Targets

| target | entry points |
|---|---|
| `kspt_parse` | `wallet::pskt::parse_pskt` (KSPT v1/v4), then `fee`, `analyze_input_script`, `signature_status` |
| `pskt_parse` | `wallet::std_pskt::parse_pskt` (PSKB / PSKT hex-JSON), region offsets, `detect_tx_format`, `pskt_signature_status` |
| `hex_decode` | `wallet::std_pskt::hex_decode_strict` |
| `kpub_import` | `wallet::xpub::{import_kpub_any, parse_kpub_parts_any, import_kpub, parse_kpub_parts}` |
| `xprv_import` | `wallet::xpub::import_xprv` |
| `address_validate` | `wallet::address::validate_kaspa_address` |
| `script_parse` | `wallet::transaction::{detect_script_type, parse_multisig_script}` |
| `payload_classify` | `qr::payload::classify` |
| `mnemonic_validate` | `wallet::bip39::{validate_mnemonic_12, validate_mnemonic_24, word_to_index}` |

## Running

From `core/`:

    cargo +nightly fuzz list
    (cd fuzz && cargo run --bin seed_corpus)      # once, writes fuzz/corpus/<target>/
    cargo +nightly fuzz run kspt_parse -- -max_len=8192
    cargo +nightly fuzz run pskt_parse -- -max_len=16384

A crash lands in `fuzz/artifacts/<target>/`; reproduce with
`cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<file>`, and add
the input to `fuzz_smoke.rs`'s structural set once fixed so the regression
runs under plain `cargo test` forever after.

`fuzz/corpus/` and `fuzz/artifacts/` are generated and not committed.
