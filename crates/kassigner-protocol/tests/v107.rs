// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! The v1.0.7 corpus (`spec/vectors/v107`, made as its `MANIFEST.md` says):
//! kassigner.org 1.0.7's requests and a v1.0.7 unit's replies. Each is held
//! to what 1.0.7's own parsers and `calculate_sighash` read in it: two
//! implementations agreeing on bytes neither wrote are unlikely to share a
//! mistake.
//!
//! A unit's `0x01` reply has no reader in 1.0.7's core; its transaction is
//! held to the request's, and its signatures checked under this crate's
//! hash.

use kassigner_kaspa::bip340;
use kassigner_kaspa::pskb::{self, transaction as pskb_tx};
use kassigner_kaspa::sighash::{schnorr_signature_hash, SIG_HASH_ALL};
use kassigner_kaspa::tx::{
    Outpoint, ScriptPublicKey, Transaction, TransactionInput, TransactionOutput, UtxoEntry,
};
use kassigner_protocol::bundle;
use kassigner_protocol::kspt::{self, legacy, Kspt, Shape};
use kassigner_protocol::profile::Profile;

const P: Profile = Profile::ESP32S3;

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::unhex;
#[path = "../../../testkit/v107.rs"]
pub mod v107;
use v107::{cosigner_key, redeem_keys};

/// A corpus file, built into the test.
macro_rules! corpus {
    ($path:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../spec/vectors/v107/",
            $path
        ))
    };
}

/// What 1.0.7 reads in one input.
struct In {
    amount: u64,
    /// The first four bytes of the previous transaction's id, and the index.
    outpoint: (&'static str, u32),
    sig_ops: u8,
    script: &'static str,
    /// The redeem script's length.
    redeem: usize,
    /// `calculate_sighash(tx, i, All)`, 1.0.7's.
    sighash: &'static str,
}

/// What 1.0.7 reads in one output; a binding as authorizing input and id.
struct Out {
    value: u64,
    script: &'static str,
    covenant: Option<(u16, &'static str)>,
}

struct Expect {
    file: &'static str,
    bytes: &'static [u8],
    /// How the device reads a KSPT payload's body; `None` for a bundle.
    shape: Option<Shape>,
    tx_version: u16,
    inputs: &'static [In],
    outputs: &'static [Out],
}

const BLANK_IN: TransactionInput<'static> = TransactionInput {
    previous_outpoint: Outpoint {
        transaction_id: [0u8; 32],
        index: 0,
    },
    sequence: 0,
    sig_op_count: 0,
    compute_budget: 0,
    signature_script: &[],
    utxo_entry: UtxoEntry {
        amount: 0,
        script_public_key: ScriptPublicKey {
            version: 0,
            script: &[],
        },
    },
};

const BLANK_OUT: TransactionOutput<'static> = TransactionOutput {
    value: 0,
    script_public_key: ScriptPublicKey {
        version: 0,
        script: &[],
    },
    covenant: None,
};

/// The transaction, held to what 1.0.7 read, with every input's hash.
fn holds(f: &str, e: &Expect, tx: &Transaction<'_>, redeem: &dyn Fn(usize) -> usize) {
    assert_eq!(tx.version, e.tx_version, "{f}: transaction version");
    assert_eq!(tx.lock_time, 0, "{f}: lock time");
    assert!(tx.payload.is_empty(), "{f}: payload");
    assert_eq!(tx.inputs.len(), e.inputs.len(), "{f}: inputs");
    assert_eq!(tx.outputs.len(), e.outputs.len(), "{f}: outputs");
    for (i, (got, want)) in tx.inputs.iter().zip(e.inputs).enumerate() {
        assert_eq!(got.utxo_entry.amount, want.amount, "{f}: input {i} amount");
        assert_eq!(
            got.previous_outpoint.transaction_id[..4],
            unhex(want.outpoint.0)[..],
            "{f}: input {i} outpoint"
        );
        assert_eq!(
            got.previous_outpoint.index, want.outpoint.1,
            "{f}: input {i} index"
        );
        assert_eq!(got.sig_op_count, want.sig_ops, "{f}: input {i} sig ops");
        assert_eq!(
            got.utxo_entry.script_public_key.version, 0,
            "{f}: input {i}"
        );
        assert_eq!(
            got.utxo_entry.script_public_key.script,
            &unhex(want.script)[..],
            "{f}: input {i} script"
        );
        assert_eq!(redeem(i), want.redeem, "{f}: input {i} redeem script");
        assert_eq!(
            schnorr_signature_hash(tx, i, SIG_HASH_ALL).expect("an input")[..],
            unhex(want.sighash)[..],
            "{f}: input {i}: this crate's signature hash is not 1.0.7's"
        );
    }
    for (o, (got, want)) in tx.outputs.iter().zip(e.outputs).enumerate() {
        assert_eq!(got.value, want.value, "{f}: output {o} value");
        assert_eq!(got.script_public_key.version, 0, "{f}: output {o}");
        assert_eq!(
            got.script_public_key.script,
            &unhex(want.script)[..],
            "{f}: output {o} script"
        );
        let cov = got
            .covenant
            .map(|c| (c.authorizing_input, c.covenant_id.to_vec()));
        let want_cov = want.covenant.map(|(a, id)| (a, unhex(id)));
        assert_eq!(cov, want_cov, "{f}: output {o} covenant binding");
    }
}

/// A KSPT payload read as the device reads one, its transaction held to
/// `e`; `more` checks what was read.
fn read_kspt(name: &str, e: &Expect, bytes: &[u8], more: impl FnOnce(&Kspt<'_>, &Transaction<'_>)) {
    let k = legacy::parse_any(bytes, &P).unwrap_or_else(|err| panic!("{name}: {err:?}"));
    let mut inputs = vec![BLANK_IN; k.num_inputs];
    let mut outputs = vec![BLANK_OUT; k.num_outputs];
    let (ni, no) = kspt::transaction::fill(&k, &mut inputs, &mut outputs)
        .unwrap_or_else(|err| panic!("{name}: {err:?}"));
    let tx = kspt::transaction::build(&k, &inputs[..ni], &outputs[..no]);
    let redeems: Vec<usize> = k.inputs().map(|i| i.redeem.len()).collect();
    holds(name, e, &tx, &|i| redeems[i]);
    more(&k, &tx);
}

/// A bundle read as the device reads one, its transaction held to `e`.
/// Returns the document.
fn read_pskb(name: &str, e: &Expect, bytes: &[u8]) -> Vec<u8> {
    let mut doc = vec![0u8; bytes.len()];
    let n = pskb::decode_envelope(bytes, &mut doc)
        .unwrap_or_else(|err| panic!("{name}: envelope: {err:?}"));
    bundle::upstream_names(&mut doc[..n]).unwrap_or_else(|err| panic!("{name}: {err:?}"));
    let n = bundle::fill_payload(&mut doc, n).unwrap_or_else(|err| panic!("{name}: {err:?}"));
    doc.truncate(n);
    let checked = pskb::check(&doc).unwrap_or_else(|err| panic!("{name}: {err:?}"));
    let mut inputs = vec![BLANK_IN; 8];
    let mut outputs = vec![BLANK_OUT; 8];
    let mut scripts = vec![0u8; 4096];
    let filled = pskb_tx::fill(&doc, 0, &mut inputs, &mut outputs, &mut scripts)
        .unwrap_or_else(|err| panic!("{name}: {err:?}"));
    let tx = pskb_tx::build(
        &filled.header,
        &inputs[..filled.inputs],
        &outputs[..filled.outputs],
    );
    let redeems: Vec<usize> = (0..filled.inputs)
        .map(|i| {
            let mut buf = [0u8; 512];
            pskb_tx::input_extras(checked, 0, i, &mut buf)
                .unwrap_or_else(|err| panic!("{name}: input {i}: {err:?}"))
                .redeem
                .len()
        })
        .collect();
    holds(name, e, &tx, &|i| redeems[i]);
    doc
}

// ── What 1.0.7 reads in each request ─────────────────────────────────────────

const KSPT2_RELAY_COVENANT: Expect = Expect {
    file: "site/kspt2_relay_covenant.bin",
    bytes: corpus!("site/kspt2_relay_covenant.bin"),
    shape: Some(Shape::LegacyMultiSig { redeem_width: 2 }),
    tx_version: 1,
    inputs: &[In {
        amount: 500_000_000,
        outpoint: ("d2fbd02f", 0),
        sig_ops: 1,
        script: "201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058ac",
        redeem: 0,
        sighash: "596a4f447c4509651bda84f3448b4764101b0d1bb29a1c916dccd4bedf7703ff",
    }],
    outputs: &[
        Out {
            value: 200_000_000,
            script: "aa20122466a2d68275ca17d502ad7c9a7b0c768ebbe0b1dbf32abdb0f4a9c19193aa87",
            covenant: Some((
                0,
                "e7fe72ba5713b80fb507ac4a5af58e560cd529125606faa4d7bafb0bad498c94",
            )),
        },
        Out {
            value: 299_000_000,
            script: "20a0f5881ec6babe339e1439146bf32fcdb0330644033a7863b068b5e10439c23cac",
            covenant: None,
        },
    ],
};

const KSPT2_RELAY_MULTISIG: Expect = Expect {
    file: "site/kspt2_relay_multisig.bin",
    bytes: corpus!("site/kspt2_relay_multisig.bin"),
    shape: Some(Shape::LegacyMultiSig { redeem_width: 2 }),
    tx_version: 0,
    inputs: &[In {
        amount: 1_000_000_000,
        outpoint: ("ef0e28c5", 0),
        sig_ops: 3,
        script: "aa20f637dfc9c1a823ccbd04975f8ccf4d57b2155c7a578b460102c16e94f18cb21987",
        redeem: 102,
        sighash: "98434ca30fb44dd1f8015f058e9518abc236816738b05cf0bddcdf20a0ff0007",
    }],
    outputs: &[
        Out {
            value: 200_000_000,
            script: "2094f42b8818f7a515339b36990612f98a2e292a148ea3b9c16150c3627d97de08ac",
            covenant: None,
        },
        Out {
            value: 799_000_000,
            script: "aa20f13e98ad1d340b3e555a6128d23388e00630c73cb0a5fcc3e6e09e3e469d7ce587",
            covenant: None,
        },
    ],
};

const KSPT2_RELAY_MULTISIG_3IN: Expect = Expect {
    file: "site/kspt2_relay_multisig_3in.bin",
    bytes: corpus!("site/kspt2_relay_multisig_3in.bin"),
    shape: Some(Shape::LegacyMultiSig { redeem_width: 2 }),
    tx_version: 0,
    inputs: &[
        In {
            amount: 100_000_000,
            outpoint: ("e8104954", 0),
            sig_ops: 3,
            script: "aa20f69474a8f7fc6ebae64d1d293f43f99ae9324a6ce3f21aece525d75dc492c8fa87",
            redeem: 102,
            sighash: "75a78efa60573fcfc0084ff4e9a407122de4f0c46f8bd5b45fe0e809090b72eb",
        },
        In {
            amount: 100_000_000,
            outpoint: ("c640e496", 1),
            sig_ops: 3,
            script: "aa20f69474a8f7fc6ebae64d1d293f43f99ae9324a6ce3f21aece525d75dc492c8fa87",
            redeem: 102,
            sighash: "2aa884e425650f455c9787278a14f0473e0aa6e7d2a26e45e68ec122ce4321c4",
        },
        In {
            amount: 100_000_000,
            outpoint: ("edb1b18e", 2),
            sig_ops: 3,
            script: "aa20f69474a8f7fc6ebae64d1d293f43f99ae9324a6ce3f21aece525d75dc492c8fa87",
            redeem: 102,
            sighash: "73283c2a3c32b5fd2eb4f1522a88f981f25f0c9bbc4808a29393e668a6b7fea8",
        },
    ],
    outputs: &[
        Out {
            value: 250_000_000,
            script: "2094f42b8818f7a515339b36990612f98a2e292a148ea3b9c16150c3627d97de08ac",
            covenant: None,
        },
        Out {
            value: 49_000_000,
            script: "aa20f13e98ad1d340b3e555a6128d23388e00630c73cb0a5fcc3e6e09e3e469d7ce587",
            covenant: None,
        },
    ],
};

const KSPT2_RELAY_SEND: Expect = Expect {
    file: "site/kspt2_relay_send.bin",
    bytes: corpus!("site/kspt2_relay_send.bin"),
    shape: Some(Shape::LegacyMultiSig { redeem_width: 2 }),
    tx_version: 0,
    inputs: &[In {
        amount: 500_000_000,
        outpoint: ("d2fbd02f", 0),
        sig_ops: 1,
        script: "201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058ac",
        redeem: 0,
        sighash: "34f75bab8027f40e68f75b7eee169d3ad4eb490474b5bbd1b6f747c22d22e3c8",
    }],
    outputs: &[
        Out {
            value: 100_000_000,
            script: "2094f42b8818f7a515339b36990612f98a2e292a148ea3b9c16150c3627d97de08ac",
            covenant: None,
        },
        Out {
            value: 399_000_000,
            script: "20276222b7bf62ffce4482c3c40aaa25e21ef06d27cc91c217b464982d042d33feac",
            covenant: None,
        },
    ],
};

const KSPT_COMPOUND: Expect = Expect {
    file: "site/kspt_compound.bin",
    bytes: corpus!("site/kspt_compound.bin"),
    shape: Some(Shape::LegacyUnsigned {
        has_redeem: false,
        has_covenant: false,
    }),
    tx_version: 0,
    inputs: &[In {
        amount: 500_000_000,
        outpoint: ("d2fbd02f", 0),
        sig_ops: 1,
        script: "201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058ac",
        redeem: 0,
        sighash: "82800b73c3c31f3844064bb2c6efc1284afa70500c03dd33c9cb11b323515fcb",
    }],
    outputs: &[
        Out {
            value: 100_000_000,
            script: "2094f42b8818f7a515339b36990612f98a2e292a148ea3b9c16150c3627d97de08ac",
            covenant: None,
        },
        Out {
            value: 200_000_000,
            script: "20434c54e1a8c8bab3d3e25b5af1a96b5132916a6b7b87c2da754211f6463a5728ac",
            covenant: None,
        },
        Out {
            value: 50_000_000,
            script: "204f2e4efeec55d8faaeb5fc41f70597fc68c135bfe81744ccfb2c126f8b5c5bc8ac",
            covenant: None,
        },
        Out {
            value: 149_000_000,
            script: "20276222b7bf62ffce4482c3c40aaa25e21ef06d27cc91c217b464982d042d33feac",
            covenant: None,
        },
    ],
};

const KSPT_CONSOLIDATE: Expect = Expect {
    file: "site/kspt_consolidate.bin",
    bytes: corpus!("site/kspt_consolidate.bin"),
    shape: Some(Shape::LegacyUnsigned {
        has_redeem: false,
        has_covenant: false,
    }),
    tx_version: 0,
    inputs: &[
        In {
            amount: 500_000_000,
            outpoint: ("d2fbd02f", 0),
            sig_ops: 1,
            script: "201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058ac",
            redeem: 0,
            sighash: "137745c88d97f1c4b446dab1942f34e1f97ac8b6de83083a4cb4160f7d10abcb",
        },
        In {
            amount: 300_000_000,
            outpoint: ("c0217b78", 1),
            sig_ops: 1,
            script: "207437b4e724aa9e8bf27d3cec468aad249440fe99653d4fb74a14a894ba6a7966ac",
            redeem: 0,
            sighash: "bdc73db63483778e73ff0728c70bd449ed6736cdb44c7e37d4084da038b226e5",
        },
        In {
            amount: 150_000_000,
            outpoint: ("f111e8d4", 0),
            sig_ops: 1,
            script: "20276222b7bf62ffce4482c3c40aaa25e21ef06d27cc91c217b464982d042d33feac",
            redeem: 0,
            sighash: "8faa7d63b82a6f1ddefbd3d76a035553c52894137d5c0d114561fefae0e4f955",
        },
    ],
    outputs: &[Out {
        value: 949_000_000,
        script: "201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058ac",
        covenant: None,
    }],
};

const KSPT_MULTISIG: Expect = Expect {
    file: "site/kspt_multisig.bin",
    bytes: corpus!("site/kspt_multisig.bin"),
    shape: Some(Shape::LegacyUnsigned {
        has_redeem: true,
        has_covenant: false,
    }),
    tx_version: 0,
    inputs: &[In {
        amount: 1_000_000_000,
        outpoint: ("ef0e28c5", 0),
        sig_ops: 3,
        script: "aa20f637dfc9c1a823ccbd04975f8ccf4d57b2155c7a578b460102c16e94f18cb21987",
        redeem: 102,
        sighash: "98434ca30fb44dd1f8015f058e9518abc236816738b05cf0bddcdf20a0ff0007",
    }],
    outputs: &[
        Out {
            value: 200_000_000,
            script: "2094f42b8818f7a515339b36990612f98a2e292a148ea3b9c16150c3627d97de08ac",
            covenant: None,
        },
        Out {
            value: 799_000_000,
            script: "aa20f13e98ad1d340b3e555a6128d23388e00630c73cb0a5fcc3e6e09e3e469d7ce587",
            covenant: None,
        },
    ],
};

const KSPT_SEND_1IN: Expect = Expect {
    file: "site/kspt_send_1in.bin",
    bytes: corpus!("site/kspt_send_1in.bin"),
    shape: Some(Shape::LegacyUnsigned {
        has_redeem: false,
        has_covenant: false,
    }),
    tx_version: 0,
    inputs: &[In {
        amount: 500_000_000,
        outpoint: ("d2fbd02f", 0),
        sig_ops: 1,
        script: "201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058ac",
        redeem: 0,
        sighash: "34f75bab8027f40e68f75b7eee169d3ad4eb490474b5bbd1b6f747c22d22e3c8",
    }],
    outputs: &[
        Out {
            value: 100_000_000,
            script: "2094f42b8818f7a515339b36990612f98a2e292a148ea3b9c16150c3627d97de08ac",
            covenant: None,
        },
        Out {
            value: 399_000_000,
            script: "20276222b7bf62ffce4482c3c40aaa25e21ef06d27cc91c217b464982d042d33feac",
            covenant: None,
        },
    ],
};

const KSPT_SEND_3IN: Expect = Expect {
    file: "site/kspt_send_3in.bin",
    bytes: corpus!("site/kspt_send_3in.bin"),
    shape: Some(Shape::LegacyUnsigned {
        has_redeem: false,
        has_covenant: false,
    }),
    tx_version: 0,
    inputs: &[
        In {
            amount: 500_000_000,
            outpoint: ("d2fbd02f", 0),
            sig_ops: 1,
            script: "201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058ac",
            redeem: 0,
            sighash: "955318500749f9c2ec1242c8c52b770d90123773c5aa55f7965ef33396f72b45",
        },
        In {
            amount: 300_000_000,
            outpoint: ("c0217b78", 1),
            sig_ops: 1,
            script: "207437b4e724aa9e8bf27d3cec468aad249440fe99653d4fb74a14a894ba6a7966ac",
            redeem: 0,
            sighash: "404a0af9c75ef50deed98b010108b3c23cef9cd516ab229f01c5c5b68c6fb53a",
        },
        In {
            amount: 150_000_000,
            outpoint: ("f111e8d4", 0),
            sig_ops: 1,
            script: "20276222b7bf62ffce4482c3c40aaa25e21ef06d27cc91c217b464982d042d33feac",
            redeem: 0,
            sighash: "8090194850293a7ec560e29b66cfb8befb37038b10025992631c232cfa60828a",
        },
    ],
    outputs: &[
        Out {
            value: 800_000_000,
            script: "2094f42b8818f7a515339b36990612f98a2e292a148ea3b9c16150c3627d97de08ac",
            covenant: None,
        },
        Out {
            value: 149_000_000,
            script: "20276222b7bf62ffce4482c3c40aaa25e21ef06d27cc91c217b464982d042d33feac",
            covenant: None,
        },
    ],
};

const PSKB_COMPOUND: Expect = Expect {
    file: "site/pskb_compound.bin",
    bytes: corpus!("site/pskb_compound.bin"),
    shape: None,
    tx_version: 0,
    inputs: &[In {
        amount: 500_000_000,
        outpoint: ("d2fbd02f", 0),
        sig_ops: 1,
        script: "201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058ac",
        redeem: 0,
        sighash: "82800b73c3c31f3844064bb2c6efc1284afa70500c03dd33c9cb11b323515fcb",
    }],
    outputs: &[
        Out {
            value: 100_000_000,
            script: "2094f42b8818f7a515339b36990612f98a2e292a148ea3b9c16150c3627d97de08ac",
            covenant: None,
        },
        Out {
            value: 200_000_000,
            script: "20434c54e1a8c8bab3d3e25b5af1a96b5132916a6b7b87c2da754211f6463a5728ac",
            covenant: None,
        },
        Out {
            value: 50_000_000,
            script: "204f2e4efeec55d8faaeb5fc41f70597fc68c135bfe81744ccfb2c126f8b5c5bc8ac",
            covenant: None,
        },
        Out {
            value: 149_000_000,
            script: "20276222b7bf62ffce4482c3c40aaa25e21ef06d27cc91c217b464982d042d33feac",
            covenant: None,
        },
    ],
};

const PSKB_COVENANT_GENESIS: Expect = Expect {
    file: "site/pskb_covenant_genesis.bin",
    bytes: corpus!("site/pskb_covenant_genesis.bin"),
    shape: None,
    tx_version: 1,
    inputs: &[In {
        amount: 500_000_000,
        outpoint: ("d2fbd02f", 0),
        sig_ops: 1,
        script: "201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058ac",
        redeem: 0,
        sighash: "596a4f447c4509651bda84f3448b4764101b0d1bb29a1c916dccd4bedf7703ff",
    }],
    outputs: &[
        Out {
            value: 200_000_000,
            script: "aa20122466a2d68275ca17d502ad7c9a7b0c768ebbe0b1dbf32abdb0f4a9c19193aa87",
            covenant: Some((
                0,
                "e7fe72ba5713b80fb507ac4a5af58e560cd529125606faa4d7bafb0bad498c94",
            )),
        },
        Out {
            value: 299_000_000,
            script: "20a0f5881ec6babe339e1439146bf32fcdb0330644033a7863b068b5e10439c23cac",
            covenant: None,
        },
    ],
};

const PSKB_MULTISIG: Expect = Expect {
    file: "site/pskb_multisig.bin",
    bytes: corpus!("site/pskb_multisig.bin"),
    shape: None,
    tx_version: 0,
    inputs: &[In {
        amount: 1_000_000_000,
        outpoint: ("ef0e28c5", 0),
        sig_ops: 3,
        script: "aa20f637dfc9c1a823ccbd04975f8ccf4d57b2155c7a578b460102c16e94f18cb21987",
        redeem: 102,
        sighash: "98434ca30fb44dd1f8015f058e9518abc236816738b05cf0bddcdf20a0ff0007",
    }],
    outputs: &[
        Out {
            value: 200_000_000,
            script: "2094f42b8818f7a515339b36990612f98a2e292a148ea3b9c16150c3627d97de08ac",
            covenant: None,
        },
        Out {
            value: 799_000_000,
            script: "aa20f13e98ad1d340b3e555a6128d23388e00630c73cb0a5fcc3e6e09e3e469d7ce587",
            covenant: None,
        },
    ],
};

const PSKB_MULTISIG_3IN: Expect = Expect {
    file: "site/pskb_multisig_3in.bin",
    bytes: corpus!("site/pskb_multisig_3in.bin"),
    shape: None,
    tx_version: 0,
    inputs: &[
        In {
            amount: 100_000_000,
            outpoint: ("e8104954", 0),
            sig_ops: 3,
            script: "aa20f69474a8f7fc6ebae64d1d293f43f99ae9324a6ce3f21aece525d75dc492c8fa87",
            redeem: 102,
            sighash: "75a78efa60573fcfc0084ff4e9a407122de4f0c46f8bd5b45fe0e809090b72eb",
        },
        In {
            amount: 100_000_000,
            outpoint: ("c640e496", 1),
            sig_ops: 3,
            script: "aa20f69474a8f7fc6ebae64d1d293f43f99ae9324a6ce3f21aece525d75dc492c8fa87",
            redeem: 102,
            sighash: "2aa884e425650f455c9787278a14f0473e0aa6e7d2a26e45e68ec122ce4321c4",
        },
        In {
            amount: 100_000_000,
            outpoint: ("edb1b18e", 2),
            sig_ops: 3,
            script: "aa20f69474a8f7fc6ebae64d1d293f43f99ae9324a6ce3f21aece525d75dc492c8fa87",
            redeem: 102,
            sighash: "73283c2a3c32b5fd2eb4f1522a88f981f25f0c9bbc4808a29393e668a6b7fea8",
        },
    ],
    outputs: &[
        Out {
            value: 250_000_000,
            script: "2094f42b8818f7a515339b36990612f98a2e292a148ea3b9c16150c3627d97de08ac",
            covenant: None,
        },
        Out {
            value: 49_000_000,
            script: "aa20f13e98ad1d340b3e555a6128d23388e00630c73cb0a5fcc3e6e09e3e469d7ce587",
            covenant: None,
        },
    ],
};

const PSKB_SEND: Expect = Expect {
    file: "site/pskb_send.bin",
    bytes: corpus!("site/pskb_send.bin"),
    shape: None,
    tx_version: 0,
    inputs: &[In {
        amount: 500_000_000,
        outpoint: ("d2fbd02f", 0),
        sig_ops: 1,
        script: "201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058ac",
        redeem: 0,
        sighash: "34f75bab8027f40e68f75b7eee169d3ad4eb490474b5bbd1b6f747c22d22e3c8",
    }],
    outputs: &[
        Out {
            value: 100_000_000,
            script: "2094f42b8818f7a515339b36990612f98a2e292a148ea3b9c16150c3627d97de08ac",
            covenant: None,
        },
        Out {
            value: 399_000_000,
            script: "20276222b7bf62ffce4482c3c40aaa25e21ef06d27cc91c217b464982d042d33feac",
            covenant: None,
        },
    ],
};

const PSKB_SEND_UTXOS: Expect = Expect {
    file: "site/pskb_send_utxos.bin",
    bytes: corpus!("site/pskb_send_utxos.bin"),
    shape: None,
    tx_version: 0,
    inputs: &[
        In {
            amount: 500_000_000,
            outpoint: ("d2fbd02f", 0),
            sig_ops: 1,
            script: "201bacea84ca721c95d67ecace19bc499a77c03726bc8739af637bcd89abaaf058ac",
            redeem: 0,
            sighash: "d3891f8f80e0d5401d14296583abeba8a2b21b75d40fc93b5ab286bcc2b15bde",
        },
        In {
            amount: 300_000_000,
            outpoint: ("c0217b78", 1),
            sig_ops: 1,
            script: "207437b4e724aa9e8bf27d3cec468aad249440fe99653d4fb74a14a894ba6a7966ac",
            redeem: 0,
            sighash: "294e8f1f438c7f50c8c14cf33044210b410cb35a2d1cee266753db3ce11e974d",
        },
    ],
    outputs: &[
        Out {
            value: 600_000_000,
            script: "2094f42b8818f7a515339b36990612f98a2e292a148ea3b9c16150c3627d97de08ac",
            covenant: None,
        },
        Out {
            value: 199_000_000,
            script: "20276222b7bf62ffce4482c3c40aaa25e21ef06d27cc91c217b464982d042d33feac",
            covenant: None,
        },
    ],
};

// ── The tests ───────────────────────────────────────────────────────────────

/// kassigner.org 1.0.7's KSPT requests: `0x01` unsigned, with and without a
/// redeem script, `0x03` and `0x05` relays.
const KSPT_REQUESTS: [&Expect; 9] = [
    &KSPT_SEND_1IN,
    &KSPT_SEND_3IN,
    &KSPT_COMPOUND,
    &KSPT_CONSOLIDATE,
    &KSPT_MULTISIG,
    &KSPT2_RELAY_SEND,
    &KSPT2_RELAY_MULTISIG,
    &KSPT2_RELAY_MULTISIG_3IN,
    &KSPT2_RELAY_COVENANT,
];

/// kassigner.org 1.0.7's bundles: single signature, compound, from given
/// UTXOs, 2-of-3 with one and three inputs, and a covenant genesis under its
/// `covenantBinding`.
const PSKB_REQUESTS: [&Expect; 6] = [
    &PSKB_SEND,
    &PSKB_SEND_UTXOS,
    &PSKB_COMPOUND,
    &PSKB_MULTISIG,
    &PSKB_MULTISIG_3IN,
    &PSKB_COVENANT_GENESIS,
];

#[test]
fn every_kassigner_org_kspt_request_reads_as_1_0_7_reads_it() {
    for e in KSPT_REQUESTS {
        read_kspt(e.file, e, e.bytes, |k, _| {
            assert_eq!(Some(k.shape()), e.shape, "{}: body shape", e.file);
        });
    }
}

#[test]
fn every_kassigner_org_bundle_reads_as_1_0_7_reads_it() {
    for e in PSKB_REQUESTS {
        read_pskb(e.file, e, e.bytes);
    }
}

/// The x-only key a pay-to-public-key script names.
fn key_of(script: &[u8]) -> [u8; 32] {
    assert_eq!((script.len(), script[0], script[33]), (34, 0x20, 0xac));
    script[1..33].try_into().unwrap()
}

/// A unit's KSPT reply: the request's transaction, every input signed once,
/// `SIGHASH_ALL`, by the key its script names, under this crate's hash.
#[test]
fn every_kspt_reply_of_a_1_0_7_unit_carries_the_request_and_verifies() {
    let replies: [(&str, &[u8], &Expect); 3] = [
        (
            "device/kspt_send_1in.reply.bin",
            corpus!("device/kspt_send_1in.reply.bin"),
            &KSPT_SEND_1IN,
        ),
        (
            "device/kspt_send_3in.reply.bin",
            corpus!("device/kspt_send_3in.reply.bin"),
            &KSPT_SEND_3IN,
        ),
        (
            "device/kspt_consolidate.reply.bin",
            corpus!("device/kspt_consolidate.reply.bin"),
            &KSPT_CONSOLIDATE,
        ),
    ];
    for (name, bytes, request) in replies {
        assert_eq!(&bytes[..6], b"KSPT\x01\x01", "{name}: signed, version 0x01");
        read_kspt(name, request, bytes, |k, tx| {
            assert_eq!(
                k.shape(),
                Shape::LegacySingleSig {
                    has_covenant: false
                },
                "{name}"
            );
            for (i, input) in k.inputs().enumerate() {
                let sigs: Vec<_> = input.signatures().collect();
                assert_eq!(sigs.len(), 1, "{name}: input {i}");
                let sig = sigs[0];
                assert_eq!(sig.sighash_type, SIG_HASH_ALL.to_u8(), "{name}: input {i}");
                let bytes: &[u8; 64] = sig.bytes.try_into().expect("64 bytes");
                let key = key_of(tx.inputs[i].utxo_entry.script_public_key.script);
                let digest = schnorr_signature_hash(tx, i, SIG_HASH_ALL).expect("an input");
                assert!(
                    bip340::verify(&key, &digest, bytes),
                    "{name}: input {i}: 1.0.7's signature does not verify here"
                );
            }
        });
    }
}

/// A unit's bundle reply: the request's transaction, and the input's key
/// among those that signed it.
#[test]
fn every_bundle_reply_of_a_1_0_7_unit_carries_the_request() {
    let replies: [(&str, &[u8], &Expect); 4] = [
        (
            "device/pskb_send.reply.bin",
            corpus!("device/pskb_send.reply.bin"),
            &PSKB_SEND,
        ),
        (
            "device/pskb_send_utxos.reply.bin",
            corpus!("device/pskb_send_utxos.reply.bin"),
            &PSKB_SEND_UTXOS,
        ),
        (
            "device/pskb_compound.reply.bin",
            corpus!("device/pskb_compound.reply.bin"),
            &PSKB_COMPOUND,
        ),
        (
            "device/pskb_covenant_genesis.reply.bin",
            corpus!("device/pskb_covenant_genesis.reply.bin"),
            &PSKB_COVENANT_GENESIS,
        ),
    ];
    for (name, bytes, request) in replies {
        let doc = read_pskb(name, request, bytes);
        let checked = pskb::check(&doc).expect("checked");
        for (i, input) in request.inputs.iter().enumerate() {
            let key = key_of(&unhex(input.script));
            let mut signed = false;
            pskb::signature::signers(checked, 0, i, |k| {
                signed |= k[1..] == key;
                true
            })
            .unwrap_or_else(|err| panic!("{name}: input {i}: {err:?}"));
            assert!(signed, "{name}: input {i}: the wallet's key did not sign");
        }
    }
}

// ── The 2-of-3's replies ────────────────────────────────────────────────────

/// The cosigner kpubs, `m/45'/111111'/0'`, as v1.0.7 exported them.
const ABANDON12_KPUB45: &str = "kpub2JKepGqGb3usUsEfD7JgwbFZav8Nu2z4dBZQ42hg8JUGnCbLUb9phbpZW2TQuk2DmayefGMiVzCK7EL9hPbr2K2vVzSk8SpuUwwqTLq8y14";
const ABANDON24_KPUB45: &str = "kpub2JG8myov28wfetFRquaJtuTJpL3jhYnBhu2V6ZuwHnDqPBAoyqgJKkQiba4wLfU9JcsNBBoBTm7zPtk1Nv4Nn36tUkoZWGUXjWn1aJCajdW";
const ZOO12_KPUB45: &str = "kpub2HgQUMVzkWe8YCDJDEg5zdMAiKnFE3inHgrv7VRUCxKanfXpGnPpSut8MQUHYBcSFKxDhNJKCFJTy6BSdUhXKd1VbrFdFRrJ2thq3ZJfPUU";

/// The 2-of-3 made a group here is v1.0.7's: at each input's hinted
/// cosigner, chain and index, its redeem script is the request's. Sorted,
/// zoo 12 is first, abandon 24 second and abandon 12 third, where a v1.0.7
/// reply puts their signatures. Cosigner 0 in the hints is the branch spent,
/// zoo 12's.
#[test]
fn the_2_of_3_made_a_group_is_1_0_7s() {
    use kassigner_kaspa::bip32_public::ExtendedPublicKey;
    use kassigner_protocol::group::{Group, MAX_REDEEM};
    use kassigner_protocol::kspt::Record;
    let key = |t: &str| ExtendedPublicKey::from_text(t.as_bytes()).expect("kpub").1;
    let group = Group::<5>::new(
        2,
        &[
            key(ZOO12_KPUB45),
            key(ABANDON24_KPUB45),
            key(ABANDON12_KPUB45),
        ],
    )
    .expect("group");
    assert_eq!(group.position(&key(ZOO12_KPUB45)), Some(0));
    assert_eq!(group.position(&key(ABANDON24_KPUB45)), Some(1));
    assert_eq!(group.position(&key(ABANDON12_KPUB45)), Some(2));
    for (name, bytes) in [
        (
            "kspt2_relay_multisig",
            &corpus!("site/kspt2_relay_multisig.bin")[..],
        ),
        (
            "kspt2_relay_multisig_3in",
            &corpus!("site/kspt2_relay_multisig_3in.bin")[..],
        ),
    ] {
        let k = legacy::parse_any(bytes, &P).expect(name);
        let mut inputs = 0;
        for (i, input) in k.inputs().enumerate() {
            let h = k
                .records()
                .find_map(|r| match r {
                    Record::InputHint(h) if usize::from(h.index) == i => Some(h),
                    _ => None,
                })
                .unwrap_or_else(|| panic!("{name}: input {i}: a hint"));
            assert_eq!(h.cosigner, 0, "{name}: the branch spent");
            let mut redeem = [0u8; MAX_REDEEM];
            let n = group
                .redeem(h.cosigner, h.chain, h.addr_index, &mut redeem)
                .expect("redeem");
            assert_eq!(&redeem[..n], input.redeem, "{name}: input {i}");
            inputs += 1;
        }
        assert!(inputs > 0, "{name}");
    }
}

/// A 2-of-3 reply: the file, the request it answers, the address index it
/// spends from, and the cosigners that must have signed it.
struct Cosigned {
    name: &'static str,
    bytes: &'static [u8],
    request: &'static Expect,
    index: u32,
    signers: &'static [&'static str],
}

/// A cosigner's reply to a `0x05` relay: the request's transaction, each of
/// `signers` signing every input at its key's place, verified under this
/// crate's hash. abandon 12 signs the relay; abandon 24 signs abandon 12's
/// reply.
#[test]
fn every_2_of_3_relay_reply_of_a_1_0_7_unit_carries_the_request_and_verifies() {
    let replies = [
        Cosigned {
            name: "device/kspt2_relay_multisig.reply.bin",
            bytes: corpus!("device/kspt2_relay_multisig.reply.bin"),
            request: &KSPT2_RELAY_MULTISIG,
            index: 0,
            signers: &[ABANDON12_KPUB45],
        },
        Cosigned {
            name: "device/kspt2_relay_multisig.reply.abandon24.bin",
            bytes: corpus!("device/kspt2_relay_multisig.reply.abandon24.bin"),
            request: &KSPT2_RELAY_MULTISIG,
            index: 0,
            signers: &[ABANDON12_KPUB45, ABANDON24_KPUB45],
        },
        Cosigned {
            name: "device/kspt2_relay_multisig_3in.reply.bin",
            bytes: corpus!("device/kspt2_relay_multisig_3in.reply.bin"),
            request: &KSPT2_RELAY_MULTISIG_3IN,
            index: 1,
            signers: &[ABANDON12_KPUB45],
        },
        Cosigned {
            name: "device/kspt2_relay_multisig_3in.reply.abandon24.bin",
            bytes: corpus!("device/kspt2_relay_multisig_3in.reply.abandon24.bin"),
            request: &KSPT2_RELAY_MULTISIG_3IN,
            index: 1,
            signers: &[ABANDON12_KPUB45, ABANDON24_KPUB45],
        },
    ];
    for Cosigned {
        name,
        bytes,
        request,
        index,
        signers,
    } in replies
    {
        assert_eq!(&bytes[..5], b"KSPT\x05", "{name}");
        read_kspt(name, request, bytes, |k, tx| {
            for (i, input) in k.inputs().enumerate() {
                let keys = redeem_keys(input.redeem);
                let digest = schnorr_signature_hash(tx, i, SIG_HASH_ALL).expect("an input");
                let mut want: Vec<usize> = signers
                    .iter()
                    .map(|kpub| {
                        let x = cosigner_key(kpub, index);
                        keys.iter()
                            .position(|k| k[..] == x[1..])
                            .unwrap_or_else(|| panic!("{name}: input {i}: not a cosigner"))
                    })
                    .collect();
                want.sort_unstable();
                let mut got = Vec::new();
                for sig in input.signatures() {
                    let at = usize::from(sig.pubkey_pos);
                    assert_eq!(sig.sighash_type, SIG_HASH_ALL.to_u8(), "{name}: input {i}");
                    let bytes: &[u8; 64] = sig.bytes.try_into().expect("64 bytes");
                    assert!(
                        bip340::verify(&keys[at], &digest, bytes),
                        "{name}: input {i}: the signature at {at} does not verify here"
                    );
                    got.push(at);
                }
                got.sort_unstable();
                assert_eq!(got, want, "{name}: input {i}: who signed");
            }
        });
    }
}

/// A cosigner's unit's reply to a 2-of-3 bundle: the request's transaction,
/// and on its input each of `signers` among those that signed.
#[test]
fn every_2_of_3_bundle_reply_of_a_1_0_7_unit_carries_the_request() {
    let replies: [(&str, &[u8], &[&str]); 2] = [
        (
            "device/pskb_multisig.reply.bin",
            corpus!("device/pskb_multisig.reply.bin"),
            &[ABANDON12_KPUB45],
        ),
        (
            "device/pskb_multisig.reply.abandon24.bin",
            corpus!("device/pskb_multisig.reply.abandon24.bin"),
            &[ABANDON12_KPUB45, ABANDON24_KPUB45],
        ),
    ];
    for (name, bytes, signers) in replies {
        let doc = read_pskb(name, &PSKB_MULTISIG, bytes);
        let checked = pskb::check(&doc).expect("checked");
        let mut got = Vec::new();
        pskb::signature::signers(checked, 0, 0, |k| {
            got.push(k);
            true
        })
        .unwrap_or_else(|err| panic!("{name}: {err:?}"));
        let mut want: Vec<[u8; 33]> = signers.iter().map(|kpub| cosigner_key(kpub, 0)).collect();
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(got, want, "{name}: who signed");
    }
}

/// The frames of a `.frames` file: one code in hex a line.
fn frames_of(file: &[u8]) -> Vec<Vec<u8>> {
    std::str::from_utf8(file)
        .expect("hex lines")
        .split_whitespace()
        .map(unhex)
        .collect()
}

/// The reply this crate writes for a 1.0.7 wallet is the reply a 1.0.7 unit
/// wrote, byte for byte, and its codes the codes that unit showed: each
/// request of the site's, the unit's own signatures put back, against the
/// unit's reply and its codes for a wallet.
#[test]
fn a_single_key_reply_is_written_as_a_1_0_7_unit_wrote_it() {
    use kassigner_protocol::frame::v107 as frames;
    struct Round {
        name: &'static str,
        request: &'static [u8],
        reply: &'static [u8],
        shown: &'static [u8],
    }
    let rounds = [
        Round {
            name: "kspt_send_1in",
            request: corpus!("site/kspt_send_1in.bin"),
            reply: corpus!("device/kspt_send_1in.reply.bin"),
            shown: corpus!("device/kspt_send_1in.reply.fast.frames"),
        },
        Round {
            name: "kspt_send_3in",
            request: corpus!("site/kspt_send_3in.bin"),
            reply: corpus!("device/kspt_send_3in.reply.bin"),
            shown: corpus!("device/kspt_send_3in.reply.fast.frames"),
        },
        Round {
            name: "kspt_consolidate",
            request: corpus!("site/kspt_consolidate.bin"),
            reply: corpus!("device/kspt_consolidate.reply.bin"),
            shown: corpus!("device/kspt_consolidate.reply.fast.frames"),
        },
    ];
    for Round {
        name,
        request,
        reply,
        shown,
    } in rounds
    {
        let unit = legacy::parse(reply, &P).expect("the unit's reply");
        let signatures: Vec<[u8; 64]> = unit
            .inputs()
            .map(|input| {
                let sig = input.signatures().next().expect("signed");
                sig.bytes.try_into().expect("64 bytes")
            })
            .collect();

        let mut out = vec![0u8; reply.len() + 1];
        let n = legacy::write_signed(request, &P, &signatures, &mut out).expect("written");
        assert_eq!(&out[..n], reply, "{name}: the reply");
        assert_eq!(
            n,
            request.len() + signatures.len() * legacy::SIGNED_RECORD_LEN,
            "{name}"
        );

        let shown = frames_of(shown);
        assert_eq!(frames::codes(n), shown.len(), "{name}: how many codes");
        for (i, want) in shown.iter().enumerate() {
            let mut code = [0u8; frames::CODE_LEN];
            let len = frames::write(&out[..n], i, &mut code).expect("a code");
            assert_eq!(&code[..len], &want[..], "{name}: code {i}");
        }
        let mut code = [0u8; frames::CODE_LEN];
        assert_eq!(frames::write(&out[..n], shown.len(), &mut code), None);

        // One byte short, and nothing is written past what fits.
        assert_eq!(
            legacy::write_signed(request, &P, &signatures, &mut out[..n - 1]),
            Err(legacy::SignedError::TooSmall { needed: n }),
            "{name}"
        );
        // Not one signature for each input.
        assert_eq!(
            legacy::write_signed(request, &P, &signatures[1..], &mut out),
            Err(legacy::SignedError::Signatures {
                given: signatures.len() - 1,
                inputs: signatures.len(),
            }),
            "{name}"
        );
        // A reply is no request: it is signed already.
        assert_eq!(
            legacy::write_signed(reply, &P, &signatures, &mut out),
            Err(legacy::SignedError::NotSingleKey),
            "{name}"
        );
    }
}

/// Only a `0x01` single-key request has the 1.0.7 answer: a multisig
/// request, a relay with hints and a `0x06` request have none.
#[test]
fn only_a_single_key_request_has_the_1_0_7_reply() {
    let signature = [[7u8; 64]];
    let mut out = [0u8; 4096];
    for (name, request) in [
        ("kspt_multisig", &corpus!("site/kspt_multisig.bin")[..]),
        (
            "kspt2_relay_send",
            &corpus!("site/kspt2_relay_send.bin")[..],
        ),
        (
            "kspt2_relay_multisig",
            &corpus!("site/kspt2_relay_multisig.bin")[..],
        ),
    ] {
        assert_eq!(
            legacy::write_signed(request, &P, &signature, &mut out),
            Err(legacy::SignedError::NotSingleKey),
            "{name}"
        );
    }
    // A request of this version is not a legacy payload at all.
    let mut canonical = corpus!("site/kspt_send_1in.bin").to_vec();
    canonical[4] = kspt::VERSION;
    assert!(matches!(
        legacy::write_signed(&canonical, &P, &signature, &mut out),
        Err(legacy::SignedError::Request(_))
    ));
}

/// The frames past the vectors: a payload of one code goes bare, a split is
/// even with the last fragment what is left, a fragment under twenty bytes
/// is padded to twenty with its own length kept, and sixty-four frames are
/// the most.
#[test]
fn frames_for_a_1_0_7_wallet_are_split_as_it_reads_them() {
    use kassigner_protocol::frame::v107 as frames;
    let payload: Vec<u8> = (0..=255u8)
        .cycle()
        .take(64 * frames::FRAGMENT_LEN + 1)
        .collect();
    let mut code = [0u8; frames::CODE_LEN];

    assert_eq!(frames::codes(0), 0);
    assert_eq!(frames::write(&[], 0, &mut code), None);
    assert_eq!(frames::codes(frames::CODE_LEN), 1);
    let n = frames::write(&payload[..frames::CODE_LEN], 0, &mut code).expect("bare");
    assert_eq!(&code[..n], &payload[..frames::CODE_LEN]);

    // 231 bytes: two frames of 116 and 115.
    assert_eq!(frames::codes(frames::CODE_LEN + 1), 2);
    let two = &payload[..frames::CODE_LEN + 1];
    let n = frames::write(two, 0, &mut code).expect("frame 0");
    assert_eq!((&code[..3], &code[3..n]), (&[0, 2, 116][..], &two[..116]));
    let n = frames::write(two, 1, &mut code).expect("frame 1");
    assert_eq!((&code[..3], &code[3..n]), (&[1, 2, 115][..], &two[116..]));

    // 455 bytes in three frames of 152, 152 and 151; whatever the length,
    // the fragments put back in order are the payload.
    for len in [455usize, 456, 681, 682, 1000, 64 * frames::FRAGMENT_LEN] {
        let total = frames::codes(len);
        let mut back = Vec::new();
        for i in 0..total {
            let n = frames::write(&payload[..len], i, &mut code).expect("a frame");
            assert_eq!((code[0], code[1]), (i as u8, total as u8), "{len}");
            let frag = usize::from(code[2]);
            assert!(frag <= frames::FRAGMENT_LEN && n == 3 + frag.max(frames::PADDED_LEN));
            assert!(code[3 + frag..n].iter().all(|b| *b == 0), "{len}: padding");
            back.extend_from_slice(&code[3..3 + frag]);
        }
        assert_eq!(back, &payload[..len], "{len}");
    }

    // Sixty-four frames are the most.
    assert_eq!(frames::codes(64 * frames::FRAGMENT_LEN), frames::MAX_FRAMES);
    assert_eq!(frames::write(&payload, 0, &mut code), None);
}
