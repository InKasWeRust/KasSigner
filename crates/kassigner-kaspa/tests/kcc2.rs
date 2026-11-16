// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! KCC-2 against its own vectors, read whole:
//! `spec/vectors/v110/covenants/kcc2/authority-schemes.json`, unchanged.

use kassigner_kaspa::kcc::abi::Type;
use kassigner_kaspa::kcc::authority::{Authority, AuthorityError, Registered, Scheme};
use kassigner_kaspa::kcc::push::{explicit_len, minimal_len, push_explicit, push_minimal};
use kassigner_kaspa::kcc::state::state_value;
use kassigner_kaspa::kcc::value::{argument, Segment, Value as Got};
use kassigner_kaspa::kcc::{abi::Field, envelope::locking_script};
use kassigner_kaspa::script::redeem_hash;
use kassigner_kaspa::tx::ScriptPublicKey;
use serde_json::Value;

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::unhex;

const VECTORS: &str =
    include_str!("../../../spec/vectors/v110/covenants/kcc2/authority-schemes.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("KCC-2's vectors parse")
}

fn text(v: &Value) -> &str {
    v.as_str().expect("a string")
}

fn byte(v: &Value) -> u8 {
    unhex(text(v))[0]
}

/// The construction a vector names.
fn construction<'v>(v: &'v Value, id: &str) -> &'v Value {
    v["constructions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap_or_else(|| panic!("no construction {id}"))
}

/// 2.1: the five standard bytes, the reserved ones refused, the custom ones
/// told apart and not read.
#[test]
fn the_registry_is_kcc2s() {
    let v = vectors();
    let rows = v["registry_checks"].as_array().unwrap();
    assert_eq!(rows.len(), 10);
    for row in rows {
        let b = byte(&row["scheme_byte"]);
        let got = Registered::of(b);
        match (row["assigned"].as_bool(), row["custom"].as_bool()) {
            (Some(true), Some(false)) => {
                let Ok(Registered::Standard(s)) = got else {
                    panic!("{b:02x}: {got:?}");
                };
                assert_eq!(s.byte(), b);
                assert_eq!(Scheme::of(b), Ok(s));
            }
            (Some(false), Some(false)) => {
                assert_eq!(got, Err(AuthorityError::Unassigned), "{b:02x}");
                assert_eq!(Scheme::of(b), Err(AuthorityError::Unassigned), "{b:02x}");
            }
            (Some(false), Some(true)) => {
                assert_eq!(got, Ok(Registered::Custom(b)), "{b:02x}");
                assert_eq!(Scheme::of(b), Err(AuthorityError::Custom), "{b:02x}");
            }
            other => panic!("a registry row this test does not know: {other:?}"),
        }
    }
    // Every byte: five standard, 123 reserved, 128 custom.
    let standard = (0..=255u8)
        .filter(|b| matches!(Registered::of(*b), Ok(Registered::Standard(_))))
        .count();
    let reserved = (0..=255u8).filter(|b| Registered::of(*b).is_err()).count();
    assert_eq!((standard, reserved), (5, 123));
}

/// 4.1: each scheme's name, type and value, made from its key, program or
/// lineage, and pushed as an argument and a state field.
#[test]
fn authorities_are_made_as_kcc2_makes_them() {
    let v = vectors();
    let rows = v["constructions"].as_array().unwrap();
    assert_eq!(rows.len(), 5);
    for row in rows {
        let id = text(&row["id"]);
        let scheme = Scheme::of(byte(&row["scheme_byte"])).unwrap();
        assert_eq!(scheme.name(), text(&row["scheme"]), "{id}");
        let ty = scheme.value_type();
        assert_eq!(ty.type_name().to_string(), text(&row["value_type"]), "{id}");
        let value = unhex(text(&row["authority_value"]));

        let made = match scheme {
            Scheme::P2pkSchnorr | Scheme::P2pkhSchnorr | Scheme::P2pkhEcdsa => {
                Authority::of_key(scheme, &unhex(text(&row["public_key"])))
                    .unwrap()
                    .value
                    .to_vec()
            }
            Scheme::P2sh => {
                let program = unhex(text(&row["redeem_script"]));
                let spk = &row["script_public_key"];
                assert_eq!(spk["version"], 0);
                assert_eq!(
                    locking_script(&program)[..],
                    unhex(text(&spk["script"]))[..],
                    "{id}"
                );
                redeem_hash(&program).to_vec()
            }
            Scheme::CovenantId => unhex(text(&row["covenant_id"])),
        };
        assert_eq!(made, value, "{id}");

        let arg = unhex(text(&row["argument_encoding"]));
        let mut pushed = vec![0u8; minimal_len(&value)];
        push_minimal(&value, &mut pushed).unwrap();
        assert_eq!(pushed, arg, "{id}");
        let params = [ty];
        let read = argument(&params, &arg, 0, &[]).unwrap();
        assert_eq!(read, Got::Bytes(&value), "{id}");
        let authority = Authority::read(scheme.byte(), &ty, read).unwrap();
        assert_eq!(authority.value[..], value[..], "{id}");

        let state = unhex(text(&row["state_encoding"]));
        let mut pushed = vec![0u8; explicit_len(value.len())];
        push_explicit(&value, &mut pushed).unwrap();
        assert_eq!(pushed, state, "{id}");
        let fields = [Field { name: "owner", ty }];
        let read = state_value(&fields, &state, &[Segment::Field("owner")]).unwrap();
        assert_eq!(
            Authority::read(scheme.byte(), &ty, read),
            Ok(authority),
            "{id}"
        );
    }
}

/// 4.2: the minimum approval checks; a key scheme's signature validity
/// comes from the vector.
#[test]
fn approvals_are_checked_as_kcc2_checks_them() {
    let v = vectors();
    let rows = v["approval_checks"].as_array().unwrap();
    assert_eq!(rows.len(), 20);
    for row in rows {
        let id = text(&row["id"]);
        let c = construction(&v, text(&row["construction"]));
        let scheme = Scheme::of(byte(&c["scheme_byte"])).unwrap();
        let authority = Authority {
            scheme,
            value: unhex(text(&c["authority_value"])).try_into().unwrap(),
        };
        let cx = &row["context"];
        let got = match scheme {
            Scheme::P2pkSchnorr | Scheme::P2pkhSchnorr | Scheme::P2pkhEcdsa => {
                authority.names_key(&unhex(text(&cx["public_key"])))
                    && cx["signature_valid"].as_bool().unwrap()
            }
            Scheme::P2sh => {
                let scripts: Vec<(u16, Vec<u8>)> = cx["input_script_public_keys"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|s| {
                        (
                            s["version"].as_u64().unwrap() as u16,
                            unhex(text(&s["script"])),
                        )
                    })
                    .collect();
                authority.p2sh_takes_part(scripts.iter().map(|(version, script)| ScriptPublicKey {
                    version: *version,
                    script,
                }))
            }
            Scheme::CovenantId => {
                let ids: Vec<Option<[u8; 32]>> = cx["input_covenant_ids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|id| id.as_str().map(|h| unhex(h).try_into().unwrap()))
                    .collect();
                authority.covenant_takes_part(ids.iter().map(Option::as_ref))
            }
        };
        assert_eq!(got, row["expected"].as_bool().unwrap(), "{id}");
    }
}

/// What 2.1 and 2.2 also forbid: a value of another type or length, a bad
/// key, a key asked of a keyless scheme, participation under another scheme.
#[test]
fn what_kcc2_forbids_is_refused() {
    let key = [7u8; 32];
    let value = [9u8; 32];
    let byte32 = Type::Array(&Type::Byte, 32);
    // p2pk's value is a `pubkey`, not a `byte[32]`; the others the reverse.
    assert_eq!(
        Authority::read(0x00, &byte32, Got::Bytes(&value)),
        Err(AuthorityError::WrongType)
    );
    assert_eq!(
        Authority::read(0x01, &Type::Pubkey, Got::Bytes(&value)),
        Err(AuthorityError::WrongType)
    );
    assert_eq!(
        Authority::read(0x01, &byte32, Got::Int(1)),
        Err(AuthorityError::WrongType)
    );
    assert_eq!(
        Authority::read(0x01, &byte32, Got::Bytes(&value[..31])),
        Err(AuthorityError::WrongLength)
    );
    assert_eq!(
        Authority::read(0x05, &byte32, Got::Bytes(&value)),
        Err(AuthorityError::Unassigned)
    );
    assert_eq!(
        Authority::read(0x80, &byte32, Got::Bytes(&value)),
        Err(AuthorityError::Custom)
    );

    assert_eq!(
        Authority::of_key(Scheme::P2pkhSchnorr, &[2; 33]),
        Err(AuthorityError::WrongLength)
    );
    assert_eq!(
        Authority::of_key(Scheme::P2pkhEcdsa, &key),
        Err(AuthorityError::WrongLength)
    );
    // 33 bytes, but not a compressed key's first byte.
    assert_eq!(
        Authority::of_key(Scheme::P2pkhEcdsa, &[4; 33]),
        Err(AuthorityError::WrongLength)
    );
    assert!(Authority::of_key(Scheme::P2pkhEcdsa, &[3; 33]).is_ok());
    for scheme in [Scheme::P2sh, Scheme::CovenantId] {
        assert_eq!(
            Authority::of_key(scheme, &key),
            Err(AuthorityError::NotAKeyScheme)
        );
        assert!(!Authority { scheme, value }.names_key(&key));
    }

    // A key scheme's value never takes part as a program or a lineage.
    let p2pk = Authority::of_key(Scheme::P2pkSchnorr, &key).unwrap();
    let lock = locking_script(&[0x51]);
    let spk = ScriptPublicKey {
        version: 0,
        script: &lock,
    };
    assert!(!p2pk.p2sh_takes_part([spk]));
    assert!(!p2pk.covenant_takes_part([Some(&key)]));
    let p2sh = Authority {
        scheme: Scheme::P2sh,
        value: redeem_hash(&[0x51]),
    };
    assert!(p2sh.p2sh_takes_part([spk]));
    assert!(!p2sh.covenant_takes_part([Some(&p2sh.value)]));
}
