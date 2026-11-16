// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! KCC-1 against its own vectors and against SilverScript's compiler. The
//! vectors, `spec/vectors/v110/covenants/kcc1/conformance.json`, are
//! unchanged, and each group is read whole.

use kassigner_kaspa::kcc::abi::{check_entrypoints, AbiError, Entrypoint, Field, Record, Type};
use kassigner_kaspa::kcc::envelope::{
    locking_script, read, read_spend, signature_script_len, write, EnvelopeError, Invocation,
};
use kassigner_kaspa::kcc::hash::{hash, key32, keyed_hash, template_hash, KeyTooLong};
use kassigner_kaspa::kcc::push::{
    explicit_len, minimal_len, push_explicit, push_minimal, pushes, PushError,
};
use kassigner_kaspa::kcc::state::{check_state, state_value, Parts, Span};
use kassigner_kaspa::kcc::value::{
    argument, check_arguments, int_argument, int_payload, Segment, Value as Got, ValueError,
};
use kassigner_kaspa::script::redeem_hash;
use kassigner_kaspa::tx::ScriptPublicKey;
use serde_json::Value;
use silverscript_abi::{SilAbiArtifact, TypeArtifact};

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::{hex, unhex};

const CONFORMANCE: &str =
    include_str!("../../../spec/vectors/v110/covenants/kcc1/conformance.json");

fn vectors() -> Value {
    serde_json::from_str(CONFORMANCE).expect("KCC-1's conformance vectors parse")
}

fn text(v: &Value) -> &str {
    v.as_str().expect("a string")
}

fn leak<T>(t: T) -> &'static T {
    Box::leak(Box::new(t))
}

fn leak_str(s: &str) -> &'static str {
    Box::leak(s.to_owned().into_boxed_str())
}

/// A KCC-1 type name as the vectors write it (`CoffeeOrder[2]`), its record
/// names from `records`.
fn parse_type(s: &str, records: &Value) -> Type<'static> {
    if let Some(inner) = s.strip_suffix("[]") {
        return Type::Dynamic(leak(parse_type(inner, records)));
    }
    if let Some(open) = s.strip_suffix(']').and_then(|t| t.rfind('[')) {
        let n = s[open + 1..s.len() - 1].parse().expect("an array length");
        return Type::Array(leak(parse_type(&s[..open], records)), n);
    }
    match s {
        "int" => Type::Int,
        "bool" => Type::Bool,
        "byte" => Type::Byte,
        "string" => Type::String,
        "pubkey" => Type::Pubkey,
        "sig" => Type::Sig,
        "datasig" => Type::Datasig,
        name => {
            let record = records
                .as_array()
                .and_then(|all| all.iter().find(|r| text(&r["name"]) == name))
                .unwrap_or_else(|| panic!("no record {name}"));
            let fields: Vec<Field<'static>> = record["fields"]
                .as_array()
                .expect("fields")
                .iter()
                .map(|f| Field {
                    name: leak_str(text(&f["name"])),
                    ty: parse_type(text(&f["type"]), records),
                })
                .collect();
            Type::Record(leak(Record {
                name: leak_str(name),
                fields: Box::leak(fields.into_boxed_slice()),
            }))
        }
    }
}

/// An entrypoint as a vector gives it: a name, argument types, records.
fn entrypoint(name: &Value, types: &Value, records: &Value) -> Entrypoint<'static> {
    let params: Vec<Type<'static>> = types
        .as_array()
        .expect("argument types")
        .iter()
        .map(|t| parse_type(text(t), records))
        .collect();
    Entrypoint {
        name: leak_str(text(name)),
        params: Box::leak(params.into_boxed_slice()),
    }
}

/// An entrypoint's signature and tag, against the vector's.
fn signs_as(e: &Entrypoint<'_>, v: &Value) {
    let signature = e.signature().to_string();
    assert_eq!(
        hex(signature.as_bytes()),
        text(&v["function_signature_utf8_hex"]),
        "{signature}"
    );
    assert_eq!(
        hex(&e.dispatch_tag().unwrap()),
        text(&v["dispatch_tag_hex"]),
        "{signature}"
    );
}

/// 6.1: BLAKE3, unkeyed and keyed, the key padded to 32 bytes.
#[test]
fn the_hash_function_is_kcc1s() {
    let v = vectors();
    let rows = v["hash_function"].as_array().unwrap();
    assert_eq!(rows.len(), 3);
    for row in rows {
        let input = unhex(text(&row["input_hex"]));
        let got = match row.get("key_hex") {
            None => hash(&input),
            Some(key) => {
                let key = unhex(text(key));
                assert_eq!(hex(&key32(&key).unwrap()), text(&row["key32_hex"]));
                keyed_hash(&input, &key).unwrap()
            }
        };
        assert_eq!(hex(&got), text(&row["hash_hex"]), "{}", row["id"]);
    }
}

/// 3.2.1: the keyed form takes 32 bytes of key at most.
#[test]
fn a_key_past_32_bytes_is_refused() {
    assert_eq!(key32(&[7; 33]), Err(KeyTooLong));
    assert_eq!(keyed_hash(b"", &[7; 33]), Err(KeyTooLong));
    assert_eq!(key32(&[7; 32]).unwrap(), [7; 32]);
}

/// 6.2: every canonical type name, a record by its own name.
#[test]
fn types_are_named_as_kcc1_names_them() {
    let v = vectors();
    let rows = v["canonical_type_names"].as_array().unwrap();
    assert_eq!(rows.len(), 11);
    let transfer = Record {
        name: "Transfer",
        fields: &[],
    };
    for row in rows {
        let ty = match text(&row["type"]) {
            "integer" => Type::Int,
            "boolean" => Type::Bool,
            "byte" => Type::Byte,
            "UTF-8 string" => Type::String,
            "32-byte public key" => Type::Pubkey,
            "65-byte transaction signature" => Type::Sig,
            "64-byte data signature" => Type::Datasig,
            "fixed byte string of length 32" => Type::Array(&Type::Byte, 32),
            "fixed array of three booleans" => Type::Array(&Type::Bool, 3),
            "dynamic array of integers" => Type::Dynamic(&Type::Int),
            "record named Transfer" => Type::Record(&transfer),
            other => panic!("a type this test does not know: {other}"),
        };
        assert_eq!(ty.type_name().to_string(), text(&row["type_name"]));
    }
}

/// 6.6: `step(int,byte[4],bool,byte)`, and `tick()` with no arguments.
#[test]
fn dispatch_tags_are_kcc1s() {
    let v = vectors();
    let none = Value::Array(vec![]);
    for group in ["dispatch_and_arguments", "zero_argument_dispatch"] {
        let row = &v[group];
        signs_as(
            &entrypoint(&row["entrypoint_name"], &row["argument_types"], &none),
            row,
        );
    }
}

/// 6.6: records in a signature by field types alone: renaming changes
/// nothing, reordering does, nesting nests.
#[test]
fn records_dispatch_by_their_field_types() {
    let v = vectors();
    let rows = v["record_dispatch"].as_array().unwrap();
    assert!(rows.len() >= 5);
    for row in rows {
        let e = entrypoint(
            &row["entrypoint_name"],
            &row["argument_types"],
            &row["records"],
        );
        let names: Vec<String> = e
            .params
            .iter()
            .map(|t| t.dispatch_name().to_string())
            .collect();
        let want: Vec<&str> = row["dispatch_type_names"]
            .as_array()
            .unwrap()
            .iter()
            .map(text)
            .collect();
        assert_eq!(names, want, "{}", row["id"]);
        signs_as(&e, row);
    }
}

/// 6.9: the prefix's and the suffix's lengths in the hash.
#[test]
fn template_hashes_are_kcc1s() {
    let v = vectors();
    let rows = v["template_hashes"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    for row in rows {
        let got = template_hash(
            &unhex(text(&row["prefix_hex"])),
            &unhex(text(&row["suffix_hex"])),
        );
        assert_eq!(hex(&got), text(&row["hash_hex"]));
    }
}

/// 3.5.1's rejections: two entrypoints alike once records are dropped to
/// field types, and two whose tags collide.
#[test]
fn entrypoints_with_one_tag_are_refused() {
    let v = vectors();
    let none = Value::Array(vec![]);
    let rows: Vec<&Value> = v["rejection_vectors"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["operation"] == "validate_entrypoints")
        .collect();
    assert_eq!(rows.len(), 2);
    for row in rows {
        let records = row.get("records").unwrap_or(&none);
        let entries: Vec<Entrypoint<'static>> = row["entrypoints"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| entrypoint(&e["name"], &e["argument_types"], records))
            .collect();
        let signatures: Vec<String> = entries.iter().map(|e| e.signature().to_string()).collect();
        let want: Vec<&str> = row["function_signatures"]
            .as_array()
            .unwrap()
            .iter()
            .map(text)
            .collect();
        assert_eq!(signatures, want, "{}", row["id"]);
        for e in &entries {
            assert_eq!(
                hex(&e.dispatch_tag().unwrap()),
                text(&row["dispatch_tag_hex"])
            );
        }
        assert_eq!(
            check_entrypoints(&entries),
            Err(AbiError::DuplicateTag),
            "{}",
            row["id"]
        );
        assert_eq!(check_entrypoints(&entries[..1]), Ok(()));
    }
}

/// 3.5: a program has an entrypoint. 3.4.1: a record's name is a type
/// identifier.
#[test]
fn what_kcc1_forbids_elsewhere_is_refused() {
    assert_eq!(check_entrypoints(&[]), Err(AbiError::NoEntrypoint));
    for (name, ok) in [
        ("Order", true),
        ("_x9", true),
        ("9lives", false),
        ("", false),
        ("a-b", false),
        ("ñ", false),
    ] {
        let r = Record { name, fields: &[] };
        let e = Entrypoint {
            name: "f",
            params: &[Type::Dynamic(&Type::Record(&r))],
        };
        assert_eq!(e.dispatch_tag().is_ok(), ok, "{name:?}");
        assert_eq!(check_entrypoints(&[e]).is_ok(), ok, "{name:?}");
    }
}

/// A vector's byte string: literal hex, or one byte repeated.
fn bytes_of(v: &Value) -> Vec<u8> {
    match (v.get("hex"), v.get("repeat_hex"), v.get("count")) {
        (Some(h), _, _) => unhex(text(h)),
        (None, Some(r), Some(n)) => unhex(text(r)).repeat(n.as_u64().unwrap() as usize),
        _ => panic!("not a byte string: {v}"),
    }
}

/// A vector's encoding of `payload`: literal hex, or a prefix and the
/// payload unchanged.
fn encoding_of(v: &Value, payload: &[u8]) -> Vec<u8> {
    match v.get("hex") {
        Some(h) => unhex(text(h)),
        None => {
            assert_eq!(v["payload"], "unchanged");
            [unhex(text(&v["encoded_prefix_hex"])), payload.to_vec()].concat()
        }
    }
}

/// 6.3: both pushes, every row, each written and read back as written.
#[test]
fn pushes_are_kcc1s() {
    let v = vectors();
    let rows = v["data_pushes"].as_array().unwrap();
    assert_eq!(rows.len(), 13);
    for row in rows {
        let payload = bytes_of(&row["payload"]);
        let id = text(&row["id"]);
        for (kind, want) in [
            ("minimal", encoding_of(&row["push_minimal"], &payload)),
            ("explicit", encoding_of(&row["push_explicit"], &payload)),
        ] {
            let mut out = vec![0u8; want.len()];
            let (n, len) = if kind == "minimal" {
                (
                    push_minimal(&payload, &mut out).unwrap(),
                    minimal_len(&payload),
                )
            } else {
                (
                    push_explicit(&payload, &mut out).unwrap(),
                    explicit_len(payload.len()),
                )
            };
            assert_eq!((n, len), (want.len(), want.len()), "{id} {kind}");
            assert_eq!(out, want, "{id} {kind}");
            let read: Vec<_> = pushes(&want).collect::<Result<_, _>>().unwrap();
            assert_eq!(read.len(), 1, "{id} {kind}");
            assert_eq!(read[0].payload, &payload[..], "{id} {kind}");
            if kind == "minimal" {
                assert!(read[0].is_minimal(), "{id}");
            } else {
                assert!(read[0].is_explicit(), "{id}");
            }
            assert_eq!(
                read[0].is_minimal(),
                want == encoding_of(&row["push_minimal"], &payload),
                "{id} {kind}"
            );
        }
        let mut short = vec![0u8; minimal_len(&payload) - 1];
        assert_eq!(
            push_minimal(&payload, &mut short),
            Err(PushError::BufferTooSmall),
            "{id}"
        );
    }
}

/// What is not a push, or is cut short, is not read as one.
#[test]
fn only_whole_pushes_are_read() {
    for (script, why) in [
        (&[0x93][..], PushError::NotPush),         // OP_ADD
        (&[0x50][..], PushError::NotPush),         // OP_RESERVED, below OP_16
        (&[0x51, 0xac][..], PushError::NotPush),   // OP_1 OP_CHECKSIG
        (&[0x02, 0x01][..], PushError::Truncated), // OP_DATA_2 and one byte
        (&[0x4d, 0x05][..], PushError::Truncated), // OP_PUSHDATA2 with half a length
    ] {
        let read: Result<Vec<_>, _> = pushes(script).collect();
        assert_eq!(read, Err(why), "{script:02x?}");
    }
}

/// 6.7: 6.6's `step` spending program `51`: its lock, and its signature
/// script written and read back.
#[test]
fn the_envelope_is_kcc1s() {
    let v = vectors();
    let row = &v["p2sh_envelope"];
    let program = unhex(text(&row["redeem_script_hex"]));
    assert_eq!(hex(&redeem_hash(&program)), text(&row["blake2b_256_hex"]));
    assert_eq!(row["script_public_key"]["version"], 0);
    let lock = locking_script(&program);
    assert_eq!(hex(&lock), text(&row["script_public_key"]["script_hex"]));

    let step = &v["dispatch_and_arguments"];
    let arguments: Vec<u8> = step["argument_encodings_hex"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|a| unhex(text(a)))
        .collect();
    let tag: [u8; 4] = unhex(text(&step["dispatch_tag_hex"])).try_into().unwrap();
    let invocation = Invocation {
        arguments: &arguments,
        dispatch_tag: tag,
        program: &program,
    };
    let want = unhex(text(&row["signature_script_hex"]));
    let mut out = vec![0u8; signature_script_len(arguments.len(), &program)];
    assert_eq!(write(&invocation, &mut out), Ok(want.len()));
    assert_eq!(out, want);
    assert_eq!(read(&want), Ok(invocation));
    let coin = ScriptPublicKey {
        version: 0,
        script: &lock,
    };
    assert_eq!(read_spend(&coin, &want), Ok(invocation));
}

/// 6.6: `tick()`, no arguments: its tag's push opens the signature script.
#[test]
fn a_spend_with_no_arguments_opens_with_its_tag() {
    let v = vectors();
    let row = &v["zero_argument_dispatch"];
    assert_eq!(text(&row["push_arguments_hex"]), "");
    let tag: [u8; 4] = unhex(text(&row["dispatch_tag_hex"])).try_into().unwrap();
    let program = [0x51];
    let invocation = Invocation {
        arguments: &[],
        dispatch_tag: tag,
        program: &program,
    };
    let mut out = [0u8; 8];
    let n = write(&invocation, &mut out).unwrap();
    assert_eq!(hex(&out[..5]), text(&row["dispatch_tag_push_hex"]));
    assert_eq!(read(&out[..n]), Ok(invocation));
}

/// 3.6's musts, each broken once, and a coin another program locks.
#[test]
fn a_signature_script_that_is_no_envelope_is_refused() {
    let program = [0x51];
    let good = unhex("011104010203045151042c49ed650151");
    assert!(read(&good).is_ok());
    for (script, why) in [
        ("", EnvelopeError::NoDispatchTag),
        ("0151", EnvelopeError::NoDispatchTag),
        // The tag pushed by OP_PUSHDATA1, and as five bytes.
        ("4c042c49ed650151", EnvelopeError::NoDispatchTag),
        ("052c49ed65000151", EnvelopeError::NoDispatchTag),
        // The program pushed by OP_PUSHDATA1, and `01` pushed as data.
        ("042c49ed654c0151", EnvelopeError::ProgramNotMinimal),
        ("042c49ed650101", EnvelopeError::ProgramNotMinimal),
        // OP_ADD among the arguments; a push cut short.
        ("93042c49ed650151", EnvelopeError::NotPushOnly),
        ("042c49ed650251", EnvelopeError::Truncated),
    ] {
        assert_eq!(read(&unhex(script)), Err(why), "{script}");
    }
    let other = locking_script(&[0x52]);
    for (coin, why) in [
        (
            ScriptPublicKey {
                version: 0,
                script: &other,
            },
            EnvelopeError::NotTheCoinsProgram,
        ),
        (
            ScriptPublicKey {
                version: 1,
                script: &locking_script(&program),
            },
            EnvelopeError::NotTheCoinsProgram,
        ),
    ] {
        assert_eq!(read_spend(&coin, &good), Err(why));
    }
    // Arguments that are not whole pushes are not written either.
    let bad = Invocation {
        arguments: &[0x93],
        dispatch_tag: [0; 4],
        program: &program,
    };
    assert_eq!(write(&bad, &mut [0u8; 16]), Err(EnvelopeError::NotPushOnly));
    let good = Invocation {
        arguments: &[],
        ..bad
    };
    assert_eq!(
        write(&good, &mut [0u8; 6]),
        Err(EnvelopeError::BufferTooSmall)
    );
}

/// A program past 65,535 bytes, pushed by `OP_PUSHDATA4`, both ways.
#[test]
fn a_program_past_64_kib_goes_by_pushdata4() {
    let program = vec![0xab; 70_000];
    let invocation = Invocation {
        arguments: &[0x51],
        dispatch_tag: [1, 2, 3, 4],
        program: &program,
    };
    let mut out = vec![0u8; signature_script_len(1, &program)];
    assert_eq!(write(&invocation, &mut out), Ok(1 + 5 + 5 + 70_000));
    assert_eq!(hex(&out[6..11]), "4e70110100");
    assert_eq!(read(&out), Ok(invocation));
}

/// A vector's value: `value`, `value_hex`, or `value_decimal` for an `int`
/// past JSON's safe range.
fn value_of(row: &Value) -> Value {
    ["value", "value_hex", "value_decimal"]
        .iter()
        .find_map(|k| row.get(*k).cloned())
        .unwrap_or_else(|| panic!("no value in {row}"))
}

/// The records a vector names: `record` alone, or `records`.
fn records_of(row: &Value) -> Value {
    match (row.get("record"), row.get("records")) {
        (Some(r), _) => Value::Array(vec![r.clone()]),
        (None, Some(rs)) => rs.clone(),
        (None, None) => Value::Array(vec![]),
    }
}

/// `want`, as KCC-1's vectors write a value, against what `get` reads at
/// `path` and below.
fn expect_json<'b>(
    ty: &Type<'static>,
    want: &Value,
    get: &dyn Fn(&[Segment<'static>]) -> Result<Got<'b>, ValueError>,
    path: &mut Vec<Segment<'static>>,
) {
    let got = get(path);
    match ty {
        Type::Int | Type::Temporal => {
            let n = match want {
                Value::String(s) => s.parse().expect("an int"),
                n => n.as_i64().expect("an int"),
            };
            assert_eq!(got, Ok(Got::Int(n)), "{path:?}");
        }
        Type::Bool => assert_eq!(got, Ok(Got::Bool(want.as_bool().unwrap())), "{path:?}"),
        Type::Byte => assert_eq!(got, Ok(Got::Byte(unhex(text(want))[0])), "{path:?}"),
        Type::String => assert_eq!(got, Ok(Got::Text(text(want))), "{path:?}"),
        Type::Pubkey
        | Type::Sig
        | Type::Datasig
        | Type::Array(Type::Byte, _)
        | Type::Dynamic(Type::Byte) => {
            assert_eq!(got, Ok(Got::Bytes(&unhex(text(want)))), "{path:?}")
        }
        Type::Array(item, _) | Type::Dynamic(item) => {
            let items = want.as_array().unwrap();
            assert_eq!(got, Ok(Got::Array(items.len())), "{path:?}");
            for (i, w) in items.iter().enumerate() {
                path.push(Segment::Index(i));
                expect_json(item, w, get, path);
                path.pop();
            }
        }
        Type::Record(r) => {
            assert_eq!(got, Ok(Got::Record), "{path:?}");
            for f in r.fields {
                let w = want
                    .get(f.name)
                    .or_else(|| want.get(format!("{}_hex", f.name)))
                    .unwrap_or_else(|| panic!("no {} in {want}", f.name));
                path.push(Segment::Field(f.name));
                expect_json(&f.ty, w, get, path);
                path.pop();
            }
        }
    }
}

/// A state of one field, `v`, holding `payload`.
fn one_field_state(payload: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; explicit_len(payload.len())];
    push_explicit(payload, &mut out).unwrap();
    out
}

/// 6.4: every scalar as an argument and a state field, and an `int` written
/// both ways.
#[test]
fn scalars_are_kcc1s() {
    let v = vectors();
    let none = Value::Array(vec![]);
    let rows = v["scalar_encodings"].as_array().unwrap();
    assert!(rows.len() >= 18);
    for row in rows {
        let ty = parse_type(text(&row["type"]), &none);
        let want = value_of(row);
        let arg = unhex(text(&row["standalone_argument_hex"]));
        let params = [ty];
        expect_json(&ty, &want, &|p| argument(&params, &arg, 0, p), &mut vec![]);

        let payload = unhex(text(&row["state_payload_hex"]));
        let state = one_field_state(&payload);
        let fields = [Field { name: "v", ty }];
        expect_json(
            &ty,
            &want,
            &|p| state_value(&fields, &state, &[&[Segment::Field("v")], p].concat()),
            &mut vec![],
        );

        if ty == Type::Int {
            let n: i64 = match &want {
                Value::String(s) => s.parse().unwrap(),
                n => n.as_i64().unwrap(),
            };
            let mut num = [0u8; 8];
            let len = int_argument(n, &mut num).unwrap();
            let mut pushed = vec![0u8; minimal_len(&num[..len])];
            push_minimal(&num[..len], &mut pushed).unwrap();
            assert_eq!(pushed, arg, "{n}");
            assert_eq!(int_payload(n).unwrap()[..], payload[..], "{n}");
        }
    }
}

/// 6.5: arrays, records and arrays of records as arguments; arrays as state
/// fields too.
#[test]
fn composites_are_kcc1s() {
    let v = vectors();
    let rows = v["composite_encodings"].as_array().unwrap();
    assert!(rows.len() >= 9);
    for row in rows {
        let records = records_of(row);
        let name = row
            .get("type")
            .map(text)
            .unwrap_or_else(|| text(&row["record"]["name"]));
        let ty = parse_type(name, &records);
        let arg = unhex(text(
            row.get("argument_hex").or(row.get("combined_hex")).unwrap(),
        ));
        for parts in ["lowered_argument_hex", "grouped_argument_hex"] {
            if let Some(ps) = row.get(parts) {
                let joined: Vec<u8> = ps
                    .as_array()
                    .unwrap()
                    .iter()
                    .flat_map(|p| unhex(text(p)))
                    .collect();
                assert_eq!(joined, arg, "{}", row["id"]);
            }
        }
        let params = [ty];
        let want = value_of(row);
        assert_eq!(check_arguments(&params, &arg), Ok(()), "{}", row["id"]);
        expect_json(&ty, &want, &|p| argument(&params, &arg, 0, p), &mut vec![]);

        if let Some(payload) = row.get("payload_hex") {
            let state = one_field_state(&unhex(text(payload)));
            let fields = [Field { name: "v", ty }];
            expect_json(
                &ty,
                &want,
                &|p| state_value(&fields, &state, &[&[Segment::Field("v")], p].concat()),
                &mut vec![],
            );
        }
    }
}

/// 6.8: a four-field state, read and written field by field.
#[test]
fn the_state_is_kcc1s() {
    let v = vectors();
    let row = &v["state_encoding"];
    let none = Value::Array(vec![]);
    let rows = row["fields"].as_array().unwrap();
    let fields: Vec<Field<'static>> = rows
        .iter()
        .map(|f| Field {
            name: leak_str(text(&f["name"])),
            ty: parse_type(text(&f["type"]), &none),
        })
        .collect();
    let encoded = unhex(text(&row["encoded_hex"]));
    assert_eq!(
        encoded.len() as u64,
        row["encoded_length"].as_u64().unwrap()
    );
    assert_eq!(check_state(&fields, &encoded), Ok(()));
    let mut written = Vec::new();
    for (f, r) in fields.iter().zip(rows) {
        let want = value_of(r);
        expect_json(
            &f.ty,
            &want,
            &|p| state_value(&fields, &encoded, &[&[Segment::Field(f.name)], p].concat()),
            &mut vec![],
        );
        let payload = match (f.ty, &want) {
            (Type::Int, n) => int_payload(n.as_i64().unwrap()).unwrap().to_vec(),
            (Type::Bool, b) => vec![u8::from(b.as_bool().unwrap())],
            (Type::String, s) => text(s).as_bytes().to_vec(),
            (_, h) => unhex(text(h)),
        };
        let field = one_field_state(&payload);
        assert_eq!(hex(&field), text(&r["encoded_hex"]), "{}", f.name);
        written.extend(field);
    }
    assert_eq!(written, encoded);
    assert_eq!(state_value(&fields, &encoded, &[]), Ok(Got::Record));
}

/// Every rejection KCC-1 lists for values, each for the reason it gives.
#[test]
fn values_kcc1_rejects_are_refused() {
    let v = vectors();
    let none = Value::Array(vec![]);
    let why = |id: &str| match id {
        "argument-int-redundant-sign-byte" | "argument-int-negative-zero" => ValueError::BadInt,
        "argument-int-nonminimal-push" => ValueError::NotCanonicalPush,
        "argument-byte-empty" | "argument-fixed-bytes-short" => ValueError::BadLength,
        "argument-bool-two" | "argument-bool-explicit-false" => ValueError::BadBool,
        "argument-int-array-partial-element" | "argument-fixed-array-wrong-count" => {
            ValueError::BadLength
        }
        "argument-bool-array-invalid-element" => ValueError::BadBool,
        "argument-record-array-unequal-groups" => ValueError::UnequalGroups,
        "argument-record-array-wrong-fixed-count" => ValueError::BadLength,
        "state-bool-small-integer-opcode" | "state-bool-nonminimal-length-prefix" => {
            ValueError::NotCanonicalPush
        }
        "state-bool-empty-payload" | "state-bool-invalid-payload" => ValueError::BadBool,
        "state-int-minimal-width" | "state-int-negative-zero" => ValueError::BadInt,
        "state-missing-field" => ValueError::Missing,
        "state-trailing-bytes" => ValueError::Trailing,
        "state-truncated-payload" | "state-truncated-length" | "state-non-push-opcode" => {
            ValueError::NotPush
        }
        other => panic!("a rejection this test does not know: {other}"),
    };
    let mut seen = 0;
    for row in v["rejection_vectors"].as_array().unwrap() {
        let id = text(&row["id"]);
        let records = row.get("records").unwrap_or(&none);
        match text(&row["operation"]) {
            "decode_arguments" => {
                let params: Vec<Type<'static>> = row["argument_types"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|t| parse_type(text(t), records))
                    .collect();
                assert_eq!(
                    check_arguments(&params, &unhex(text(&row["argument_hex"]))),
                    Err(why(id)),
                    "{id}"
                );
            }
            "decode_state" => {
                let fields: Vec<Field<'static>> = row["fields"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|f| Field {
                        name: leak_str(text(&f["name"])),
                        ty: parse_type(text(&f["type"]), records),
                    })
                    .collect();
                assert_eq!(
                    check_state(&fields, &unhex(text(&row["encoded_hex"]))),
                    Err(why(id)),
                    "{id}"
                );
            }
            "validate_argument_type" => {
                let ty = parse_type(text(&row["type"]), records);
                assert_eq!(ty.check_layout(), Err(AbiError::BadLayout), "{id}");
                let params = [ty];
                assert_eq!(
                    check_arguments(&params, &[]),
                    Err(ValueError::Type(AbiError::BadLayout)),
                    "{id}"
                );
            }
            "encode_scalar" => {
                // Past i64 it cannot be asked for at all; at -2^63 it is.
                let n: i128 = text(&row["value_decimal"]).parse().unwrap();
                if let Ok(n) = i64::try_from(n) {
                    assert_eq!(
                        int_argument(n, &mut [0; 8]),
                        Err(ValueError::BadInt),
                        "{id}"
                    );
                    assert_eq!(int_payload(n), Err(ValueError::BadInt), "{id}");
                }
            }
            "validate_entrypoints" => continue,
            other => panic!("an operation this test does not know: {other}"),
        }
        seen += 1;
    }
    assert_eq!(seen, 28);
}

/// A location that selects nothing, in arguments and in a state.
#[test]
fn a_location_that_selects_nothing_is_refused() {
    let v = vectors();
    let row = v["composite_encodings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "record-array")
        .unwrap();
    let ty = parse_type(text(&row["type"]), &records_of(row));
    let arg = unhex(text(&row["combined_hex"]));
    let params = [ty];
    use Segment::{Field as F, Index as I};
    assert_eq!(argument(&params, &arg, 0, &[I(1)]), Ok(Got::Record));
    assert_eq!(
        argument(&params, &arg, 0, &[I(1), F("id"), I(1)]),
        Ok(Got::Byte(0xdd))
    );
    for path in [
        &[I(2)][..],
        &[I(0), F("nope")],
        &[I(0), F("enabled"), I(0)],
        &[F("id")],
    ] {
        assert_eq!(
            argument(&params, &arg, 0, path),
            Err(ValueError::BadLocation),
            "{path:?}"
        );
    }
    assert_eq!(
        argument(&params, &arg, 1, &[]),
        Err(ValueError::BadLocation)
    );

    let fields = [Field {
        name: "v",
        ty: Type::Bool,
    }];
    let state = [0x01, 0x01];
    assert_eq!(state_value(&fields, &state, &[F("v")]), Ok(Got::Bool(true)));
    for path in [&[F("w")][..], &[F("v"), I(0)], &[I(0)]] {
        assert_eq!(
            state_value(&fields, &state, path),
            Err(ValueError::BadLocation),
            "{path:?}"
        );
    }
}

/// 3.7: a program cut at its state, a stateless one at `0` and `0`, a span
/// past its end refused.
#[test]
fn a_program_is_cut_at_its_state() {
    let program = [1, 2, 3, 4, 5];
    let parts = Parts::of(&program, Span { start: 1, len: 2 }).unwrap();
    assert_eq!(
        (parts.prefix, parts.state, parts.suffix),
        (&[1][..], &[2, 3][..], &[4, 5][..])
    );
    assert_eq!(parts.template_hash(), template_hash(&[1], &[4, 5]));
    let stateless = Parts::of(&program, Span::default()).unwrap();
    assert_eq!(
        (stateless.prefix, stateless.state, stateless.suffix),
        (&[][..], &[][..], &program[..])
    );
    for span in [
        Span { start: 4, len: 2 },
        Span { start: 6, len: 0 },
        Span {
            start: usize::MAX,
            len: 1,
        },
    ] {
        assert_eq!(
            Parts::of(&program, span),
            Err(ValueError::OutOfBounds),
            "{span:?}"
        );
    }
}

// ── SilverScript ────────────────────────────────────────────────────────────

/// A program with an entrypoint for every kind of argument SilverScript
/// takes, a state field for a template, and a nested record.
const PROBE: &str = r#"
pragma silverscript ^0.1.0;

contract Probe(pubkey owner, int start) {
    int counter = start;

    struct Order {
        byte[4] recipe;
        byte sugar;
        bool milk;
    }

    struct Pair {
        int count;
        bool enabled;
    }

    struct Envelope {
        Pair pair;
        byte marker;
    }

    entry tick() {
        require(counter >= 0);
    }

    entry step(int a, byte[4] b, bool c, byte d) {
        require(a >= 0 && c && b == b && d == d);
    }

    entry keys(pubkey pk, sig s, datasig ds, string memo) {
        require(pk == owner && checkSig(s, pk) && ds == ds && memo == memo);
    }

    entry lists(byte[] data, int[3] counts, bool[] flags) {
        require(data.length >= 0 && counts.length == 3 && flags.length >= 0);
    }

    entry orders(Order[] list, Order[2] two) {
        require(list.length >= 0 && two.length == 2);
    }

    entry nested(Envelope e) {
        require(e.marker == e.marker);
    }

    entry later(temporal when) {
        require(tx.time >= when);
    }
}
"#;

fn compile(source: &str) -> SilAbiArtifact {
    use silverscript_abi::ArtifactValue;
    let args = [ArtifactValue::Bytes(vec![2; 32]), ArtifactValue::Int(5)];
    silverscript_lang::compiler::compile_to_sil_abi_artifact(source, &args)
        .expect("SilverScript compiles the probe")
}

/// A SilverScript artifact's type as this crate's, its records from
/// `artifact`.
fn from_artifact(t: &TypeArtifact, artifact: &SilAbiArtifact) -> Type<'static> {
    match t {
        TypeArtifact::Int => Type::Int,
        TypeArtifact::Temporal => Type::Temporal,
        TypeArtifact::Bool => Type::Bool,
        TypeArtifact::Byte => Type::Byte,
        TypeArtifact::Bytes => Type::Dynamic(&Type::Byte),
        TypeArtifact::Text => Type::String,
        TypeArtifact::Pubkey => Type::Pubkey,
        TypeArtifact::Sig => Type::Sig,
        TypeArtifact::Datasig => Type::Datasig,
        TypeArtifact::FixedBytes { len } => Type::Array(&Type::Byte, *len),
        TypeArtifact::FixedArray { item, len } => {
            Type::Array(leak(from_artifact(item, artifact)), *len)
        }
        TypeArtifact::DynamicArray { item } => Type::Dynamic(leak(from_artifact(item, artifact))),
        TypeArtifact::Struct { name } => {
            let fields: Vec<Field<'static>> = artifact.structs[name]
                .fields
                .iter()
                .map(|f| Field {
                    name: leak_str(&f.name),
                    ty: from_artifact(&f.ty, artifact),
                })
                .collect();
            Type::Record(leak(Record {
                name: leak_str(name),
                fields: Box::leak(fields.into_boxed_slice()),
            }))
        }
    }
}

/// Every entrypoint's tag, `temporal` included, and the template hash, as
/// SilverScript's compiler wrote them.
#[test]
fn silverscript_compiles_the_same_tags_and_template() {
    let artifact = compile(PROBE);
    let contract = &artifact.contracts["Probe"];
    assert_eq!(contract.entries.len(), 7);
    let mut entries = Vec::new();
    for (name, entry) in &contract.entries {
        let params: Vec<Type<'static>> = entry
            .params
            .iter()
            .map(|p| from_artifact(&p.ty, &artifact))
            .collect();
        let e = Entrypoint {
            name: leak_str(name),
            params: Box::leak(params.into_boxed_slice()),
        };
        assert_eq!(
            e.dispatch_tag().unwrap()[..],
            entry.dispatch_tag.as_bytes()[..],
            "{}",
            e.signature()
        );
        entries.push(e);
    }
    assert_eq!(check_entrypoints(&entries), Ok(()));
    // What was hashed, so a change in either side shows as text.
    let mut signatures: Vec<String> = entries.iter().map(|e| e.signature().to_string()).collect();
    signatures.sort();
    assert_eq!(
        signatures,
        [
            "keys(pubkey,sig,datasig,string)",
            "later(temporal)",
            "lists(byte[],int[3],bool[])",
            "nested({{int,bool},byte})",
            "orders({byte[4],byte,bool}[],{byte[4],byte,bool}[2])",
            "step(int,byte[4],bool,byte)",
            "tick()",
        ]
    );

    let compiled = &contract.compiled;
    assert!(compiled.state_span.len > 0, "the probe keeps state");
    let (prefix, _state, suffix) = compiled.script_parts(&compiled.bytecode).unwrap();
    assert_eq!(template_hash(prefix, suffix), compiled.template_hash);
}

/// The template hash against SilverScript's, over lengths that change a
/// push's encoding and one past 64 KiB.
#[test]
fn silverscript_hashes_templates_the_same() {
    let mut x: u32 = 0x9e37_79b9;
    let mut bytes = |n: usize| -> Vec<u8> {
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    };
    for (p, s) in [
        (0, 0),
        (0, 1),
        (1, 0),
        (75, 76),
        (255, 256),
        (520, 3),
        (65_536, 17),
    ] {
        let (prefix, suffix) = (bytes(p), bytes(s));
        assert_eq!(
            template_hash(&prefix, &suffix),
            silverscript_abi::template_hash(&prefix, &suffix),
            "{p} {s}"
        );
    }
}

/// A record's value, for SilverScript's encoder.
fn object(fields: Vec<(&str, silverscript_abi::ArtifactValue)>) -> silverscript_abi::ArtifactValue {
    silverscript_abi::ArtifactValue::Object(
        fields
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect::<std::collections::BTreeMap<_, _>>(),
    )
}

/// One spend of each of the probe's entrypoints: its name and arguments.
fn probe_spends() -> Vec<(&'static str, Vec<silverscript_abi::ArtifactValue>)> {
    use silverscript_abi::ArtifactValue as V;

    let order = |recipe: u8, sugar: u8, milk: bool| {
        object(vec![
            ("recipe", V::Bytes(vec![recipe; 4])),
            ("sugar", V::Byte(sugar)),
            ("milk", V::Bool(milk)),
        ])
    };
    vec![
        ("tick", vec![]),
        (
            "step",
            vec![
                V::Int(17),
                V::Bytes(vec![1, 2, 3, 4]),
                V::Bool(true),
                V::Byte(1),
            ],
        ),
        (
            "keys",
            vec![
                V::Bytes(vec![2; 32]),
                V::Bytes(vec![0x11; 65]),
                V::Bytes(vec![0x22; 64]),
                V::Text("hello".into()),
            ],
        ),
        (
            "lists",
            vec![
                V::Bytes(vec![9; 300]),
                V::Array(vec![V::Int(1), V::Int(-2), V::Int(3)]),
                V::Array(vec![V::Bool(true), V::Bool(false)]),
            ],
        ),
        (
            "orders",
            vec![
                V::Array(vec![
                    order(1, 2, true),
                    order(3, 0, false),
                    order(5, 16, true),
                ]),
                V::Array(vec![order(7, 1, false), order(8, 129, true)]),
            ],
        ),
        (
            "nested",
            vec![object(vec![
                (
                    "pair",
                    object(vec![("count", V::Int(5)), ("enabled", V::Bool(false))]),
                ),
                ("marker", V::Byte(9)),
            ])],
        ),
        ("later", vec![V::Int(1_700_000_000_000)]),
    ]
}

/// One spend of each probe entrypoint, its arguments as SilverScript's ABI
/// encodes them and its program as upstream pushes it: written byte for
/// byte, read back to the same parts, the coin's lock upstream's.
#[test]
fn silverscript_spends_read_and_write_the_same() {
    use kaspa_txscript::script_builder::ScriptBuilder;

    let spends = probe_spends();
    let artifact = compile(PROBE);
    let contract = &artifact.contracts["Probe"];
    let program = &contract.compiled.bytecode;
    let lock = locking_script(program);
    assert_eq!(
        lock[..],
        kaspa_txscript::pay_to_script_hash_script(program).script()[..]
    );
    let coin = ScriptPublicKey {
        version: 0,
        script: &lock,
    };
    assert_eq!(spends.len(), contract.entries.len());
    for (name, args) in spends {
        let head =
            silverscript_abi::encode_contract_entry_sig_script(&artifact, "Probe", name, &args)
                .unwrap_or_else(|e| panic!("{name}: {e}"));
        let tail = ScriptBuilder::new().add_data(program).unwrap().drain();
        let full = [head.clone(), tail].concat();
        let tag = *contract.entries[name].dispatch_tag.as_bytes();

        let invocation = read_spend(&coin, &full).unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert_eq!(invocation.dispatch_tag, tag, "{name}");
        assert_eq!(invocation.program, &program[..], "{name}");
        assert_eq!(invocation.arguments, &head[..head.len() - 5], "{name}");

        let mut out = vec![0u8; signature_script_len(invocation.arguments.len(), program)];
        assert_eq!(write(&invocation, &mut out), Ok(full.len()), "{name}");
        assert_eq!(out, full, "{name}");
    }
}

/// `want`, a value as SilverScript's ABI holds it, against what `get` reads
/// at `path` and below it.
fn expect_artifact<'b>(
    ty: &Type<'static>,
    want: &silverscript_abi::ArtifactValue,
    get: &dyn Fn(&[Segment<'static>]) -> Result<Got<'b>, ValueError>,
    path: &mut Vec<Segment<'static>>,
) {
    use silverscript_abi::ArtifactValue as V;
    let got = get(path);
    match (ty, want) {
        (Type::Int | Type::Temporal, V::Int(n)) => assert_eq!(got, Ok(Got::Int(*n)), "{path:?}"),
        (Type::Bool, V::Bool(b)) => assert_eq!(got, Ok(Got::Bool(*b)), "{path:?}"),
        (Type::Byte, V::Byte(b)) => assert_eq!(got, Ok(Got::Byte(*b)), "{path:?}"),
        (Type::String, V::Text(s)) => assert_eq!(got, Ok(Got::Text(s)), "{path:?}"),
        (_, V::Bytes(b)) => assert_eq!(got, Ok(Got::Bytes(b)), "{path:?}"),
        (Type::Array(item, _) | Type::Dynamic(item), V::Array(items)) => {
            assert_eq!(got, Ok(Got::Array(items.len())), "{path:?}");
            for (i, w) in items.iter().enumerate() {
                path.push(Segment::Index(i));
                expect_artifact(item, w, get, path);
                path.pop();
            }
        }
        (Type::Record(r), V::Object(map)) => {
            assert_eq!(got, Ok(Got::Record), "{path:?}");
            assert_eq!(map.len(), r.fields.len(), "{path:?}");
            for f in r.fields {
                path.push(Segment::Field(f.name));
                expect_artifact(&f.ty, &map[f.name], get, path);
                path.pop();
            }
        }
        (ty, want) => panic!("{ty:?} against {want:?} at {path:?}"),
    }
}

/// Every probe argument reads back as SilverScript's ABI encoded it.
#[test]
fn silverscript_arguments_read_as_encoded() {
    let artifact = compile(PROBE);
    let contract = &artifact.contracts["Probe"];
    for (name, args) in probe_spends() {
        let head =
            silverscript_abi::encode_contract_entry_sig_script(&artifact, "Probe", name, &args)
                .unwrap();
        let encoded = &head[..head.len() - 5];
        let params: Vec<Type<'static>> = contract.entries[name]
            .params
            .iter()
            .map(|p| from_artifact(&p.ty, &artifact))
            .collect();
        assert_eq!(check_arguments(&params, encoded), Ok(()), "{name}");
        for (i, (ty, want)) in params.iter().zip(&args).enumerate() {
            expect_artifact(ty, want, &|p| argument(&params, encoded, i, p), &mut vec![]);
        }
    }
}

/// The probe's compiled state: its template hashed as the compiler did, its
/// `counter` the constructor's `5`.
#[test]
fn silverscript_state_reads_as_compiled() {
    let artifact = compile(PROBE);
    let contract = &artifact.contracts["Probe"];
    let compiled = &contract.compiled;
    let span = Span {
        start: compiled.state_span.offset,
        len: compiled.state_span.len,
    };
    let parts = Parts::of(&compiled.bytecode, span).unwrap();
    assert_eq!(parts.template_hash(), compiled.template_hash);
    let fields: Vec<Field<'static>> = contract
        .runtime_state
        .fields
        .iter()
        .map(|f| Field {
            name: leak_str(&f.name),
            ty: from_artifact(&f.ty, &artifact),
        })
        .collect();
    assert_eq!(
        state_value(&fields, parts.state, &[Segment::Field("counter")]),
        Ok(Got::Int(5))
    );
}

/// A state of every field kind SilverScript's ABI writes, read back field by
/// field; its own decoder agrees.
#[test]
fn silverscript_state_reads_as_encoded() {
    use silverscript_abi::{
        ArtifactValue as V, FieldArtifact, RuntimeFieldArtifact, StructArtifact, TypeArtifact as T,
    };
    use std::collections::BTreeMap;

    let mut artifact = compile(PROBE);
    let field = |name: &str, ty: T| FieldArtifact {
        name: name.into(),
        ty,
    };
    artifact.structs = BTreeMap::from([
        (
            "Inner".to_string(),
            StructArtifact {
                fields: vec![field("marker", T::Byte)],
            },
        ),
        (
            "Outer".to_string(),
            StructArtifact {
                fields: vec![
                    field(
                        "inner",
                        T::Struct {
                            name: "Inner".into(),
                        },
                    ),
                    field("active", T::Bool),
                ],
            },
        ),
        (
            "Pair".to_string(),
            StructArtifact {
                fields: vec![
                    field("amount", T::Int),
                    field("code", T::FixedBytes { len: 2 }),
                ],
            },
        ),
    ]);
    let layout: Vec<(&str, T, V)> = vec![
        ("a", T::Int, V::Int(-5)),
        ("when", T::Temporal, V::Int(1_700_000_000_000)),
        ("b", T::Bool, V::Bool(true)),
        ("c", T::Byte, V::Byte(0x81)),
        ("d", T::FixedBytes { len: 32 }, V::Bytes(vec![7; 32])),
        ("e", T::Pubkey, V::Bytes(vec![2; 32])),
        ("label", T::Text, V::Text("Kaspa".into())),
        ("blob", T::Bytes, V::Bytes(vec![9; 300])),
        (
            "f",
            T::FixedArray {
                item: Box::new(T::Int),
                len: 3,
            },
            V::Array(vec![V::Int(0), V::Int(128), V::Int(-128)]),
        ),
        (
            "flags",
            T::DynamicArray {
                item: Box::new(T::Bool),
            },
            V::Array(vec![V::Bool(false), V::Bool(true)]),
        ),
        (
            "current",
            T::Struct {
                name: "Outer".into(),
            },
            object(vec![
                ("inner", object(vec![("marker", V::Byte(7))])),
                ("active", V::Bool(true)),
            ]),
        ),
        (
            "pairs",
            T::FixedArray {
                item: Box::new(T::Struct {
                    name: "Pair".into(),
                }),
                len: 2,
            },
            V::Array(vec![
                object(vec![
                    ("amount", V::Int(11)),
                    ("code", V::Bytes(vec![0xaa, 0xbb])),
                ]),
                object(vec![
                    ("amount", V::Int(12)),
                    ("code", V::Bytes(vec![0xcc, 0xdd])),
                ]),
            ]),
        ),
    ];
    let contract = artifact.contracts.get_mut("Probe").unwrap();
    contract.runtime_state.fields = layout
        .iter()
        .map(|(name, ty, _)| RuntimeFieldArtifact {
            name: (*name).into(),
            ty: ty.clone(),
        })
        .collect();
    let values: BTreeMap<String, V> = layout
        .iter()
        .map(|(n, _, v)| ((*n).into(), v.clone()))
        .collect();
    let runtime = artifact.contracts["Probe"].runtime_state.clone();
    let encoded =
        silverscript_abi::encode_runtime_state_script(&artifact, &runtime, &values).unwrap();
    assert_eq!(
        silverscript_abi::decode_runtime_state_script(&artifact, &runtime, &encoded).unwrap(),
        values
    );

    let fields: Vec<Field<'static>> = runtime
        .fields
        .iter()
        .map(|f| Field {
            name: leak_str(&f.name),
            ty: from_artifact(&f.ty, &artifact),
        })
        .collect();
    assert_eq!(check_state(&fields, &encoded), Ok(()));
    for f in &fields {
        expect_artifact(
            &f.ty,
            &values[f.name],
            &|p| state_value(&fields, &encoded, &[&[Segment::Field(f.name)], p].concat()),
            &mut vec![],
        );
    }
    // One byte more, or one less, is not this state.
    assert_eq!(
        check_state(&fields, &[&encoded[..], &[0x00]].concat()),
        Err(ValueError::Trailing)
    );
    assert!(check_state(&fields, &encoded[..encoded.len() - 1]).is_err());
}
