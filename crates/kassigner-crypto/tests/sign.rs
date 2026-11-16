// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! BIP340 signing against vectors 0 to 3 of BIP340's `test-vectors.csv`: a
//! secret key, an aux value, a message, and the exact signature. With a
//! fixed aux a signature is one 64-byte value, so a wrong nonce scheme, tag
//! or negation shows as a mismatch, not as a signature that still verifies.

use kassigner_crypto::sign::{public_key, sign, SignError, Signature, SIGNATURE_SIZE};
use kassigner_kaspa::bip340;

#[path = "../../../testkit/hex.rs"]
pub mod hex;
use hex::{hex, unhex_array};

/// (secret key, aux, message, public key, signature), from BIP340, never
/// from this code's output: a vector taken from the code it checks proves
/// only self-consistency.
const VECTORS: &[(&str, &str, &str, &str, &str)] = &[
    (
        "0000000000000000000000000000000000000000000000000000000000000003",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
    ),
    (
        "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
    ),
    (
        "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
        "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
        "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
        "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
    ),
    (
        "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
        "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
    ),
];

/// Every vector produces exactly the signature the specification states.
#[test]
fn signatures_match_the_specification_byte_for_byte() {
    for (i, (sk, aux, msg, pk, sig)) in VECTORS.iter().enumerate() {
        let sk = unhex_array::<32>(sk);
        let aux = unhex_array::<32>(aux);
        let msg = unhex_array::<32>(msg);

        assert_eq!(
            hex(&public_key(&sk).expect("public key")),
            pk.to_lowercase(),
            "vector {i}: key"
        );

        let produced = sign(&sk, &msg, &aux).unwrap_or_else(|e| panic!("vector {i}: {e:?}"));
        assert_eq!(
            hex(produced.as_bytes()),
            sig.to_lowercase(),
            "vector {i}: signature"
        );
    }
}

/// A signature this produces verifies with level 0's verifier: the two
/// halves of BIP340 live in different crates and could drift.
#[test]
fn what_this_signs_the_level_zero_verifier_accepts() {
    for (sk, aux, msg, _, _) in VECTORS {
        let sk = unhex_array::<32>(sk);
        let aux = unhex_array::<32>(aux);
        let msg = unhex_array::<32>(msg);

        let pk = public_key(&sk).unwrap();
        let sig = sign(&sk, &msg, &aux).unwrap();
        assert!(bip340::verify(&pk, &msg, sig.as_bytes()));
    }
}

/// The aux value changes the signature, not its validity: BIP340's guard
/// against fault attacks, which is why the argument has no default.
#[test]
fn the_aux_changes_the_signature_not_its_validity() {
    let sk = unhex_array::<32>(VECTORS[1].0);
    let msg = unhex_array::<32>(VECTORS[1].2);
    let pk = public_key(&sk).unwrap();

    let mut seen: Vec<[u8; SIGNATURE_SIZE]> = Vec::new();
    for byte in [0u8, 1, 0x7F, 0x80, 0xFF] {
        let sig = sign(&sk, &msg, &[byte; 32]).expect("sign");
        assert!(bip340::verify(&pk, &msg, sig.as_bytes()), "aux {byte:#04x}");
        assert!(
            !seen.contains(sig.as_bytes()),
            "aux {byte:#04x} repeated a signature"
        );
        seen.push(*sig.as_bytes());
    }

    // The same aux gives the same signature: what makes the vectors
    // checkable.
    let a = sign(&sk, &msg, &[7u8; 32]).unwrap();
    let b = sign(&sk, &msg, &[7u8; 32]).unwrap();
    assert_eq!(a.as_bytes(), b.as_bytes());
}

/// An invalid private key is refused.
#[test]
fn an_invalid_private_key_is_refused() {
    let msg = [0u8; 32];
    let aux = [0u8; 32];

    assert_eq!(
        sign(&[0u8; 32], &msg, &aux).err(),
        Some(SignError::InvalidPrivateKey)
    );
    assert_eq!(
        public_key(&[0u8; 32]).err(),
        Some(SignError::InvalidPrivateKey)
    );

    // The curve order itself, and all ones, above it.
    let n = unhex_array::<32>("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    assert_eq!(
        sign(&n, &msg, &aux).err(),
        Some(SignError::InvalidPrivateKey)
    );
    assert_eq!(
        sign(&[0xFFu8; 32], &msg, &aux).err(),
        Some(SignError::InvalidPrivateKey)
    );

    // One below the order is fine.
    let last =
        unhex_array::<32>("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");
    assert!(sign(&last, &msg, &aux).is_ok());
}

/// A signature is public, and its Debug shows it whole: unlike the secrets
/// this crate redacts, it travels on the wire.
#[test]
fn a_signature_is_not_secret() {
    let sk = unhex_array::<32>(VECTORS[0].0);
    let sig = sign(&sk, &[0u8; 32], &[0u8; 32]).unwrap();
    let shown = format!("{sig:?}");
    assert!(shown.contains(&hex(sig.as_bytes())));
    assert!(!shown.contains("redacted"));
}

/// The signature round-trips through its byte form.
#[test]
fn a_signature_round_trips_through_bytes() {
    let expected = unhex_array::<SIGNATURE_SIZE>(VECTORS[0].4);
    let s = Signature::from_bytes(expected);
    assert_eq!(s.as_bytes(), &expected);

    let sk = unhex_array::<32>(VECTORS[0].0);
    let produced = sign(&sk, &[0u8; 32], &[0u8; 32]).unwrap();
    assert_eq!(
        produced, s,
        "the vector and what we produce are the same signature"
    );
}
