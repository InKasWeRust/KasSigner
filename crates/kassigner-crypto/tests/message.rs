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

//! A message signature is rusty-kaspa's: its `sign_message` with
//! `no_aux_rand` (`wallet/core/src/message.rs`) is BIP340 over the personal
//! message hash with 32 zero bytes of auxiliary randomness. Ours gives the
//! same 64 bytes, and they verify against the x-only public key.

use kassigner_crypto::sign::sign;
use kassigner_kaspa::sighash::personal_message_hash;
use secp256k1::{schnorr, Keypair, Message, SECP256K1};

#[test]
fn a_message_signature_is_rusty_kaspas() {
    let mut key = [0u8; 32];
    key[31] = 3;
    for text in ["Hello Kaspa!", "Not Hello Kaspa!", "a line\nand another"] {
        let hash = personal_message_hash(text.as_bytes());
        let ours = sign(&key, &hash, &[0; 32]).unwrap();
        let pair = Keypair::from_seckey_slice(SECP256K1, &key).unwrap();
        let theirs = SECP256K1.sign_schnorr_no_aux_rand(&Message::from_digest(hash), &pair);
        assert_eq!(ours.as_bytes(), theirs.as_ref(), "{text}");
        let sig = schnorr::Signature::from_slice(ours.as_bytes()).unwrap();
        let (public, _) = pair.x_only_public_key();
        assert!(SECP256K1
            .verify_schnorr(&sig, &Message::from_digest(hash), &public)
            .is_ok());
    }
}
