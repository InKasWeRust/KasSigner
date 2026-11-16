<!--
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
-->

# The SDK's vectors

What the SDK builds and a unit answers, for the tests of layers that cannot
sign: `kassigner-sdk-host`'s and the bindings' checks. The seeds are the
bench's, abandon 12 and zoo 12, with abandon 24's kpub as the 2-of-3's
third; the unit's aux randomness is the bench's too, so every byte repeats.

## Where they come from

`firmware/kassigner-fw/tests/sdk.rs`, `the_sdk_vectors_are_current`:
requests through `kassigner-sdk`, replies through the firmware's own
signing on a host. With `KASSIGNER_SDK_VECTORS=write` the test writes them;
without it, it compares every file here with what the code makes, so a
change to the SDK's writer or the unit's reply fails the test instead of
leaving a stale vector.

| File | What |
|------|------|
| `single.request` / `.reply.abandon12` | A `44'` spend: two coins (receive 0, change 3), 4 KAS to zoo 12's receive 0, change to change 4; the unit's reply, complete |
| `multisig.request` / `.reply.abandon12` / `.reply.zoo12` | The 2-of-3's cosigner 0 receive 0, 7 KAS to abandon 12's receive 1, change to the group; each cosigner's reply, one signature each |
| `sweep.request` / `.reply.abandon12` | A `22'` sweep: two coins of the KCC-3 receive 0 address, one hinted, to abandon 12's receive 0; the reply carries the unit's redeem scripts |
| `pskb_send.request` / `.reply.abandon12` | The v1.0.7 bench's send bundle re-priced to 0.1 KAS of fee (KIP-9), prepared with abandon 12's hint and its fingerprint `73c5da0a`; the unit's reply |
| `pskb_multisig.request` / `.reply.abandon12` / `.reply.zoo12` | The bench's 2-of-3 bundle prepared with the group's hint; each cosigner's reply |
| `single.bundle` / `.reply.abandon12` | `single.request` built as a bundle (`request::bundle`), each coin's entry at DAA score `90000000` plus its index, not a coinbase, the change output carrying its key on the account's change chain; the unit's reply, which finishes to the KSPT reply's transaction |
| `multisig.bundle` / `.reply.abandon12` / `.reply.zoo12` | `multisig.request` built as a bundle, the coin's entry likewise, the change output carrying the group's keys on its change chain; each cosigner's reply |
| `single.safe.json` / `.safe.signed.json` | `single.request` written in the WASM SDK's safe JSON (`request::safe_json`), unsigned, the coins' entries as in `single.bundle`; and as a wallet hands it back signed, its unlocking scripts the ones the unit's reply finishes to |
| `multisig.safe.json` / `.safe.signed.json` | `multisig.request` likewise, signed with the two cosigners' merged reply's scripts |
| `message.record` | `kassigner.org login` signed by abandon 12's receive 0 |
| `savings.backup` | A Time-Locked Savings card's backup line: abandon 12's receive 0 the owner, zoo 12's receive 0 the recovery wallet, unlocking on 01/01/2027 at 00:00 UTC |
| `savings.request` / `.reply.abandon12` / `.reply.zoo12` | The card's two UTXOs, 5 and 3 KAS, swept to zoo 12's receive 1 under its unlock time as lock time, coin 1's key named; abandon 12's reply, the owner's, a claim, and zoo 12's, the recovery wallet's, a recovery |
| `savings.bundle` / `.reply.abandon12` / `.reply.zoo12` | The same request as a bundle, each input's `redeemScript` the card's program, its `sequence` zero and its `minTime` the unlock time, coin 1's key in its derivations; each reply |
| `savings.claim.signed.json` / `savings.recover.signed.json` | Each KSPT reply finished by the SDK, written in the safe JSON with its coins' entries, for the engine: the bundle replies finish to the same transactions |
| `covenant.start.request` / `.reply.abandon12` / `.signed.json` | A version 1 request that starts a covenant (`Binding::Start`): two `44'` coins of 1000 KAS (receive 1 and 2), two outputs of 100 KAS to the script hash of `77…77` bound under the id coin 0's input makes, change to change 0, not bound; the unit's reply; and the transaction finished by the SDK in the safe JSON, each input committing no signature operations and a compute budget of 10 |
| `covenant.continue.request` / `.reply.abandon12` / `.signed.json` | The same coins, coin 0 bound to covenant `5a…5a` (the request names it, record `0x49`), one output of 100 KAS continuing that covenant (`Binding::Continue`), change not bound; the reply; the finished transaction, coin 0's entry carrying its covenant |
| `covenant.group.request` / `.reply.abandon12` / `.reply.both` / `.signed.json` | The 2-of-3's cosigner 0 receive 0 coin of 1000 KAS starting a covenant in one output of 100 KAS, change to the group; abandon 12's reply, then zoo 12's over it; the finished transaction, its input's compute budget 30, ten a key |
| `covenant.kcc3.signed.json` / `covenant.card.signed.json` | A `22'` coin (receive 0, hinted) and the card's first UTXO, each starting a covenant in one output of 1 KAS with change to change 0, finished by the SDK: the budget of KCC-3's redeem, 10, and of the card's program, ten times its signature operations |

The coins' outpoints are the tests' (`[n; 32]:n`), not the chain's: a
reply here verifies and finalizes, and a node would not find its inputs.

A key source in a bundle is written as rusty-kaspa writes it,
`{"keyFingerprint":…,"derivationPath":…}`; every reader takes the two
members in either order. The bundles built here and the unit's replies to
them read back through rusty-kaspa 2.1.0's own crate to the same bytes
(`kassigner-kaspa`'s `the_sdks_bundles_read_back_as_upstream_writes_them`),
and the safe JSON files through the WASM SDK's own serializer, each id the
one upstream computes (`the_sdks_safe_json_reads_back_as_upstream_writes_it`).
The card's two finished spends pass rusty-kaspa's script engine as consensus
runs it (`kassigner-protocol`'s
`the_sdks_finished_card_spends_pass_the_engine`), and the five finished
covenant transactions pass its covenant rule and its engine under the
compute budgets they commit, with the ids, storage masses and minimum fees
upstream computes (`the_sdks_finished_covenant_transactions_pass_upstream`).
