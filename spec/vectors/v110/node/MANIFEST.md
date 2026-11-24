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

# The node vectors

A node's wRPC as the SDK speaks it, for the tests of layers that cannot
link a node: `kassigner-sdk-host`'s, the browser package's `check/check.mjs`
and the native bindings' `check/check.py` and `check/check.swift`. Each
call is in both of the node's encodings: `.borsh`, a binary frame on the
`--rpclisten-borsh` port; `.json`, a text frame on the `--rpclisten-json`
port. Every request carries id 7, and every reply answers it.

## Where they come from

`crates/kassigner-kaspa/tests/wrpc.rs`, `the_node_vectors_are_current`.
The requests are the SDK's, each shown by that file to read on a node
(workflow-rpc 0.18.0's framing and the request types' deserializers at
rusty-kaspa `01b532e8`) as the request upstream builds for the same values;
in Borsh, byte for byte what upstream's client sends. The replies are
written by the response types' serializers and workflow-rpc's server
framing at the same versions.

`single.submit.*` come from `crates/kassigner-sdk-host/tests/node.rs`,
`a_signed_transaction_goes_to_a_node`: the SDK's single-signature vector
(`../sdk/single.reply.abandon12`) finished and framed. `wrpc.rs` reads them
back as a node and finds the transaction id the SDK computed.

With `KASSIGNER_NODE_VECTORS=write` the two tests write the files; without
it, they compare every file here with what the code makes.

`kaspad/` holds a live node's answers to the SDK's requests, captured as
they arrived: kaspad 2.1.0, built from the pinned rev, on mainnet with
`--utxoindex` and no peers. In `wrpc.rs`,
`a_live_kaspad_frames_as_these_tests_do` reads each as upstream's client
does and writes it again as its own node does, byte for byte the same, so
every reply above is one a node makes. `kassigner-sdk-host`'s
`tests/node.rs` (`a_live_kaspads_answers_read`) reads them through the SDK.
The tests do not write these; they are captured again only for a new node
release.

| File | What |
|------|------|
| `server_info.request.*` / `.reply.*` | `getServerInfo`; the reply of a mainnet node 2.1.0 with a UTXO index, not yet synced |
| `fee_estimate.request.*` / `.reply.*` | `getFeeEstimate`; a priority bucket, two normal, one low |
| `utxos.request.*` / `.reply.*` | `getUtxosByAddresses` for five addresses, every version on every network; six coins, one of each address with a covenant id on the second, one with no address, amounts from 0 to `u64::MAX` sompi |
| `submit.request.*` | `submitTransaction` of a two-in, two-out transaction of the test's, its storage mass committed |
| `submit.reply.*` | The id a node answers with, `ab` × 32 |
| `submit.error.*` | A node refusing a transaction: `Rejected transaction …: transaction … is an orphan where orphan is disallowed`; in Borsh what the method returned, a `Result`'s error, under the call's op |
| `single.submit.request.*` | `submitTransaction` of the SDK's finished single-signature vector |
| `single.submit.id` | That transaction's id, hex, as the SDK computed it |
| `kaspad/server_info.reply.*` | A live kaspad 2.1.0 on mainnet, unsynced, with a UTXO index |
| `kaspad/fee_estimate.reply.*` | Its fee estimate |
| `kaspad/utxos.reply.*` | Its answer for the first two addresses above: no coins |
| `kaspad/single.submit.error.*` | Its refusal of the SDK's finished single-signature vector as it was when captured, an orphan on a node with no chain, under the id in `kaspad/single.submit.id` |
| `kaspad/single.submit.id` | That transaction's id, hex: `single.submit.id` as it was when the node was asked, kept here since that vector's fee changed |
| `kaspad/no_op.error.borsh` | A request for op 0, which no node serves: `RPC method not found`, an error with no op |

The coins and transactions are the tests', not the chain's.
