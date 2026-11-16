<!--
// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
-->

# KasSigner SDK

Everything a wallet needs to use a KasSigner unit as its signer. The wallet
stays watch-only: the SDK holds no seed, and cannot reach the one crate that
does. A test checks it.

## The round trip

A unit is air-gapped. Everything it knows arrives as data it reads, and
everything it says leaves as data it shows. A wallet does five things:

1. **Import** what the unit hands over: a kpub, a cosigner's file, a multisig
   descriptor, a `22'` address, a signed message.
2. **Watch** the addresses and scripts that follow from it.
3. **Request** a signature on a transaction. The request is checked against
   the unit's own rules first, so a refusal shows in the wallet, not on the
   unit.
4. **Transport** the request in the unit's frames, and put the reply back
   together from the frames the unit shows.
5. **Finish**: signatures checked, cosigners' replies merged, the transaction
   ready to send.

The same calls cover multisig, rusty-kaspa's PSKB bundles, messages to sign,
and Time-Locked Savings cards. Nothing is kept between calls: what to store,
and which node to talk to, are the wallet's.

## Packages

| Crate | For | Build |
| --- | --- | --- |
| `kassigner-sdk` | Rust, `no_std`, no allocation: the caller's buffers | `cargo build -p kassigner-sdk` |
| `kassigner-sdk-host` | Rust with an allocator: owned values in and out | `cargo build -p kassigner-sdk-host` |
| `kassigner-sdk-wasm` | JavaScript and TypeScript, in the browser | `sh crates/kassigner-sdk-wasm/build.sh`, into `pkg/` |
| `kassigner-sdk-ffi` | Swift, Kotlin and Python, over a C ABI | `sh crates/kassigner-sdk-ffi/build.sh`, into `out/` |

The browser package comes in two builds. `build.sh` alone makes the full
one, into `pkg/`: everything in this README. `build.sh watch` makes a
watch-only one, into `pkg-watch/`: imports, addresses, coins, signed messages,
cards, codes and a node's reads, and nothing that builds, checks or sends a
transaction. The test tool at kassigner.org is built on the watch-only one.
The full tool, in its own repository, is built on the full one, for you to
build and run at your own risk.

Build from the repository root, once `fork.sh` has run
([CONTRIBUTING.md](../../CONTRIBUTING.md#set-up)). Each script lists what it
needs at its top, and prints the SHA-256 of what it built, to compare with
another build of the same commit. The bindings use
the same names in each language's own style: `readImport` in JavaScript,
`read_import` in Python.

Each release carries the browser package and the bindings already built, in
`kassigner-sdk-<version>-web.tar.gz` and
`kassigner-sdk-<version>-bindings.tar.gz`, both in the release's signed
`SHA256SUMS`.

## A first round trip, in JavaScript

```js
import init, * as sdk from "./pkg/kassigner_sdk.js";
await init();

const profile = sdk.Profile.esp32s3(); // the bounds every unit shares
const rates = sdk.Rates.mainnet();

// 1. Import: the kpub the unit showed, as the text its code holds.
// `account` is undefined when what was read is not a kpub: check `kind`.
const account = sdk.readImport(new TextEncoder().encode(kpub)).account;
const receive0 = account.address(0, 0);

// 3. Request: a coin from your node, a payment, the change back home.
const b = new sdk.RequestBuilder();
b.spendAccount(account, 0, 0, new sdk.Coin(txId, 0, 300_000_000n));
b.pay(destination, 100_000_000n);
b.changeToAccount(account, 1, 0);
const request = b.build(100n, rates, profile); // sompi a gram: 100 is the minimum

// 4. Transport: show each frame in turn, for the unit's camera.
const codes = sdk.codes(request.bytes, "kspt", profile);
for (let k = 0; k < codes.frames; k++) show(codes.svg(k, 4), codes.periodMs);

// The unit reviews, signs, and shows its reply. Read it back:
const reader = new sdk.Reader(profile, 225); // 225: the bytes a frame carries, on every unit
for (const frame of framesFromYourCamera) if (reader.take(frame).whole) break;
const reply = reader.collect();

// 5. Finish: the reply checked against the request, ready to send.
const done = sdk.finalizeReply(request.bytes, reply, false, rates, profile);
// done.submitJson: a node's wRPC submitTransaction
// done.restJson:   kaspa-rest-server's POST /transactions
```

A failure throws an `Error` named as the unit names it, such as
`Insufficient { have: 5, need: 7 }`.

## Good to know

- **The unit's rules, not a copy of them.** Every format and limit is read
  from the same crates the unit reads, so the wallet and the unit cannot
  disagree.
- **One profile for every unit**, the P4 included.
- **Mainnet only**, like the units.
- **The node is yours.** `Node` writes a node's wRPC calls and reads its
  answers, in Borsh or JSON: unspent outputs, fee estimates, sending the
  transaction. Which node, and the connection to it, are the wallet's.
- **Test vectors.** `spec/vectors/v110/sdk/` holds requests and the units'
  signed replies; `spec/vectors/v110/node/` a node's messages. Test your
  integration against them, byte for byte.

## Licence

[MPL-2.0](LICENSE): any wallet can link the SDK, and changes to its own files
stay public. The browser package and the native library each ship with their
`LICENSE` and `THIRD_PARTY_NOTICES`.
