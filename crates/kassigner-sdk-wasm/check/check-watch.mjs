// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// The watch-only browser package under Node.js, run by `build.sh watch`:
// what it keeps works, and nothing that builds, checks, finishes or sends a
// transaction is in it.
//
//   node check-watch.mjs <the package's dir> <spec/vectors/v110>

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [pkg, vectors] = process.argv.slice(2);
const sdk = await import(pathToFileURL(join(pkg, "kassigner_sdk.js")).href);
sdk.initSync({ module: readFileSync(join(pkg, "kassigner_sdk_bg.wasm")) });

function check(ok, what) {
  if (!ok) throw new Error(`check failed: ${what}`);
}
const same = (a, b) => a.length === b.length && a.every((x, k) => x === b[k]);

const ABANDON12_KPUB44 =
  "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8";
const KAS = 100_000_000n;
const p = sdk.Profile.esp32s3();
check(p.maxInputs === 32 && p.maxFrames === 64, "the ESP32-S3 profile");

// Import and addresses.
const i = sdk.readImport(new TextEncoder().encode(ABANDON12_KPUB44));
check(i.kind === "account" && i.account !== undefined, "an account imported");
const a = i.account;
const receive0 = a.address(0, 0);
check(receive0.startsWith("kaspa:q"), receive0);
check(sdk.addressOfScript(a.script(0, 0)) === receive0, "the address of a script");
check(same(sdk.scriptOfAddress(receive0), a.script(0, 0)), "the script of an address");

// A mining reward waits to mature.
const mined = 90_000_000n;
const reward = sdk.Coin.withEntry("01".repeat(32), 1, 3n * KAS, mined, true);
check(reward.spendableAt(mined + 999n) === false, "a mining reward not yet matured");
check(reward.spendableAt(mined + 1_000n) === true, "a mining reward matured");

// A signed message, checked as a unit checks one.
const record = new Uint8Array(readFileSync(join(vectors, "sdk", "message.record")));
const verified = sdk.verifyMessage(record);
check(verified.record.address.startsWith("kaspa:q"), "a signed message verified");

// A card made, backed up and read back, its backup as the codes a unit reads.
const card = sdk.Card.savings(receive0, undefined, 1, 1, 2030, 12, 30);
const line = card.backup();
check(line.startsWith("savings_v1("), line);
const again = sdk.Card.fromBackup(line);
check(again.address() === card.address() && again.owner() === receive0, "a card read back");
check(card.signer(a, 20).index === 0, "the card's key found in the account");
check(sdk.codes(new TextEncoder().encode(line), "opaque", p).frames >= 1, "the backup's codes");

// A node is asked, never told: its reads are here, its submit is not.
const node = new sdk.Node("borsh");
check(node.getServerInfo(1).length > 0, "a node's server info request");
check(node.getUtxosByAddresses(2, [receive0]).length > 0, "a node's coins request");
check(node.submitTransaction === undefined, "Node.submitTransaction is not in the watch-only package");

// Nothing that builds, checks, finishes or sends a transaction.
for (const name of [
  "RequestBuilder", "Request", "Rates", "summary",
  "readReply", "readSignedReply", "mergeReplies", "mergeSignedReplies",
  "finalizeReply", "finalizeSignedReply", "finalizeSafeJson",
  "prepareBundle", "readBundle", "readSignedBundle", "mergeBundles", "mergeSignedBundles",
  "finalizeBundle", "finalizeSignedBundle", "bundleSummary", "Hints", "Prepared", "Checked", "Finalized",
]) {
  check(sdk[name] === undefined, `${name} is not in the watch-only package`);
}

console.log("the watch-only package: it watches, and holds nothing a transaction is made or sent with");
