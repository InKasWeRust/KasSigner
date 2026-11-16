// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// The browser package under Node.js, run by `build.sh`: the native
// binding's `check.py` round over the SDK's vectors and a node's wRPC over
// the node vectors, every value as an app passes and gets it.
//
//   node check.mjs <the package's dir> <spec/vectors/v110>

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [pkg, vectors] = process.argv.slice(2);
const sdk = await import(pathToFileURL(join(pkg, "kassigner_sdk.js")).href);
sdk.initSync({ module: readFileSync(join(pkg, "kassigner_sdk_bg.wasm")) });

const vector = (dir, name) => new Uint8Array(readFileSync(join(vectors, dir, name)));
const v = (name) => vector("sdk", name);
const same = (a, b) => a.length === b.length && a.every((x, k) => x === b[k]);
function check(ok, what) {
  if (!ok) throw new Error(`check failed: ${what}`);
}
function throws(f, name) {
  try {
    f();
  } catch (e) {
    check(e.message === name || e.message.startsWith(name), `${name}, not ${e.message}`);
    return;
  }
  throw new Error(`check failed: ${name} was not thrown`);
}

const ABANDON12_KPUB44 =
  "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8";
const KAS = 100_000_000n;
const p = sdk.Profile.esp32s3();
const rates = sdk.Rates.mainnet();
check(p.maxInputs === 32 && p.maxFrames === 64, "the ESP32-S3 profile");
check(
  sdk.codes(new Uint8Array(300), "opaque", p).periodMs === 600 &&
    sdk.codes(new Uint8Array(1000), "opaque", p).periodMs === 850,
  "the frame period follows the version",
);

// Import and addresses.
const i = sdk.readImport(new TextEncoder().encode(ABANDON12_KPUB44));
check(i.kind === "account" && i.account !== undefined, "an account imported");
const a = i.account;
const receive0 = a.address(0, 0);
check(receive0.startsWith("kaspa:q"), receive0);
check(sdk.addressOfScript(a.script(0, 0)) === receive0, "the address of a script");
check(same(sdk.scriptOfAddress(receive0), a.script(0, 0)), "the script of an address");

// A request: the vector's, byte for byte.
const single = v("single.request");
const s = sdk.summary(single, p);
check(s.inputs === 2 && s.totalIn === 5n * KAS && s.outputs.length === 2, "the summary");
const coin = (n, amount) => new sdk.Coin(n.toString(16).padStart(2, "0").repeat(32), n, amount);
const b = new sdk.RequestBuilder();
b.spendAccount(a, 0, 0, coin(1, 3n * KAS));
b.spendAccount(a, 1, 3, coin(2, 2n * KAS));
b.payScript(s.outputs[0].script, 4n * KAS);
b.changeToAccount(a, 1, 4);
const r = b.build(100n, rates, p);
check(same(r.bytes, single), "the builder builds the vector");
check(r.signatures === 2 && r.change === s.outputs[1].value, "its change");

// Its codes back through the reader, each matrix rasterized and read by
// the unit's decoder.
const c = sdk.codes(single, "kspt", p);
const reader = new sdk.Reader(p, 225);
for (let k = c.frames - 1; k >= 0; k--) {
  const frame = c.bytes(k);
  const m = c.matrix(k);
  const scale = 4, quiet = 4, side = (m.size + 2 * quiet) * scale;
  const px = new Uint8Array(side * side).fill(0xff);
  for (let y = 0; y < m.size; y++)
    for (let x = 0; x < m.size; x++)
      if (m.modules[y * m.size + x])
        for (let dy = 0; dy < scale; dy++)
          px.fill(0, ((y + quiet) * scale + dy) * side + (x + quiet) * scale,
            ((y + quiet) * scale + dy) * side + (x + quiet) * scale + scale);
  check(same(sdk.decodeQr(px, side, side, 8), frame), `frame ${k} decodes`);
  check(reader.take(frame).whole === (k === 0), `frame ${k} taken`);
}
check(same(reader.collect(), single), "the reader reassembles the request");
check(reader.received() === (c.bare ? 0n : (1n << BigInt(c.frames)) - 1n), "the reader says every frame is in");
check(c.svg(0, 4).startsWith("<svg"), "an SVG");

// The reply checked and finished, with every submit body.
const rep = v("single.reply.abandon12");
const ck = sdk.readReply(single, rep, p);
check(ck.signatures === 2 && ck.present === undefined && ck.complete, "the reply checked");
const f = sdk.finalizeReply(single, rep, false, rates, p);
check(f.id.length === 64 && f.fee === s.fee, "the reply finished");
check(f.submitJson.includes(`"mass":${f.storageMass}`), "the JSON request commits the mass");
check(f.restJson.includes('"amount":400000000') && !f.restJson.includes('"mass"'), "the REST body");
check(f.submitBorsh.length > 0, "the Borsh request");
throws(() => sdk.readReply(v("sweep.request"), rep, p), "NotTheRequest");
throws(() => sdk.finalizeReply(v("sweep.request"), rep, false, rates, p), "NotTheRequest");

// As a bundle, its coins with their entries: the vector, and its reply
// finishes to the KSPT's transaction. A coin without its entry is refused.
const entered = (n, amount) =>
  sdk.Coin.withEntry(n.toString(16).padStart(2, "0").repeat(32), n, amount, 90000000n + BigInt(n), false);
check(entered(1, KAS).blockDaaScore === 90000001n && entered(1, KAS).isCoinbase === false, "a coin's entry");
check(coin(1, KAS).blockDaaScore === undefined, "a coin without one");
const bb = new sdk.RequestBuilder();
bb.spendAccount(a, 0, 0, entered(1, 3n * KAS));
bb.spendAccount(a, 1, 3, entered(2, 2n * KAS));
bb.payScript(s.outputs[0].script, 4n * KAS);
bb.changeToAccount(a, 1, 4);
const rb = bb.buildBundle(100n, rates, p);
check(same(rb.bytes, v("single.bundle")), "the builder builds the bundle vector");
check(rb.fee === r.fee && rb.change === r.change, "the bundle's fee and change");
const brep = v("single.bundle.reply.abandon12");
check(sdk.readBundle(rb.bytes, brep, p).complete, "the bundle reply checked");
check(sdk.finalizeBundle(rb.bytes, brep, false, rates, p).id === f.id, "the KSPT's transaction");
throws(() => b.buildBundle(100n, rates, p), "NoEntry { coin: 0 }");

// And as the WASM SDK's safe JSON: the vector. Signed by a wallet, it
// finishes to the KSPT's transaction; unsigned, it is refused.
const rs = bb.buildSafeJson(100n, rates, p);
check(same(rs.bytes, v("single.safe.json")), "the builder writes the safe JSON vector");
check(rs.fee === r.fee && rs.change === r.change, "the safe JSON's fee and change");
check(JSON.parse(rs.text).inputs[0].utxo.blockDaaScore === "90000001", "a decimal string");
const signedJson = new TextDecoder().decode(v("single.safe.signed.json"));
check(sdk.finalizeSafeJson(rs.text, signedJson, false, rates, p).id === f.id, "the KSPT's transaction");
throws(() => sdk.finalizeSafeJson(rs.text, rs.text, false, rates, p), "Unsigned { input: 0 }");

// A multisig: one reply, then two merged and finished.
const multi = v("multisig.request");
const [first, second] = [v("multisig.reply.abandon12"), v("multisig.reply.zoo12")];
const mc = sdk.readReply(multi, first, p);
check(mc.present === 1 && mc.required === 2 && !mc.complete, "one cosigner of two");
const merged = sdk.mergeReplies(multi, [first, second], p);
check(sdk.readReply(multi, merged, p).complete, "merged complete");
const fm = sdk.finalizeReply(multi, merged, false, rates, p);
check(fm.unlocks.length === 1 && fm.unlocks[0].length > 2 * 132, "two signatures and the redeem");

// A wallet's bundle with a group hint: prepared as the vector, two
// replies merged.
const g = sdk.Group.fromDescriptor(
  "multi_hd45(2,kpub2JKepGqGb3usUsEfD7JgwbFZav8Nu2z4dBZQ42hg8JUGnCbLUb9phbpZW2TQuk2DmayefGMiVzCK7EL9hPbr2K2vVzSk8SpuUwwqTLq8y14," +
    "kpub2JG8myov28wfetFRquaJtuTJpL3jhYnBhu2V6ZuwHnDqPBAoyqgJKkQiba4wLfU9JcsNBBoBTm7zPtk1Nv4Nn36tUkoZWGUXjWn1aJCajdW," +
    "kpub2HgQUMVzkWe8YCDJDEg5zdMAiKnFE3inHgrv7VRUCxKanfXpGnPpSut8MQUHYBcSFKxDhNJKCFJTy6BSdUhXKd1VbrFdFRrJ2thq3ZJfPUU)",
);
check(g.required === 2 && g.total === 3, "a 2-of-3");
const hints = new sdk.Hints();
hints.group(0, g, 0, 0, 0, []);
const bench = new Uint8Array(readFileSync(join(vectors, "../v107/site/pskb_multisig.bin")));
const prepared = sdk.prepareBundle(bench, hints, p);
check(same(prepared.bytes, v("pskb_multisig.request")), "prepared as the vector");
const [bfirst, bsecond] = [v("pskb_multisig.reply.abandon12"), v("pskb_multisig.reply.zoo12")];
check(!sdk.readBundle(prepared.bytes, bfirst, p).complete, "one bundle reply");
const bmerged = sdk.mergeBundles(prepared.bytes, [bfirst, bsecond], p);
check(sdk.readBundle(prepared.bytes, bmerged, p).complete, "bundles merged");
sdk.finalizeBundle(prepared.bytes, bmerged, false, rates, p);

// Signed copies with no request, KSPT and bundle: read, merged (a cosigner
// in two copies kept once) and finished to the request's transaction.
const kfirst = v("multisig.reply.abandon12");
check(!sdk.readSignedReply(kfirst, p).complete, "one signed copy");
const kmerged = sdk.mergeSignedReplies([kfirst, v("multisig.reply.zoo12")], p);
check(same(sdk.mergeSignedReplies([kmerged, kfirst], p), kmerged), "a cosigner held once");
check(
  sdk.finalizeSignedReply(kmerged, false, rates, p).id ===
    sdk.finalizeReply(v("multisig.request"), kmerged, false, rates, p).id,
  "the request's transaction"
);
throws(() => sdk.mergeSignedReplies([kfirst, v("single.reply.abandon12")], p), "NotTheRequest");
const bsigned = sdk.mergeSignedBundles([bfirst, bsecond, bfirst], p);
check(sdk.readSignedBundle(bsigned, p).complete, "signed bundles merged");
check(
  sdk.finalizeSignedBundle(bsigned, false, rates, p).id ===
    sdk.finalizeBundle(prepared.bytes, bmerged, false, rates, p).id,
  "the bundle's transaction"
);
check(sdk.bundleSummary(bsigned, p).outputs.length > 0, "a bundle summed up");

// A signed record.
const record = v("message.record");
const ver = sdk.verifyMessage(record);
check(ver.record.text === "kassigner.org login", "a signed record");
sdk.verifyMessageAgainst(record, "kassigner.org login", ver.record.address);
check(sdk.messageCodes("hello, unit", p).bare, "a text's codes");
check(sdk.readImport(record).kind === "signedMessage", "a record imported");

// A Time-Locked Savings card: its backup line read and written again, the
// card made again, the owner's key found. Its claim is the vectors' KSPT
// and bundle, its replies finish to the vectors' transactions; the safe
// JSON and impossible dates and times are refused.
const line = new TextDecoder().decode(v("savings.backup"));
const card = sdk.Card.fromBackup(line);
check(card.backup() === line, "the backup line written again");
check(card.unlockMs === 1798761600000n, "the moment it unlocks");
check(card.unlockDay === 1 && card.unlockMonth === 1 && card.unlockYear === 2027, "its day");
check(card.unlockHour === 0 && card.unlockMinute === 0, "its time of day");
check(card.owner() === receive0 && card.address().startsWith("kaspa:p"), "its owner and address");
check(sdk.Card.savings(card.owner(), card.recovery(), 1, 1, 2027, 0, 0).backup() === line, "made again");
const eve = sdk.Card.savings(card.owner(), undefined, 31, 12, 2026, 23, 59);
check(eve.unlockHour === 23 && eve.unlockMinute === 59, "a time of day");
check(eve.unlockMs === card.unlockMs - 60000n, "a minute before");
check(eve.backup().includes(",31/12/2026 23:59,"), "its line, to the minute");
const signer = card.signer(a, 20);
check(signer.index === 0 && !signer.recovers, "the owner's key found");
const to = sdk.summary(v("savings.request"), p).outputs[0].address;
const cb = new sdk.RequestBuilder();
cb.lockUntil(card.unlockMs);
cb.spendCardAs(card, entered(1, 5n * KAS), a, 0);
cb.spendCard(card, entered(2, 3n * KAS));
cb.sweepTo(to);
const claim = cb.build(100n, rates, p);
check(same(claim.bytes, v("savings.request")), "the claim, the vector's KSPT");
const claimBundle = cb.buildBundle(100n, rates, p);
check(same(claimBundle.bytes, v("savings.bundle")), "the claim, the vector's bundle");
for (const [seed, entry] of [["abandon12", "claim"], ["zoo12", "recover"]]) {
  const fk = sdk.finalizeReply(claim.bytes, v(`savings.reply.${seed}`), false, rates, p);
  const fb = sdk.finalizeBundle(claimBundle.bytes, v(`savings.bundle.reply.${seed}`), false, rates, p);
  const signed = JSON.parse(new TextDecoder().decode(v(`savings.${entry}.signed.json`)));
  check(fk.id === signed.id && fb.id === fk.id, `the ${entry} finished as the SDK finished it`);
}
throws(() => cb.buildSafeJson(100n, rates, p), "CardInSafeJson { coin: 0 }");
throws(() => sdk.Card.savings(card.owner(), undefined, 29, 2, 2027, 0, 0), "Date");
throws(() => sdk.Card.savings(card.owner(), undefined, 1, 1, 2027, 24, 0), "Date");
throws(() => sdk.Card.savings(card.owner(), undefined, 1, 1, 2027, 0, 60), "Date");

// Covenants, as the vectors: an output starts one or continues a coin's,
// named by the coin whose input authorizes it; one ends only on the
// request's word; a bundle carries no bound output.
const COVENANT = "5a".repeat(32);
const covenantScript = new Uint8Array([0xaa, 0x20, ...new Array(32).fill(0x77), 0x87]);
const covenantBuilder = (bound, outputs) => {
  const cv = new sdk.RequestBuilder();
  for (const n of [1, 2]) {
    const c = sdk.Coin.withEntry(n.toString(16).padStart(2, "0").repeat(32), n, 1000n * KAS, 0n, false);
    cv.spendAccount(a, 0, n, n === 1 && bound !== undefined ? c.boundTo(bound) : c);
  }
  for (let k = 0; k < outputs; k++) cv.payScript(covenantScript, 100n * KAS);
  cv.changeToAccount(a, 1, 0);
  return cv;
};
const start = covenantBuilder(undefined, 2);
start.startCovenant(0, 0);
start.startCovenant(1, 0);
const started = start.build(100n, rates, p);
check(same(started.bytes, v("covenant.start.request")), "a covenant started, the vector's KSPT");
const cs = sdk.summary(started.bytes, p);
const made = cs.outputs[0].covenantId;
check(cs.version === 1 && made !== undefined && made.length === 64, "version 1, the new covenant's id");
check(
  cs.outputs[1].covenantId === made &&
    cs.outputs[0].authorizingInput === 0 &&
    cs.outputs[1].authorizingInput === 0 &&
    cs.outputs[2].covenantId === undefined &&
    cs.outputs[2].authorizingInput === undefined,
  "both outputs of the one covenant, the change not bound",
);
check(sdk.summary(single, p).version === 0 && s.outputs[0].covenantId === undefined, "a plain send");
const fc = sdk.finalizeReply(started.bytes, v("covenant.start.reply.abandon12"), false, rates, p);
check(fc.fee === started.fee, "the fee the request found");
check(
  fc.submitJson.split('"computeBudget":10').length - 1 === 2 && fc.submitJson.includes('"sigOpCount":0'),
  "each input's compute budget",
);
check(start.buildSafeJson(100n, rates, p).text.includes('"version":1'), "the safe JSON, version 1");
throws(() => start.buildBundle(100n, rates, p), "CovenantInBundle");

const ends = covenantBuilder(COVENANT, 1);
throws(() => ends.build(100n, rates, p), "CovenantBound { coin: 0 }");
ends.endCovenants();
check(sdk.summary(ends.build(100n, rates, p).bytes, p).version === 0, "ended on the request's word");

const goOn = covenantBuilder(COVENANT, 1);
goOn.continueCovenant(0, 0);
const continued = goOn.build(100n, rates, p);
check(same(continued.bytes, v("covenant.continue.request")), "a covenant continued, the vector's KSPT");
const cc = sdk.summary(continued.bytes, p).outputs[0];
check(cc.covenantId === COVENANT && cc.authorizingInput === 0, "under its coin's id");
throws(() => goOn.startCovenant(1, 0), "BadBinding { output: 1 }");
goOn.continueCovenant(0, 1);
throws(() => goOn.build(100n, rates, p), "BadBinding { output: 0 }");

// A refusal, by the SDK's name.
throws(() => new sdk.RequestBuilder().build(100n, rates, p), "Empty");

// ── A node ───────────────────────────────────────────────────────────────────

const n = (name) => vector("node", name);
const addresses = new TextDecoder()
  .decode(n("utxos.request.json"))
  .match(/kaspa[a-z]*:[a-z0-9]+/g);
check(addresses.length === 5, "the five addresses");
const borsh = new sdk.Node("borsh");
const json = new sdk.Node("json");
check(borsh.defaultPort() === 17110 && json.defaultPort() === 18110, "ports");
throws(() => new sdk.Node("grpc"), "no wRPC encoding");

// Requests: bytes for Borsh, text for JSON, each the vector.
const text = (bytes) => new TextDecoder().decode(bytes);
for (const [node, ext, as] of [[borsh, "borsh", (x) => x], [json, "json", text]]) {
  const want = (name) => as(n(`${name}.request.${ext}`));
  const eq = (got, w) => (typeof w === "string" ? got === w : got instanceof Uint8Array && same(got, w));
  check(eq(node.getServerInfo(7), want("server_info")), `getServerInfo, ${ext}`);
  check(eq(node.getFeeEstimate(7), want("fee_estimate")), `getFeeEstimate, ${ext}`);
  check(eq(node.getUtxosByAddresses(7, addresses), want("utxos")), `getUtxosByAddresses, ${ext}`);
  check(eq(node.submitTransaction(7, f), as(n(`single.submit.request.${ext}`))), `submitTransaction, ${ext}`);
  throws(() => node.getUtxosByAddresses(7, [addresses[0], "kaspa:nope"]), "Address { index: 1");
}

// Replies, from every form a WebSocket hands over.
const forms = (bytes, isText) =>
  isText ? [text(bytes), bytes] : [bytes, bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.length)];
for (const [node, ext] of [[borsh, "borsh"], [json, "json"]]) {
  for (const m of forms(n(`utxos.reply.${ext}`), ext === "json")) {
    const ans = node.read(m);
    check(ans.id === 7 && ans.kind === "reply" && ans.call === "getUtxosByAddresses", `utxos, ${ext}`);
    const u = ans.utxos;
    check(u.length === 6 && u[1].amount === 18446744073709551615n, "a u64 of sompi, exact");
    check(u[0].address === addresses[0] && u[5].address === undefined, "the addresses");
    check(u[1].covenantId === "c0".repeat(32) && u[2].isCoinbase, "a covenant, a coinbase");
    const cn = u[0].coin();
    check(cn.txId === "01".repeat(32) && cn.index === 1 && cn.amount === 123456789n, "a coin");
    check(ans.serverInfo === undefined && ans.error === undefined, "nothing else");
  }
  const info = node.read(n(`server_info.reply.${ext}`)).serverInfo;
  check(info.network === "mainnet" && info.rpcApiVersion === 1 && info.hasUtxoIndex && !info.isSynced, `info, ${ext}`);
  check(info.virtualDaaScore === 475165565n && info.serverVersion === "2.1.0", "the score, the version");
  const fe = node.read(n(`fee_estimate.reply.${ext}`)).feeEstimate;
  check(fe.priority.feerate === 1.0000001 && fe.priority.feeRate === 2n, `fees, ${ext}`);
  check(fe.normal.length === 2 && fe.low[0].estimatedSeconds === 60, "the buckets");
  check(node.read(n(`submit.reply.${ext}`)).transactionId === "ab".repeat(32), `submitted, ${ext}`);
  const refused = node.read(n(`submit.error.${ext}`));
  check(refused.kind === "error" && refused.error.includes("is an orphan where orphan is disallowed"), `refused, ${ext}`);
}
throws(() => borsh.read(n("utxos.reply.json")), "Malformed { at: ");

console.log("kassigner_sdk", sdk.version(), "through JavaScript: the round holds");
