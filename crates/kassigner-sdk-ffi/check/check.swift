// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// The generated Swift binding through `check.py`'s round, over the SDK's
// vectors (`spec/vectors/v110/sdk/`) and the node vectors (`../node/`).
// `build.sh` compiles it on a Mac into one module with `KasSignerSdk.swift`,
// so the names are used as an app importing `KasSignerSdk` uses them, and
// runs it:
//
//   out/swift-check/check-swift spec/vectors/v110/sdk

import Foundation

let KAS: UInt64 = 100_000_000
let ABANDON12_KPUB44 = "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8"
let GROUP = "multi_hd45(2,"
    + "kpub2JKepGqGb3usUsEfD7JgwbFZav8Nu2z4dBZQ42hg8JUGnCbLUb9phbpZW2TQuk2DmayefGMiVzCK7EL9hPbr2K2vVzSk8SpuUwwqTLq8y14,"
    + "kpub2JG8myov28wfetFRquaJtuTJpL3jhYnBhu2V6ZuwHnDqPBAoyqgJKkQiba4wLfU9JcsNBBoBTm7zPtk1Nv4Nn36tUkoZWGUXjWn1aJCajdW,"
    + "kpub2HgQUMVzkWe8YCDJDEg5zdMAiKnFE3inHgrv7VRUCxKanfXpGnPpSut8MQUHYBcSFKxDhNJKCFJTy6BSdUhXKd1VbrFdFRrJ2thq3ZJfPUU)"

func fail(_ what: String) -> Never {
    FileHandle.standardError.write(Data(("check failed: " + what + "\n").utf8))
    exit(1)
}

func check(_ ok: Bool, _ what: String) {
    if !ok { fail(what) }
}

/// `body` refused by the SDK under `name`, or a name starting with it.
func refused(_ name: String, _ body: () throws -> Void) {
    do {
        try body()
    } catch Fault.Sdk(let message) {
        check(message == name || message.hasPrefix(name), "\(name), not \(message)")
        return
    } catch {
        fail("\(name), not \(error)")
    }
    fail("\(name) was not refused")
}

@main
struct Check {
    static func main() throws {
        let args = CommandLine.arguments
        if args.count != 2 { fail("usage: check-swift <spec/vectors/v110/sdk>") }
        let vectors = URL(fileURLWithPath: args[1])
        let nodes = vectors.deletingLastPathComponent().appendingPathComponent("node")
        func vector(_ name: String) throws -> Data {
            try Data(contentsOf: vectors.appendingPathComponent(name))
        }
        func nodeVector(_ name: String) throws -> Data {
            try Data(contentsOf: nodes.appendingPathComponent(name))
        }

        let p = Profile.esp32s3()
        let rates = Rates.mainnet()
        check(p.maxInputs() == 32 && p.maxFrames() == 64, "the ESP32-S3 profile")
        let light = try codes(payload: Data(count: 300), format: "opaque", profile: p)
        let dense = try codes(payload: Data(count: 1000), format: "opaque", profile: p)
        check(light.periodMs() == 600 && dense.periodMs() == 850, "the frame period follows the version")

        // A node's UTXO as the coin a request spends, its covenant with it.
        let bound = String(repeating: "5a", count: 32)
        let utxo = Utxo(
            address: nil, transactionId: String(repeating: "01", count: 32), index: 1, amount: 3 * KAS,
            scriptVersion: 0, script: Data(), blockDaaScore: 90_000_001, isCoinbase: false, covenantId: bound)
        let coin = utxoCoin(utxo: utxo)
        check(coin.covenantId == bound && coin.blockDaaScore == 90_000_001 && coin.isCoinbase == false,
              "a UTXO's covenant goes with its coin")

        // Import and addresses.
        let imported = try readImport(bytes: Data(ABANDON12_KPUB44.utf8))
        check(imported.kind == "account", "an account imported, not \(imported.kind)")
        guard let a = imported.account else { fail("no account in the import") }
        let receive0 = try a.address(chain: 0, index: 0)
        check(receive0.hasPrefix("kaspa:q"), receive0)
        let script0 = try a.script(chain: 0, index: 0)
        check(try addressOfScript(script: script0) == receive0, "the address of a script")
        check(try scriptOfAddress(address: receive0) == script0, "the script of an address")
        check(try a.publicKey(chain: 0, index: 0).count == 64, "a public key, hex")

        // The vector's request, built byte for byte.
        let single = try vector("single.request")
        let s = try summary(kspt: single, profile: p)
        check(s.inputs == 2 && s.totalIn == 5 * KAS && s.outputs.count == 2, "the summary")
        let b = RequestBuilder()
        try b.spendAccount(account: a, chain: 0, index: 0,
                           coin: Coin(txId: String(repeating: "01", count: 32), index: 1, amount: 3 * KAS))
        try b.spendAccount(account: a, chain: 1, index: 3,
                           coin: Coin(txId: String(repeating: "02", count: 32), index: 2, amount: 2 * KAS))
        b.payScript(script: s.outputs[0].script, amount: 4 * KAS)
        b.changeToAccount(account: a, chain: 1, index: 4)
        let built = try b.build(feeRate: 100, rates: rates, profile: p)
        check(built.bytes == single, "the builder builds the vector")
        check(built.signatures == 2 && built.change == s.outputs[1].value, "its change")

        // Its codes through the reader, each matrix rasterized through the
        // unit's decoder.
        let c = try codes(payload: single, format: "kspt", profile: p)
        let reader = Reader(profile: p, slot: 225)
        for k in (0..<Int(c.frames())).reversed() {
            let frame = try c.bytes(index: UInt32(k))
            let m = try c.matrix(index: UInt32(k))
            let size = Int(m.size), modules = [UInt8](m.modules)
            check(modules.count == size * size, "frame \(k)'s matrix")
            let scale = 4, quiet = 4, side = (size + 2 * quiet) * scale
            var px = [UInt8](repeating: 0xff, count: side * side)
            for y in 0..<size {
                for x in 0..<size where modules[y * size + x] != 0 {
                    for dy in 0..<scale {
                        let row = ((y + quiet) * scale + dy) * side + (x + quiet) * scale
                        for dx in 0..<scale { px[row + dx] = 0 }
                    }
                }
            }
            let decoded = try decodeQr(pixels: Data(px), width: UInt32(side), height: UInt32(side), denom: 8)
            check(decoded == frame, "frame \(k) decodes")
            let t = try reader.take(code: frame)
            check(t.whole == (k == 0), "frame \(k) taken: \(t.status)")
        }
        check(try reader.collect() == single, "the reader reassembles the request")
        check(reader.received() == (c.bare() ? 0 : (UInt64(1) << UInt64(c.frames())) - 1), "the reader says every frame is in")
        check(try c.svg(index: 0, module: 4).hasPrefix("<svg"), "an SVG")

        // The reply checked and finished; another request's refused.
        let rep = try vector("single.reply.abandon12")
        let ck = try readReply(request: single, reply: rep, profile: p)
        check(ck.signatures == 2 && ck.present == nil && ck.complete, "the reply checked")
        let f = try finalizeReply(request: single, reply: rep, allowOrphan: false, rates: rates, profile: p)
        check(f.id.count == 64 && f.fee == s.fee, "the reply finished")
        check(f.submitJson.contains("\"mass\":\(f.storageMass)"), "the JSON request commits the mass")
        check(f.restJson.contains("\"amount\":400000000") && !f.restJson.contains("\"mass\""), "the REST body")
        check(!f.submitBorsh.isEmpty, "the Borsh request")
        let sweep = try vector("sweep.request")
        refused("NotTheRequest") { _ = try readReply(request: sweep, reply: rep, profile: p) }
        refused("NotTheRequest") {
            _ = try finalizeReply(request: sweep, reply: rep, allowOrphan: false, rates: rates, profile: p)
        }

        // As a bundle, as the vector, finishing to the same transaction; a
        // coin without its entry refused.
        let bb = RequestBuilder()
        try bb.spendAccount(account: a, chain: 0, index: 0,
                            coin: Coin(txId: String(repeating: "01", count: 32), index: 1, amount: 3 * KAS,
                                       blockDaaScore: 90_000_001, isCoinbase: false))
        try bb.spendAccount(account: a, chain: 1, index: 3,
                            coin: Coin(txId: String(repeating: "02", count: 32), index: 2, amount: 2 * KAS,
                                       blockDaaScore: 90_000_002, isCoinbase: false))
        bb.payScript(script: s.outputs[0].script, amount: 4 * KAS)
        bb.changeToAccount(account: a, chain: 1, index: 4)
        let rb = try bb.buildBundle(feeRate: 100, rates: rates, profile: p)
        check(try rb.bytes == vector("single.bundle"), "the builder builds the bundle vector")
        check(rb.fee == built.fee && rb.change == built.change, "the bundle's fee and change")
        let brep = try vector("single.bundle.reply.abandon12")
        check(try readBundle(request: rb.bytes, reply: brep, profile: p).complete, "the bundle reply checked")
        let fb = try finalizeBundle(request: rb.bytes, reply: brep, allowOrphan: false, rates: rates, profile: p)
        check(fb.id == f.id, "the KSPT's transaction")
        refused("NoEntry { coin: 0 }") { _ = try b.buildBundle(feeRate: 100, rates: rates, profile: p) }

        // In the safe JSON, as the vector: finished once a wallet signed
        // it, refused unsigned.
        let rs = try bb.buildSafeJson(feeRate: 100, rates: rates, profile: p)
        check(try rs.bytes == vector("single.safe.json"), "the builder writes the safe JSON vector")
        check(rs.fee == built.fee && rs.change == built.change, "the safe JSON's fee and change")
        let safe = String(decoding: rs.bytes, as: UTF8.self)
        let signedData = try vector("single.safe.signed.json")
        let signed = String(decoding: signedData, as: UTF8.self)
        let fs = try finalizeSafeJson(request: safe, signedJson: signed, allowOrphan: false, rates: rates, profile: p)
        check(fs.id == f.id, "the safe JSON's transaction is the KSPT's")
        refused("Unsigned { input: 0 }") {
            _ = try finalizeSafeJson(request: safe, signedJson: safe, allowOrphan: false, rates: rates, profile: p)
        }

        let multi = try vector("multisig.request")
        let first = try vector("multisig.reply.abandon12")
        let second = try vector("multisig.reply.zoo12")
        let mc = try readReply(request: multi, reply: first, profile: p)
        check(mc.present == 1 && mc.required == 2 && !mc.complete, "one cosigner of two")
        let merged = try mergeReplies(request: multi, replies: [first, second], profile: p)
        check(try readReply(request: multi, reply: merged, profile: p).complete, "merged complete")
        let fm = try finalizeReply(request: multi, reply: merged, allowOrphan: false, rates: rates, profile: p)
        check(fm.unlocks.count == 1 && fm.unlocks[0].count > 2 * 132, "two signatures and the redeem")

        // A bundle prepared with the group's hint, as the vector; replies
        // merged.
        let g = try Group.fromDescriptor(descriptor: GROUP)
        check(g.required() == 2 && g.total() == 3, "a 2-of-3")
        let hints = Hints()
        try hints.group(input: 0, group: g, cosigner: 0, chain: 0, index: 0, fingerprints: [])
        let bench = try Data(contentsOf: vectors.appendingPathComponent("../../v107/site/pskb_multisig.bin").standardized)
        let prepared = try prepareBundle(bundle: bench, hints: hints, profile: p)
        check(try prepared.bytes == vector("pskb_multisig.request"), "prepared as the vector")
        let bfirst = try vector("pskb_multisig.reply.abandon12")
        let bsecond = try vector("pskb_multisig.reply.zoo12")
        check(try !readBundle(request: prepared.bytes, reply: bfirst, profile: p).complete, "one bundle reply")
        let bmerged = try mergeBundles(request: prepared.bytes, replies: [bfirst, bsecond], profile: p)
        check(try readBundle(request: prepared.bytes, reply: bmerged, profile: p).complete, "bundles merged")
        _ = try finalizeBundle(request: prepared.bytes, reply: bmerged, allowOrphan: false, rates: rates, profile: p)

        // A signed record.
        let record = try vector("message.record")
        let v = try verifyMessage(bytes: record)
        check(v.record.text == "kassigner.org login", "a signed record")
        _ = try verifyMessageAgainst(bytes: record, text: "kassigner.org login", address: v.record.address)
        check(try messageCodes(text: "hello, unit", profile: p).bare(), "a text's codes")
        check(try readImport(bytes: record).kind == "signedMessage", "a record imported")

        // A Time-Locked Savings card: its backup line read and written
        // again, the card made again from its keys, the owner's key found;
        // its claim built and finished as the vectors'; the safe JSON and
        // impossible times refused.
        let line = String(decoding: try vector("savings.backup"), as: UTF8.self)
        let card = try Card.fromBackup(line: line)
        check(try card.backup() == line, "the backup line written again")
        check(card.unlockMs() == 1_798_761_600_000, "the moment it unlocks")
        check(card.unlockDay() == 1 && card.unlockMonth() == 1 && card.unlockYear() == 2027, "its day")
        check(card.unlockHour() == 0 && card.unlockMinute() == 0, "its time of day")
        check(try card.owner() == receive0, "its owner")
        let again = try Card.savings(owner: card.owner(), recovery: card.recovery(),
                                     day: 1, month: 1, year: 2027, hour: 0, minute: 0)
        check(try again.backup() == line, "made again")
        let eve = try Card.savings(owner: card.owner(), recovery: nil,
                                   day: 31, month: 12, year: 2026, hour: 23, minute: 59)
        check(eve.unlockHour() == 23 && eve.unlockMinute() == 59, "a time of day")
        check(eve.unlockMs() == card.unlockMs() - 60_000, "a minute before")
        check(try eve.backup().contains(",31/12/2026 23:59,"), "its line, to the minute")
        let signer = try card.signer(account: a, depth: 20)
        check(signer?.index == 0 && signer?.recovers == false, "the owner's key found")
        guard let to = try summary(kspt: vector("savings.request"), profile: p).outputs[0].address else {
            fail("the claim pays an address")
        }
        let cb = RequestBuilder()
        cb.lockUntil(lockTime: card.unlockMs())
        try cb.spendCardAs(card: card,
                           coin: Coin(txId: String(repeating: "01", count: 32), index: 1, amount: 5 * KAS,
                                      blockDaaScore: 90_000_001, isCoinbase: false),
                           account: a, index: 0)
        try cb.spendCard(card: card,
                         coin: Coin(txId: String(repeating: "02", count: 32), index: 2, amount: 3 * KAS,
                                    blockDaaScore: 90_000_002, isCoinbase: false))
        try cb.sweepTo(address: to)
        let claim = try cb.build(feeRate: 100, rates: rates, profile: p)
        check(try claim.bytes == vector("savings.request"), "the claim, the vector's KSPT")
        let claimBundle = try cb.buildBundle(feeRate: 100, rates: rates, profile: p)
        check(try claimBundle.bytes == vector("savings.bundle"), "the claim, the vector's bundle")
        for (seed, entry) in [("abandon12", "claim"), ("zoo12", "recover")] {
            let fk = try finalizeReply(request: claim.bytes, reply: vector("savings.reply.\(seed)"),
                                       allowOrphan: false, rates: rates, profile: p)
            let fb = try finalizeBundle(request: claimBundle.bytes, reply: vector("savings.bundle.reply.\(seed)"),
                                        allowOrphan: false, rates: rates, profile: p)
            let signed = String(decoding: try vector("savings.\(entry).signed.json"), as: UTF8.self)
            check(signed.hasPrefix("{\"id\":\"\(fk.id)\"") && fb.id == fk.id,
                  "the \(entry) finished as the SDK finished it")
        }
        refused("CardInSafeJson { coin: 0 }") { _ = try cb.buildSafeJson(feeRate: 100, rates: rates, profile: p) }
        refused("Date") {
            _ = try Card.savings(owner: card.owner(), recovery: nil, day: 29, month: 2, year: 2027, hour: 0, minute: 0)
        }
        refused("Date") {
            _ = try Card.savings(owner: card.owner(), recovery: nil, day: 1, month: 1, year: 2027, hour: 24, minute: 0)
        }
        refused("Date") {
            _ = try Card.savings(owner: card.owner(), recovery: nil, day: 1, month: 1, year: 2027, hour: 0, minute: 60)
        }

        // Covenants, as the vectors: an output starts one or continues a
        // coin's, named by the coin whose input authorizes it; one ends
        // only on the request's word; a bundle carries no bound output.
        let covenantScript = Data([0xaa, 0x20] + [UInt8](repeating: 0x77, count: 32) + [0x87])
        func covenantBuilder(_ covenant: String?, _ outputs: Int) throws -> RequestBuilder {
            let cv = RequestBuilder()
            for n in [UInt32(1), 2] {
                try cv.spendAccount(
                    account: a, chain: 0, index: n,
                    coin: Coin(txId: String(repeating: String(format: "%02x", n), count: 32), index: n,
                               amount: 1000 * KAS, blockDaaScore: 0, isCoinbase: false,
                               covenantId: n == 1 ? covenant : nil))
            }
            for _ in 0..<outputs {
                cv.payScript(script: covenantScript, amount: 100 * KAS)
            }
            cv.changeToAccount(account: a, chain: 1, index: 0)
            return cv
        }
        let start = try covenantBuilder(nil, 2)
        try start.startCovenant(output: 0, coin: 0)
        try start.startCovenant(output: 1, coin: 0)
        let started = try start.build(feeRate: 100, rates: rates, profile: p)
        check(try started.bytes == vector("covenant.start.request"), "a covenant started, the vector's KSPT")
        let cs = try summary(kspt: started.bytes, profile: p)
        guard let made = cs.outputs[0].covenantId else { fail("the started output is bound") }
        check(cs.version == 1 && made.count == 64, "version 1, the new covenant's id")
        check(cs.outputs[1].covenantId == made
                && cs.outputs[0].authorizingInput == 0 && cs.outputs[1].authorizingInput == 0
                && cs.outputs[2].covenantId == nil && cs.outputs[2].authorizingInput == nil,
              "both outputs of the one covenant, the change not bound")
        check(try summary(kspt: single, profile: p).version == 0 && s.outputs[0].covenantId == nil,
              "a plain send")
        let fc = try finalizeReply(request: started.bytes, reply: vector("covenant.start.reply.abandon12"),
                                   allowOrphan: false, rates: rates, profile: p)
        check(fc.fee == started.fee, "the fee the request found")
        check(fc.submitJson.components(separatedBy: "\"computeBudget\":10").count - 1 == 2
                && fc.submitJson.contains("\"sigOpCount\":0"),
              "each input's compute budget")
        let startSafe = try start.buildSafeJson(feeRate: 100, rates: rates, profile: p)
        check(String(decoding: startSafe.bytes, as: UTF8.self).contains("\"version\":1"),
              "the safe JSON, version 1")
        refused("CovenantInBundle") { _ = try start.buildBundle(feeRate: 100, rates: rates, profile: p) }

        let ends = try covenantBuilder(bound, 1)
        refused("CovenantBound { coin: 0 }") { _ = try ends.build(feeRate: 100, rates: rates, profile: p) }
        ends.endCovenants()
        let ended = try ends.build(feeRate: 100, rates: rates, profile: p)
        check(try summary(kspt: ended.bytes, profile: p).version == 0, "ended on the request's word")

        let goOn = try covenantBuilder(bound, 1)
        try goOn.continueCovenant(output: 0, coin: 0)
        let continued = try goOn.build(feeRate: 100, rates: rates, profile: p)
        check(try continued.bytes == vector("covenant.continue.request"),
              "a covenant continued, the vector's KSPT")
        let cc = try summary(kspt: continued.bytes, profile: p).outputs[0]
        check(cc.covenantId == bound && cc.authorizingInput == 0, "under its coin's id")
        refused("BadBinding { output: 1 }") { try goOn.startCovenant(output: 1, coin: 0) }
        try goOn.continueCovenant(output: 0, coin: 1)
        refused("BadBinding { output: 0 }") { _ = try goOn.build(feeRate: 100, rates: rates, profile: p) }

        // A refusal, by the SDK's name.
        refused("Empty") { _ = try RequestBuilder().build(feeRate: 100, rates: rates, profile: p) }

        // A node, both encodings: each request as the vector, each reply
        // read.
        let addresses = String(decoding: try nodeVector("utxos.request.json"), as: UTF8.self)
            .split(separator: "\"").map(String.init).filter { $0.hasPrefix("kaspa") }
        check(addresses.count == 5, "the five addresses")
        for encoding in ["borsh", "json"] {
            let node = try Node(encoding: encoding)
            check(node.encoding() == encoding && node.isText() == (encoding == "json"), "a \(encoding) node")
            check(try node.getServerInfo(id: 7) == nodeVector("server_info.request.\(encoding)"), "getServerInfo, \(encoding)")
            check(try node.getFeeEstimate(id: 7) == nodeVector("fee_estimate.request.\(encoding)"), "getFeeEstimate, \(encoding)")
            check(try node.getUtxosByAddresses(id: 7, addresses: addresses) == nodeVector("utxos.request.\(encoding)"),
                  "getUtxosByAddresses, \(encoding)")
            check(try node.submitTransaction(id: 7, finalized: f) == nodeVector("single.submit.request.\(encoding)"),
                  "submitTransaction, \(encoding)")

            let answer = try node.read(message: nodeVector("utxos.reply.\(encoding)"))
            check(answer.id == 7 && answer.kind == "reply" && answer.call == "getUtxosByAddresses", "utxos, \(encoding)")
            guard let utxos = answer.utxos else { fail("no coins in the utxos reply, \(encoding)") }
            check(utxos.count == 6 && utxos[1].amount == UInt64.max, "a u64 of sompi, exact")
            check(utxos[0].address == addresses[0] && utxos[5].address == nil, "the addresses")
            let info = try node.read(message: nodeVector("server_info.reply.\(encoding)")).serverInfo
            check(info?.network == "mainnet" && info?.rpcApiVersion == 1 && info?.hasUtxoIndex == true, "info, \(encoding)")
            let fe = try node.read(message: nodeVector("fee_estimate.reply.\(encoding)")).feeEstimate
            check(fe?.priority.feeRate == 2 && fe?.normal.count == 2 && fe?.low.first?.estimatedSeconds == 60,
                  "fees, \(encoding)")
            let submitted = try node.read(message: nodeVector("submit.reply.\(encoding)"))
            check(submitted.transactionId == String(repeating: "ab", count: 32), "submitted, \(encoding)")
            let refusal = try node.read(message: nodeVector("submit.error.\(encoding)"))
            check(refusal.kind == "error" && (refusal.error ?? "").contains("orphan is disallowed"), "refused, \(encoding)")
        }
        check(try Node(encoding: "borsh").defaultPort() == 17110, "the Borsh port")
        let json = try nodeVector("utxos.reply.json")
        refused("Malformed { at: ") { _ = try Node(encoding: "borsh").read(message: json) }

        print("kassigner_sdk \(version()) through Swift: the round holds")
    }
}
