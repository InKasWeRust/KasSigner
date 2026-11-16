// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// The generated Kotlin binding through the same round as `check.py`, over
// the SDK's vectors (`spec/vectors/v110/sdk/`), on a JVM with JNA.
//
//   java -cp <binding and check>:jna.jar -Djna.library.path=<dir with the library> CheckKt <vectors dir>

import java.io.File
import org.kassigner.sdk.*

const val ABANDON12_KPUB44 = "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8"
const val KAS = 100_000_000UL

fun must(ok: Boolean, what: String) { if (!ok) throw AssertionError(what) }

/** `block` must be refused by the SDK with exactly `name`. */
fun refused(name: String, what: String, block: () -> Unit) {
    try { block() } catch (e: Fault.Sdk) { must(e.message == name, "$what: ${e.message}"); return }
    throw AssertionError(what)
}

fun main(args: Array<String>) {
    val vectors = File(args[0])
    fun vector(name: String) = File(vectors, name).readBytes()

    val p = Profile.esp32s3()
    val rates = Rates.mainnet()
    must(p.maxInputs() == 32u && p.maxFrames() == 64u, "the ESP32-S3 profile")
    must(codes(ByteArray(300), "opaque", p).periodMs() == 600u, "versions 6 and 7: 600 ms")
    must(codes(ByteArray(1000), "opaque", p).periodMs() == 850u, "versions 8 and 9: 850 ms")

    // Import and addresses.
    val i = readImport(ABANDON12_KPUB44.toByteArray())
    must(i.kind == "account" && i.account != null, "the kpub imports as an account")
    val a = i.account!!
    val receive0 = a.address(0u, 0u)
    must(receive0.startsWith("kaspa:q"), receive0)
    must(addressOfScript(a.script(0u, 0u)) == receive0, "a script's address")
    must(a.publicKey(0u, 0u).length == 64, "a public key, hex")

    // The vector's request, built byte for byte; its payee read off output 0.
    val single = vector("single.request")
    val s = summary(single, p)
    must(s.inputs == 2u && s.totalIn == 5UL * KAS && s.outputs.size == 2, "the request's summary")
    val b = RequestBuilder()
    b.spendAccount(a, 0u, 0u, Coin(txId = "01".repeat(32), index = 1u, amount = 3UL * KAS))
    b.spendAccount(a, 1u, 3u, Coin(txId = "02".repeat(32), index = 2u, amount = 2UL * KAS))
    b.payScript(s.outputs[0].script, 4UL * KAS)
    b.changeToAccount(a, 1u, 4u)
    val r = b.build(100UL, rates, p)
    must(r.bytes.contentEquals(single), "the builder builds the vector")
    must(r.signatures == 2u && r.change == s.outputs[1].value, "its signatures and change")

    // Its codes through the reader, each matrix through the unit's decoder.
    val c = codes(single, "kspt", p)
    val reader = Reader(p, 225u)
    for (k in (c.frames().toInt() - 1) downTo 0) {
        val frame = c.bytes(k.toUInt())
        val m = c.matrix(k.toUInt())
        val size = m.size.toInt()
        must(m.modules.size == size * size, "a matrix is square")
        val scale = 4; val quiet = 4
        val side = (size + 2 * quiet) * scale
        val px = ByteArray(side * side) { 0xff.toByte() }
        for (y in 0 until size) for (x in 0 until size) if (m.modules[y * size + x] != 0.toByte()) {
            for (dy in 0 until scale) {
                val row = ((y + quiet) * scale + dy) * side + (x + quiet) * scale
                for (dx in 0 until scale) px[row + dx] = 0
            }
        }
        must(decodeQr(px, side.toUInt(), side.toUInt(), 8u).contentEquals(frame), "frame $k decodes")
        val t = reader.take(frame)
        must(t.whole == (k == 0), "frame $k: ${t.status}")
    }
    must(reader.collect().contentEquals(single), "the frames give the request back")
    must(c.svg(0u, 4u).startsWith("<svg"), "a code as SVG")

    // The reply checked and finished; another request's refused.
    val rep = vector("single.reply.abandon12")
    val ck = readReply(single, rep, p)
    must(ck.signatures == 2u && ck.present == null && ck.complete, "the reply checks")
    val f = finalizeReply(single, rep, false, rates, p)
    must(f.id.length == 64 && f.fee == s.fee, "the finished transaction")
    must(f.submitJson.contains("\"mass\":${f.storageMass}"), "its storage mass committed")
    must(f.restJson.contains("\"amount\":400000000") && !f.restJson.contains("\"mass\""), "its REST form")
    refused("NotTheRequest", "another request's reply was taken") { readReply(vector("sweep.request"), rep, p) }
    refused("NotTheRequest", "another request's reply was finished") { finalizeReply(vector("sweep.request"), rep, false, rates, p) }

    // As a PSKB, as the vector, finishing to the same transaction; a coin
    // without its entry refused.
    val bb = RequestBuilder()
    bb.spendAccount(a, 0u, 0u, Coin("01".repeat(32), 1u, 3UL * KAS, 90000001UL, false))
    bb.spendAccount(a, 1u, 3u, Coin("02".repeat(32), 2u, 2UL * KAS, 90000002UL, false))
    bb.payScript(s.outputs[0].script, 4UL * KAS)
    bb.changeToAccount(a, 1u, 4u)
    val rb = bb.buildBundle(100UL, rates, p)
    must(rb.bytes.contentEquals(vector("single.bundle")), "the builder builds the PSKB vector")
    must(rb.fee == r.fee && rb.change == r.change, "the same fee and change")
    val brep = vector("single.bundle.reply.abandon12")
    must(readBundle(rb.bytes, brep, p).complete, "the PSKB reply checks")
    must(finalizeBundle(rb.bytes, brep, false, rates, p).id == f.id, "the KSPT's transaction")
    refused("NoEntry { coin: 0 }", "a coin without its entry was put in a PSKB") { b.buildBundle(100UL, rates, p) }

    // In the safe JSON, as the vector: finished once signed, refused unsigned.
    val rs = bb.buildSafeJson(100UL, rates, p)
    must(rs.bytes.contentEquals(vector("single.safe.json")), "the builder writes the safe JSON vector")
    val safe = String(rs.bytes)
    val signed = String(vector("single.safe.signed.json"))
    must(finalizeSafeJson(safe, signed, false, rates, p).id == f.id, "the KSPT's transaction, from the safe JSON")
    refused("Unsigned { input: 0 }", "an unsigned transaction was finished") { finalizeSafeJson(safe, safe, false, rates, p) }

    println("kassigner_sdk through Kotlin: the round holds")
}
