# KasSigner — Air-gapped offline signing device for Kaspa
# Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# The generated Python binding through the host crate tests' round, run by
# `build.sh` beside the library over the SDK's vectors
# (`spec/vectors/v110/sdk/`) and the node vectors (`../node/`).
#
#   python3 check.py <dir with kassigner_sdk.py and the library> <vectors dir>

import sys
from pathlib import Path

out, vectors = Path(sys.argv[1]), Path(sys.argv[2])
sys.path.insert(0, str(out))
import kassigner_sdk as sdk  # noqa: E402

ABANDON12_KPUB44 = "kpub2JXpdok4yzBUdLiywgMbE36ixpEnffDhG31kJpRextvhpBQgBJVPcQJ7A99JryUvi8JNBcnzGoiu4qbGcvCfpY1T2RWndCaUjJqhwDSUNw8"
KAS = 100_000_000


def vector(name):
    return (vectors / name).read_bytes()


p = sdk.Profile.esp32s3()
rates = sdk.Rates.mainnet()
assert p.max_inputs() == 32 and p.max_frames() == 64, "the ESP32-S3 profile"
assert sdk.codes(bytes(300), "opaque", p).period_ms() == 600, "versions 6 and 7: 600 ms"
assert sdk.codes(bytes(1000), "opaque", p).period_ms() == 850, "versions 8 and 9: 850 ms"

# A node's UTXO as the coin a request spends, its covenant with it.
u = sdk.Utxo(address=None, transaction_id="01" * 32, index=1, amount=3 * KAS, script_version=0,
             script=b"", block_daa_score=90_000_001, is_coinbase=False, covenant_id="5a" * 32)
c = sdk.utxo_coin(u)
assert (c.tx_id, c.index, c.amount, c.block_daa_score, c.is_coinbase, c.covenant_id) == (
    "01" * 32, 1, 3 * KAS, 90_000_001, False, "5a" * 32), "a UTXO's covenant goes with its coin"

# Import and addresses.
i = sdk.read_import(ABANDON12_KPUB44.encode())
assert i.kind == "account" and i.account is not None
a = i.account
receive0 = a.address(0, 0)
assert receive0.startswith("kaspa:q"), receive0
assert sdk.address_of_script(a.script(0, 0)) == receive0
assert len(a.public_key(0, 0)) == 64

# The vector's request, built byte for byte; its payee read off output 0.
single = vector("single.request")
s = sdk.summary(single, p)
assert s.inputs == 2 and s.total_in == 5 * KAS and len(s.outputs) == 2
b = sdk.RequestBuilder()
b.spend_account(a, 0, 0, sdk.Coin(tx_id="01" * 32, index=1, amount=3 * KAS))
b.spend_account(a, 1, 3, sdk.Coin(tx_id="02" * 32, index=2, amount=2 * KAS))
b.pay_script(s.outputs[0].script, 4 * KAS)
b.change_to_account(a, 1, 4)
r = b.build(100, rates, p)
assert r.bytes == single, "the builder builds the vector"
assert r.signatures == 2 and r.change == s.outputs[1].value

# Its codes through the reader, each matrix rasterized through the unit's
# decoder.
c = sdk.codes(single, "kspt", p)
reader = sdk.Reader(p, 225)
for k in reversed(range(c.frames())):
    frame = c.bytes(k)
    m = c.matrix(k)
    assert len(m.modules) == m.size * m.size
    scale, quiet = 4, 4
    side = (m.size + 2 * quiet) * scale
    px = bytearray(b"\xff" * (side * side))
    for y in range(m.size):
        for x in range(m.size):
            if m.modules[y * m.size + x]:
                for dy in range(scale):
                    row = ((y + quiet) * scale + dy) * side + (x + quiet) * scale
                    px[row:row + scale] = b"\x00" * scale
    assert sdk.decode_qr(bytes(px), side, side, 8) == frame, f"frame {k} decodes"
    t = reader.take(frame)
    assert t.whole == (k == 0), (k, t.status)
assert reader.collect() == single
assert reader.received() == (0 if c.bare() else (1 << c.frames()) - 1)
assert c.svg(0, 4).startswith("<svg")

# The reply checked and finished; another request's refused.
rep = vector("single.reply.abandon12")
ck = sdk.read_reply(single, rep, p)
assert (ck.signatures, ck.present, ck.complete) == (2, None, True)
f = sdk.finalize_reply(single, rep, False, rates, p)
assert len(f.id) == 64 and f.fee == s.fee
assert '"mass":%d' % f.storage_mass in f.submit_json
assert '"amount":400000000' in f.rest_json and '"mass"' not in f.rest_json
try:
    sdk.read_reply(vector("sweep.request"), rep, p)
    raise AssertionError("another request's reply was taken")
except sdk.Fault.Sdk as e:
    assert str(e) == "NotTheRequest", str(e)
try:
    sdk.finalize_reply(vector("sweep.request"), rep, False, rates, p)
    raise AssertionError("another request's reply was finished")
except sdk.Fault.Sdk as e:
    assert str(e) == "NotTheRequest", str(e)

# As a bundle, as the vector, finishing to the same transaction; a coin
# without its entry refused.
bb = sdk.RequestBuilder()
bb.spend_account(a, 0, 0, sdk.Coin(tx_id="01" * 32, index=1, amount=3 * KAS,
                                   block_daa_score=90000001, is_coinbase=False))
bb.spend_account(a, 1, 3, sdk.Coin(tx_id="02" * 32, index=2, amount=2 * KAS,
                                   block_daa_score=90000002, is_coinbase=False))
bb.pay_script(s.outputs[0].script, 4 * KAS)
bb.change_to_account(a, 1, 4)
rb = bb.build_bundle(100, rates, p)
assert rb.bytes == vector("single.bundle"), "the builder builds the bundle vector"
assert (rb.fee, rb.change) == (r.fee, r.change)
brep = vector("single.bundle.reply.abandon12")
assert sdk.read_bundle(rb.bytes, brep, p).complete
assert sdk.finalize_bundle(rb.bytes, brep, False, rates, p).id == f.id, "the KSPT's transaction"
try:
    b.build_bundle(100, rates, p)
    raise AssertionError("a coin without its entry was put in a bundle")
except sdk.Fault.Sdk as e:
    assert str(e) == "NoEntry { coin: 0 }", str(e)

# In the safe JSON, as the vector: finished once a wallet signed it,
# refused unsigned.
rs = bb.build_safe_json(100, rates, p)
assert rs.bytes == vector("single.safe.json"), "the builder writes the safe JSON vector"
assert (rs.fee, rs.change) == (r.fee, r.change)
safe = rs.bytes.decode()
signed = vector("single.safe.signed.json").decode()
assert sdk.finalize_safe_json(safe, signed, False, rates, p).id == f.id, "the KSPT's transaction"
try:
    sdk.finalize_safe_json(safe, safe, False, rates, p)
    raise AssertionError("an unsigned transaction was finished")
except sdk.Fault.Sdk as e:
    assert str(e) == "Unsigned { input: 0 }", str(e)

multi = vector("multisig.request")
first, second = vector("multisig.reply.abandon12"), vector("multisig.reply.zoo12")
ck = sdk.read_reply(multi, first, p)
assert (ck.present, ck.required, ck.complete) == (1, 2, False)
merged = sdk.merge_replies(multi, [first, second], p)
assert sdk.read_reply(multi, merged, p).complete
f = sdk.finalize_reply(multi, merged, False, rates, p)
assert len(f.unlocks) == 1 and len(f.unlocks[0]) > 2 * 132

# A bundle prepared with the group's hint, as the vector; replies merged.
g = sdk.Group.from_descriptor(
    "multi_hd45(2,kpub2JKepGqGb3usUsEfD7JgwbFZav8Nu2z4dBZQ42hg8JUGnCbLUb9phbpZW2TQuk2DmayefGMiVzCK7EL9hPbr2K2vVzSk8SpuUwwqTLq8y14,"
    "kpub2JG8myov28wfetFRquaJtuTJpL3jhYnBhu2V6ZuwHnDqPBAoyqgJKkQiba4wLfU9JcsNBBoBTm7zPtk1Nv4Nn36tUkoZWGUXjWn1aJCajdW,"
    "kpub2HgQUMVzkWe8YCDJDEg5zdMAiKnFE3inHgrv7VRUCxKanfXpGnPpSut8MQUHYBcSFKxDhNJKCFJTy6BSdUhXKd1VbrFdFRrJ2thq3ZJfPUU)"
)
assert (g.required(), g.total()) == (2, 3)
hints = sdk.Hints()
hints.group(0, g, 0, 0, 0, [])
bench = (vectors / "../../v107/site/pskb_multisig.bin").read_bytes()
prepared = sdk.prepare_bundle(bench, hints, p)
assert prepared.bytes == vector("pskb_multisig.request"), "prepared as the vector"
bfirst, bsecond = vector("pskb_multisig.reply.abandon12"), vector("pskb_multisig.reply.zoo12")
assert not sdk.read_bundle(prepared.bytes, bfirst, p).complete
bmerged = sdk.merge_bundles(prepared.bytes, [bfirst, bsecond], p)
assert sdk.read_bundle(prepared.bytes, bmerged, p).complete
sdk.finalize_bundle(prepared.bytes, bmerged, False, rates, p)

# A signed record.
record = vector("message.record")
v = sdk.verify_message(record)
assert v.record.text == "kassigner.org login"
sdk.verify_message_against(record, "kassigner.org login", v.record.address)
assert sdk.message_codes("hello, unit", p).bare()
assert sdk.read_import(record).kind == "signedMessage"

# A Time-Locked Savings card: its backup line read and written again, the
# card made again from its keys, the owner's key found; its claim built and
# finished as the vectors'; the safe JSON and impossible times refused.
line = vector("savings.backup").decode()
card = sdk.Card.from_backup(line)
assert card.backup() == line, "the backup line written again"
assert card.unlock_ms() == 1_798_761_600_000, "the moment it unlocks"
assert (card.unlock_day(), card.unlock_month(), card.unlock_year()) == (1, 1, 2027)
assert (card.unlock_hour(), card.unlock_minute()) == (0, 0)
assert card.owner() == receive0 and card.address().startswith("kaspa:p")
assert sdk.Card.savings(card.owner(), card.recovery(), 1, 1, 2027, 0, 0).backup() == line, "made again"
eve = sdk.Card.savings(card.owner(), None, 31, 12, 2026, 23, 59)
assert (eve.unlock_hour(), eve.unlock_minute()) == (23, 59), "a time of day"
assert eve.unlock_ms() == card.unlock_ms() - 60_000, "a minute before"
assert ",31/12/2026 23:59," in eve.backup(), "its line, to the minute"
signer = card.signer(a, 20)
assert signer is not None and (signer.index, signer.recovers) == (0, False)
to = sdk.summary(vector("savings.request"), p).outputs[0].address
cb = sdk.RequestBuilder()
cb.lock_until(card.unlock_ms())
cb.spend_card_as(card, sdk.Coin(tx_id="01" * 32, index=1, amount=5 * KAS,
                                block_daa_score=90000001, is_coinbase=False), a, 0)
cb.spend_card(card, sdk.Coin(tx_id="02" * 32, index=2, amount=3 * KAS,
                             block_daa_score=90000002, is_coinbase=False))
cb.sweep_to(to)
claim = cb.build(100, rates, p)
assert claim.bytes == vector("savings.request"), "the claim, the vector's KSPT"
claim_bundle = cb.build_bundle(100, rates, p)
assert claim_bundle.bytes == vector("savings.bundle"), "the claim, the vector's bundle"
for seed, entry in [("abandon12", "claim"), ("zoo12", "recover")]:
    fk = sdk.finalize_reply(claim.bytes, vector(f"savings.reply.{seed}"), False, rates, p)
    fb = sdk.finalize_bundle(claim_bundle.bytes, vector(f"savings.bundle.reply.{seed}"),
                             False, rates, p)
    signed = vector(f"savings.{entry}.signed.json").decode()
    assert signed.startswith(f'{{"id":"{fk.id}"') and fb.id == fk.id, entry
for build, name in [(lambda: cb.build_safe_json(100, rates, p), "CardInSafeJson { coin: 0 }"),
                    (lambda: sdk.Card.savings(card.owner(), None, 29, 2, 2027, 0, 0), "Date"),
                    (lambda: sdk.Card.savings(card.owner(), None, 1, 1, 2027, 24, 0), "Date"),
                    (lambda: sdk.Card.savings(card.owner(), None, 1, 1, 2027, 0, 60), "Date")]:
    try:
        build()
        raise AssertionError(f"{name} was not refused")
    except sdk.Fault.Sdk as e:
        assert str(e) == name, str(e)

# Covenants, as the vectors: an output starts one or continues a coin's,
# named by the coin whose input authorizes it; one ends only on the
# request's word; a bundle carries no bound output.
COVENANT = "5a" * 32
covenant_script = bytes([0xAA, 0x20]) + bytes([0x77] * 32) + bytes([0x87])


def covenant_builder(bound, outputs):
    cv = sdk.RequestBuilder()
    for n in (1, 2):
        cv.spend_account(a, 0, n, sdk.Coin(
            tx_id=("%02x" % n) * 32, index=n, amount=1000 * KAS, block_daa_score=0,
            is_coinbase=False, covenant_id=bound if n == 1 else None))
    for _ in range(outputs):
        cv.pay_script(covenant_script, 100 * KAS)
    cv.change_to_account(a, 1, 0)
    return cv


def refused(build, name):
    try:
        build()
        raise AssertionError(f"{name} was not refused")
    except sdk.Fault.Sdk as e:
        assert str(e) == name, str(e)


start = covenant_builder(None, 2)
start.start_covenant(0, 0)
start.start_covenant(1, 0)
started = start.build(100, rates, p)
assert started.bytes == vector("covenant.start.request"), "a covenant started, the vector's KSPT"
cs = sdk.summary(started.bytes, p)
made = cs.outputs[0].covenant_id
assert cs.version == 1 and made is not None and len(made) == 64, "version 1, the new covenant's id"
assert [(o.covenant_id, o.authorizing_input) for o in cs.outputs] == [
    (made, 0), (made, 0), (None, None)], "both outputs of the one covenant, the change not bound"
assert sdk.summary(single, p).version == 0 and s.outputs[0].covenant_id is None, "a plain send"
fc = sdk.finalize_reply(started.bytes, vector("covenant.start.reply.abandon12"), False, rates, p)
assert fc.fee == started.fee, "the fee the request found"
assert fc.submit_json.count('"computeBudget":10') == 2 and '"sigOpCount":0' in fc.submit_json
assert '"version":1' in start.build_safe_json(100, rates, p).bytes.decode()
refused(lambda: start.build_bundle(100, rates, p), "CovenantInBundle")

ends = covenant_builder(COVENANT, 1)
refused(lambda: ends.build(100, rates, p), "CovenantBound { coin: 0 }")
ends.end_covenants()
assert sdk.summary(ends.build(100, rates, p).bytes, p).version == 0, "ended on the request's word"

go_on = covenant_builder(COVENANT, 1)
go_on.continue_covenant(0, 0)
continued = go_on.build(100, rates, p)
assert continued.bytes == vector("covenant.continue.request"), "a covenant continued, the vector's KSPT"
cc = sdk.summary(continued.bytes, p).outputs[0]
assert (cc.covenant_id, cc.authorizing_input) == (COVENANT, 0), "under its coin's id"
refused(lambda: go_on.start_covenant(1, 0), "BadBinding { output: 1 }")
go_on.continue_covenant(0, 1)
refused(lambda: go_on.build(100, rates, p), "BadBinding { output: 0 }")

# A refusal, by the SDK's name.
try:
    sdk.RequestBuilder().build(100, rates, p)
    raise AssertionError("an empty request was built")
except sdk.Fault.Sdk as e:
    assert str(e) == "Empty", str(e)

# A node, both encodings: each request as the vector, each reply read.
nodes = vectors / "../node"


def node_vector(name):
    return (nodes / name).read_bytes()


addresses = [
    w for w in node_vector("utxos.request.json").decode().split('"') if w.startswith("kaspa")
]
assert len(addresses) == 5, addresses
f = sdk.finalize_reply(single, rep, False, rates, p)
for encoding in ("borsh", "json"):
    node = sdk.Node(encoding)
    assert node.encoding() == encoding and node.is_text() == (encoding == "json")
    assert node.get_server_info(7) == node_vector(f"server_info.request.{encoding}")
    assert node.get_fee_estimate(7) == node_vector(f"fee_estimate.request.{encoding}")
    assert node.get_utxos_by_addresses(7, addresses) == node_vector(f"utxos.request.{encoding}")
    assert node.submit_transaction(7, f) == node_vector(f"single.submit.request.{encoding}")
    a = node.read(node_vector(f"utxos.reply.{encoding}"))
    assert (a.id, a.kind, a.call) == (7, "reply", "getUtxosByAddresses")
    assert len(a.utxos) == 6 and a.utxos[1].amount == 2**64 - 1
    assert a.utxos[0].address == addresses[0] and a.utxos[5].address is None
    i = node.read(node_vector(f"server_info.reply.{encoding}")).server_info
    assert (i.network, i.rpc_api_version, i.has_utxo_index) == ("mainnet", 1, True)
    e = node.read(node_vector(f"fee_estimate.reply.{encoding}")).fee_estimate
    assert (e.priority.fee_rate, len(e.normal), e.low[0].estimated_seconds) == (2, 2, 60.0)
    assert node.read(node_vector(f"submit.reply.{encoding}")).transaction_id == "ab" * 32
    r = node.read(node_vector(f"submit.error.{encoding}"))
    assert r.kind == "error" and "orphan is disallowed" in r.error
assert sdk.Node("borsh").default_port() == 17110
try:
    sdk.Node("borsh").read(node_vector("utxos.reply.json"))
    raise AssertionError("a JSON message was read as Borsh")
except sdk.Fault.Sdk as e:
    assert str(e).startswith("Malformed { at: "), str(e)

print("kassigner_sdk", sdk.version(), "through Python: the round holds")
