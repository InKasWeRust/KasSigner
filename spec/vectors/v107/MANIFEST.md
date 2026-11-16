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

# The v1.0.7 corpus

The files v1.0.7 units and their companion write, made by v1.0.7's own
code, for v1.1.0 to read: in each crate's `tests/v107.rs`, the corpus
section at the end of `firmware/kassigner-fw/tests/scan.rs`, and the flow
tests in `tests/flow/`, mainly `corpus_v107.rs`.

## Where it comes from

- **The unit's half**: tag `v1.0.7`, commit `528f379`, built on a host with
  stable Rust 1.97 (no byte depends on the compiler): the tag's `core`
  crate, its `bootloader/src/hw/sd_backup.rs` and
  `bootloader/src/ui/seed_manager.rs` unchanged, and, line for line, the
  handler code that writes the `KAS\x03` files inline
  (`handlers/sd.rs:2933-2966`).
- **The companion's half**: the v1.0.7 site as kassigner.org served it
  (`gh-pages` at `9b3f7c4`, wasm built from the tag), its `kassee_web.js`
  and `kassee_web_bg.wasm` run unchanged in Node against a stand-in node.
  The frames are its own SVG codes, read back to bytes by its own jsQR.
- **Checked both ways**: all thirteen unit replies went through that site
  as its page sends them: a signed KSPT to `broadcast_signed`, a bundle to
  `pskt_finalize_and_broadcast`, a 2-of-3 KSPT reply merged into its bundle
  (`pskt_merge_signed_kspt_v2`), then finalized and submitted once both
  cosigners signed.

The generator compiles v1.0.7's code, so it is kept outside this tree.

## What is fixed so that it repeats

- **Seeds**: the BIP39 test phrases, no passphrase.
  - abandon 12: `abandon` x11, `about`. Master fingerprint `73c5da0a`.
  - abandon 24: `abandon` x23, `art`.
  - zoo 12: `zoo` x11, `wrong`.
- **Password**: `abc`; `SD000003.KAS` has the empty password v1.0.7
  allowed.
- **Salts and nonces** (a unit's generator): byte `i` of a salt is
  `((tag + i) * 7) | 1`, of a nonce `((tag + i) * 13) | 2`, `tag` distinct
  per file; never all zeros, which `encrypt_v3` refuses.
- **BIP340's auxiliary bytes** (also the generator): a counter, which
  changes a signature's bytes but not its format or validity.
- **UTXOs**: made up, each transaction id SHA-256 of `corpus107:<label>`, so
  nothing spends anything on any network.
  - abandon 12 receive 0: 5 KAS (`a12-r0`), receive 1: 3 KAS (`a12-r1`),
    change 0: 1.5 KAS (`a12-c0`).
  - The 2-of-3's first address: 10 KAS (`ms-0`). Its second: three coins
    of 1 KAS (`ms1-0` to `ms1-2`).

## The files

### `seeds.json`

The three seeds as v1.0.7 derives them: word indices, the kpub at
`m/44'/111111'/0'` and the cosigner kpub at `m/45'/111111'/0'`, the account
xprv, and the first receive and change addresses.

### `seedqr/`

`<seed>.standard` (four digits a word) and `<seed>.compact` (the entropy's
16 or 32 bytes), from the tag's `encode_seedqr` and `encode_compact_seedqr`.

### `site/`

`<name>.bin` is a request, `<name>.frames` the codes the site shows, one
code in hex per line. A request of up to 251 bytes is one bare code; a
longer one is frames of `[index, total, length]` and a balanced fragment of
at most 248 bytes.

| Name | Bytes | Codes | What |
|---|---|---|---|
| `kspt_send_1in` | 228 | 1 | KSPT `0x01`: 1 KAS to abandon 24 receive 0, fee 0.01, one input |
| `kspt_send_3in` | 408 | 2 | KSPT `0x01`: 8 KAS to abandon 24 receive 0, three inputs |
| `kspt_compound` | 318 | 2 | KSPT `0x01`: three recipients |
| `kspt_consolidate` | 363 | 2 | KSPT `0x01`: every UTXO back to the wallet |
| `kspt_multisig` | 333 | 2 | KSPT `0x01`, flags `0x02`: the 2-of-3 pays 2 KAS, change to itself |
| `pskb_send` | 2040 | 9 | Bundle: 1 KAS to abandon 24 receive 0 |
| `pskb_send_utxos` | 2958 | 12 | Bundle from two given UTXOs: 6 KAS |
| `pskb_compound` | 2738 | 12 | Bundle: three recipients |
| `pskb_multisig` | 4142 | 17 | Bundle: the 2-of-3 pays 2 KAS, change to itself |
| `pskb_multisig_3in` | 8478 | 35 | Bundle: the 2-of-3's second address pays 2.5 KAS from its three coins |
| `pskb_covenant_genesis` | 2332 | 10 | Bundle, transaction version 1: abandon 12 funds a Time-Locked Savings vault with 2 KAS, a covenant binding on the vault's output |
| `kspt2_relay_send` | 231 | 1 | `pskb_send` relayed compact (`pskt_relay_to_kspt_v2`), KSPT `0x03` |
| `kspt2_relay_multisig` | 363 | 2 | `pskb_multisig` relayed compact, KSPT `0x05`, its key hints |
| `kspt2_relay_multisig_3in` | 783 | 4 | `pskb_multisig_3in` relayed compact, KSPT `0x05` |
| `kspt2_relay_covenant` | 268 | 2 | `pskb_covenant_genesis` relayed compact, KSPT `0x03` |

The 2-of-3 is `multi_hd45(2,<abandon 12>,<abandon 24>,<zoo 12>)` over the
cosigner kpubs in `seeds.json`; the site sorts them and derives each key at
cosigner, chain, index. Its coins sit on cosigner 0's first two receive
addresses,
`kaspa:prmr0h7fcx5z8n9aqjt4lrx0f4tmy92u0ftck3spqtqka9833jepjqzv0u403` and
the one at index 1; change goes to its first change address,
`kaspa:prcnax9dr56qk0j4tfsj353n3rsqvvx88jc2tlxrumsfu0jxn47w2d5k8thnc`.
The site spends at most three inputs from it ("Multisig P2SH limited to 3
inputs").

The vault is the site's `covenant_timelocked_savings` with abandon 12's
receive 0 key as owner and heir, lock time 99,999,999, at
`kaspa:pqfzge4z66p8tjsh65p26ly60vx8dr4muzcahue2hkc0f2wpjxf65dwxu0l9k`.

`kspt_multisig` comes from the site's `create_multisig_kspt`, which its page
never calls. v1.0.7's signer refuses it for all three cosigners; the tests
here read it and never sign it.

### `device/`

What a unit answers (abandon 12 unless named), signed by the tag's own calls
in the order `app/signing.rs` makes them. `<name>.bin` is the reply;
`<name>.fast.frames` and `<name>.safe.frames` are its codes at each density
(`handlers/menu.rs`, `ui/screens.rs`, `draw_kspt_density_choice`): `fast`,
227 bytes a frame, for a phone or the site and KasSigner's Fast, where a
reply of up to 230 bytes is one bare code; `safe`, 40 bytes a frame, for
KasSigner's Safe. The unit asks which reads it, a phone or the site or a
KasSigner, for a multisig reply and for a transaction loaded from the card
(`handlers/sd.rs:2374`); a single-signature reply goes straight to the
wallet's code (`app/signing.rs:1962`), so its `safe` set is what the unit
shows when it is loaded from the card. Splits are balanced; a fragment under
20 bytes is padded to 20 with zeros, its length byte the unpadded length. A
density needing more than 64 frames is dimmed and not taken
(`density_fits`), so it has no set here.

| Name | Bytes | Fast | Safe |
|---|---|---|---|
| `kspt_send_1in.reply` | 294, KSPT `0x01` flags `0x01` | 2 | 8 |
| `kspt_send_3in.reply` | 606, KSPT `0x01` flags `0x01` | 3 | 16 |
| `kspt_consolidate.reply` | 561, KSPT `0x01` flags `0x01` | 3 | 15, the last of 29 bytes, a frame of 32 |
| `pskb_send.reply` | 2562, bundle | 12 | none |
| `pskb_send_utxos.reply` | 4006, bundle | 18 | none |
| `pskb_compound.reply` | 3260, bundle | 15 | none |
| `pskb_covenant_genesis.reply` | 2808, bundle | 13 | none |
| `kspt2_relay_multisig.reply` | 429, KSPT `0x05`, 1 of 2 signatures | 2 | 11 |
| `kspt2_relay_multisig.reply.abandon24` | 495, KSPT `0x05` flags `0x01`, 2 of 2 | 3 | 13 |
| `kspt2_relay_multisig_3in.reply` | 981, KSPT `0x05`, 1 of 2 on each input | 5 | 25 |
| `kspt2_relay_multisig_3in.reply.abandon24` | 1179, KSPT `0x05` flags `0x01`, 2 of 2 | 6 | 30, the last padded |
| `pskb_multisig.reply` | 4518, bundle, 1 of 2 | 20 | none |
| `pskb_multisig.reply.abandon24` | 4942, bundle, 2 of 2 | 22 | none |

The 2-of-3's replies are a cosigner unit's, signing with its one selected
slot: the compact relay through `parse_signed_pskt_v2` and
`sign_and_serialize_multisig`, the bundle through
`sign_and_serialize_pskt_multisig`. Abandon 12, cosigner 0, signs the
site's request first; `.reply.abandon24` is abandon 24's unit signing what
abandon 12's unit shows.

`abandon12.kpub44` and `abandon12.kpub45` are the two kpubs as the unit
shows them: `.one.frames` one code of the kpub's text, `.two.frames` two
frames of the raw form, the marker `0x01` and the 78-byte payload.

### `cards/`

The files a unit writes to a card, under its 8.3 names.

| Name | What |
|---|---|
| `SD000001.KAS` | Seed backup, `KAS\x04` purpose 1: abandon 12, password `abc` |
| `SD000002.KAS` | Seed backup, `KAS\x04` purpose 1: abandon 24, password `abc` |
| `SD000003.KAS` | Seed backup, `KAS\x04` purpose 1: zoo 12, empty password |
| `XP000001.KAS` | xprv backup, `KAS\x04` purpose 2: abandon 12's account xprv |
| `RAWHINT.KAS` | Raw blob, `KAS\x04` purpose 3, as v1.0.7 seals a stego recovery hint; not a name v1.0.7 gives a file |
| `KP000001.TXT` | kpub file, plain: abandon 12's kpub |
| `KP000002.TXT` | kpub file, `KAS\x03`: abandon 12's kpub |
| `KP000003.TXT` | kpub file, `KAS\x03`: abandon 12's cosigner kpub |
| `TX000001.KSP` | Signed transaction, `KAS\x03`: `device/kspt_send_1in.reply.bin` |
| `TX000002.KSP` | Signed transaction, plain: the same reply |

### `card.sectors`

A card the tag formatted and wrote: its `do_format_fat32` on a blank card
of 70,000 sectors, then every file in `cards/` in the order above, each
written as `write_file_to_sd` writes it (a delete that finds nothing, then a
create). Stored sparse: a text line `KASSIGNER-CARD sectors=70000`, then
each sector that is not all zeros as its number (`u32`, little-endian) and
its 512 bytes.

### `unit/`

Written by a provisioned unit running the v1.0.7 release, with abandon 12
selected: the only files here not generated, so their salts, nonces and
names are the unit's own. They check that the released image writes what
the tag's source does: they open here as the generated ones do, and have
the same lengths.

| Name | What |
|---|---|
| `SD000001.KAS` | Seed backup, `KAS\x04` purpose 1: abandon 12, password `abc` |
| `KP000001.TXT` | kpub file, `KAS\x03`: abandon 12's kpub, password `abc` |
| `KP000002.TXT` | kpub file, plain: abandon 12's kpub |

## On hardware

The frames were checked on hardware too: a 2-of-3 reply a provisioned unit
showed at Safe, read by a v1.1.0 unit.
