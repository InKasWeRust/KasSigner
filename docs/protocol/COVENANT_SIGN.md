# COVENANT SIGN protocol

`COVENANT SIGN` is KasSigner's universal authorization path for covenants that
need a Schnorr signature over an externally defined 32-byte commitment. It is
intentionally separate from ordinary wallet transaction and message signing.

The protocol has two independent layers:

- **KasSigner envelope:** identifies allocation/binding/signing intent, the
  isolated covenant-key instance, original script/context, portable binding
  record, and anti-klepto transcript.
- **Covenant commitment:** the exact 32 bytes defined by the third-party
  covenant. KasSigner does **not** prepend a domain string, normalize, or hash
  those 32 bytes again before BIP340 signing.

In short: **KasSigner-specific envelope: yes. KasSigner-specific covenant hash:
no.**

## Key isolation and instance allocation

Universal covenant authorization never uses an ordinary Kaspa wallet-spending
private key. Mnemonic/BIP39-passphrase wallets derive signing keys below:

```text
m/10016'/111111'/0'/i0'/i1'/i2'/i3'/i4'
```

`i0..i4` are five hardened 31-bit indices deterministically derived from
`SHA256("KasSigner Covenant Key v1\0" || covenant_instance_id)`. A zero ID is
invalid. Raw private-key and imported account-XPrv slots cannot enter this
master-level hierarchy.

The host does **not** choose the covenant instance ID. A `KeyInfo` request must
carry an all-zero ID. KasSigner obtains fresh hardware entropy, allocates a
nonzero 32-byte ID, derives the isolated covenant public key, and returns both.
Only that current pending allocation may subsequently be bound. A newer
allocation replaces an unbound pending allocation.

This removes host-controlled key reuse from the protocol. A host cannot submit
an old ID and ask KasSigner to allocate or rebind it.

## Portable one-time script binding

After receiving the device-allocated public key, the developer builds the
actual third-party covenant script. Before the covenant is funded, the script
is returned in a `Bind` request.

KasSigner accepts Bind only when the request ID/public key matches its current
pending allocation. Known-mode Bind additionally performs the registered
semantic/canonical-script validation; Opaque Bind performs only the selected
opaque key-presence sanity check, if requested. After user confirmation,
KasSigner returns a **32-byte non-secret binding record**.

The binding record is authenticated using a separate hardened mnemonic branch:

```text
m/10016'/111111'/1'/i0'/i1'/i2'/i3'/i4'
```

Its authenticated data is:

```text
covenant_instance_id || SHA256(exact_script) || derived_covenant_pubkey
```

The binding key itself is never exposed through `COVENANT SIGN`. Every later
Known or Opaque signing request must carry the record. KasSigner re-derives the
binding key from the mnemonic and validates the record against the **exact
script supplied in that request**. Reusing the same ID/record with another
script therefore fails authentication.

The record is portable metadata, not a private key. It must travel with the
covenant's invite/recovery metadata. After mnemonic recovery KasSigner can
re-derive the isolated key and validate the same record; no covenant private
key or mutable on-device covenant registry needs to be stored.

## Request kinds

The binary protocol is version 2. All multibyte lengths are big-endian and
parsers require exact total consumption.

### `CVSG` — request envelope

A `CVSG` request carries:

- request kind: `KeyInfo`, `Bind`, `Known`, or `Opaque`;
- registered Known scheme ID, when applicable;
- optional Opaque binding hint;
- 16-byte anti-klepto session ID;
- 32-byte host-randomness commitment;
- 32-byte covenant instance/key ID;
- 32-byte portable binding record;
- the covenant's **exact 32-byte commitment**;
- bounded original covenant/script bytes; and
- bounded context/preimage bytes for Known requests.

There is no host authorization label. A host-provided description cannot make
an unknown contract "Known" or alter what the device claims to have verified.

`KeyInfo` carries zero session, host commitment, key ID, binding record,
commitment, script, and context. KasSigner selects the ID and returns it with
the derived public key.

`Bind` carries the device-selected ID and exact script, but no previous binding
record or anti-klepto session. A successful Binding response returns the new
record and the exact `SHA256(script)` fingerprint.

### Known / described signing

A Known request is accepted as **verified** only when KasSigner has a registered
recognizer for that scheme. The recognizer must:

1. independently recompute the exact third-party commitment from the supplied
   context;
2. compare it byte-for-byte with the request commitment;
3. validate the **complete canonical covenant script grammar**;
4. prove that the derived covenant key and exact commitment occupy the expected
   authorization positions; and
5. provide device-derived semantics for review.

The portable binding record must also authenticate the exact script before the
request reaches signing review.

Current registered schemes are:

- **SHA-256 preimage** — commitment is exactly `SHA256(context)` and the script
  is exactly `PUSH32(commitment) PUSH32(covenant_key)
  OP_CHECKSIGFROMSTACK`.
- **Oracle-v1** — commitment is exactly `SHA256(exact UTF-8 release statement)`
  and the complete canonical Oracle-v1 covenant grammar must match, including
  the isolated oracle covenant key.

The protocol permits up to **1,024 bytes** of Known context. Firmware retains
that full bound in its covenant-signing state. It rejects invalid UTF-8,
oversized context, and—under the current SHA-256 and Oracle-v1 recognizers—text
outside display-safe printable ASCII rather than truncating or ambiguously
rendering authorization bytes. Review is paged across the entire retained
context, and SIGN/BIND is offered only on the final page. Oracle-v1 uses its own
tighter 256-byte semantic maximum. A future recognizer for non-text/binary
context must define an explicit complete on-device rendering policy before it
may be classified as Known.

### Opaque / custom signing

Opaque mode is for third-party covenants KasSigner does not understand. It
accepts the covenant's exact 32-byte commitment and does **not** claim to know
what it authorizes. Opaque requests carry **zero context bytes** so the host
cannot smuggle undisplayed authorization material into the envelope. The exact
script is still covered by the portable binding record and shown by its SHA-256
fingerprint during confirmation.

An optional `KeyPresent` hint can require the raw x-only covenant key to appear
in script bytes. It is deliberately not mandatory because legitimate custom
covenants may bind a key through hashing, aggregation, or another construction.

Opaque signing uses a stronger two-stage confirmation. The device explicitly
warns that it cannot verify what the hash authorizes, shows the full 32-byte
commitment and covenant/script identity, and can sign only with the isolated
covenant key—not an ordinary wallet-spending key.

## Two-round anti-klepto exchange

Known and Opaque signing use host-assisted anti-klepto without modifying the
third-party commitment:

1. Host generates a fresh 32-byte secret and 16-byte session ID.
2. `CVSG` commits to that secret using the shared KasSigner anti-klepto domain.
3. After complete on-device review, signer returns `CVSR` kind
   `NonceCommitment` with the exact commitment and provisional nonce point.
4. Host verifies transcript identity and sends `CVRV` containing the same
   session, key ID, exact commitment, and host secret.
5. Signer verifies the reveal, finalizes the nonce contribution, verifies the
   nonce relation, and returns `CVSR` kind `Signature`.
6. Host verifies both BIP340 over the **original exact 32-byte commitment** and
   the anti-klepto nonce relation.

The anti-klepto transcript changes nonce derivation, **not the message**.

## `CVSR` — responses

Responses are fixed-length and include response kind, session ID, device
instance ID, x-only covenant public key, binding record, commitment/fingerprint,
compressed nonce point, and signature field.

- `KeyInfo`: returns device-selected ID + covenant pubkey; signing fields zero.
- `Binding`: returns the portable binding record; the commitment/fingerprint
  field contains exact `SHA256(script)`.
- `NonceCommitment`: returns the provisional nonce and exact covenant
  commitment, with no final signature.
- `Signature`: returns the final BIP340 signature over the same exact covenant
  commitment.

## `CVRV` — host reveal

The reveal repeats the session ID, covenant instance ID, and exact commitment,
then supplies the 32-byte host secret. Any mismatch, invalid host commitment,
or unexpected state fails closed and clears the active signing session.

## Oracle-v1

Oracle-v1 uses this common infrastructure rather than the retired KasSigner
message-domain workaround. Its on-chain commitment is exactly:

```text
SHA256(exact UTF-8 Oracle-v1 release statement)
```

The device-allocated isolated oracle covenant key is first bound to the final
canonical Oracle-v1 script. Funding/share actions are withheld until KasSee has
scanned the Binding response and persisted its portable record. Invitations and
encrypted recovery metadata carry the record so another session restored from
the same mnemonic can validate the covenant without storing a covenant private
key.

## Permanent boundary

`COVENANT SIGN` does **not** restore generic `SIGN HASH` for ordinary
wallet-spending keys. Transaction keys sign reviewed transaction commitments;
human-readable wallet messages use their own device-defined message domain;
only the isolated mnemonic covenant hierarchy can authorize arbitrary external
32-byte covenant commitments.

Supporting a new Known covenant requires adding and testing a full recognizer.
A third-party protocol never needs to adopt a proprietary KasSigner covenant
hash to use Opaque mode.
