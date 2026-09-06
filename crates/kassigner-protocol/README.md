[KasSigner](../../README.md) › [Documentation](../../docs/README.md) › [Wallet Integration](../../docs/integration/WALLET_INTEGRATION.md) › Protocol

# KasSigner Protocol — Rust/WASM

`kassigner-protocol` is the low-level, network-free KasSigner protocol library. It is implemented in Rust and builds as both an `rlib` and a `wasm-bindgen` WebAssembly package.

KasSee is a reference consumer. Third-party wallets communicate directly with KasSigner hardware and never request signing services or wallet state from KasSee.

## Boundary

The crate owns descriptor/privacy pairing, typed networks and derived addresses, the **single canonical compact KSPT v4 wire codec**, PSKT/PSKB → KSPT adaptation, raw QR framing and instance-owned reassembly, signed-response validation/merge, derivation-metadata encoding, and optional standard finalization. It does not choose UTXOs, fees, outputs, change policy, providers, or broadcast behavior.

## `no_std` wire core

`kassigner-protocol` supports `default-features = false` for constrained consumers. The allocation-free `wire::kspt` core owns KSPT magic/version/flags, compact script lengths, signature records, network/derivation/MS45/covenant trailers, canonical trailer ordering, and binary decode/encode. `wire::pskt_envelope` owns the canonical PSKB/PSKT envelope magic, while `wire::qr_payload` owns the public raw-QR payload envelope. These modules read from `&[u8]` and, where encoding is required, write into caller-provided buffers or bounded values rather than duplicating wire discriminators in consumers.

KasSigner hardware consumes that exact codec through a bounded `offline-signer` adapter; KasSee and the SDK use host adapters over the same grammar. `wire::multisig_descriptor` likewise owns the bounded `multi`/`multi_hd`/`multi_hd45` grammar so firmware and KasSee do not maintain separate parsers. Cryptographic transaction interpretation, private-key operations, anti-klepto signing mechanics and signing remain in `offline-signer`; physical review/seed-entropy authorization and device behavior live in the GPL-only `signer-firmware-core` outside the SDK dependency graph.

```toml
[dependencies]
kassigner-protocol = { version = "=2.0.0", default-features = false }
```

## Native Rust and stable errors

The default `host` feature is native Rust and does **not** pull `wasm-bindgen` or `js-sys`. Public fallible integration APIs return `ProtocolResult<T>` with a stable `ProtocolErrorKind`; callers can match categories such as `WrongNetwork`, `TransactionMismatch`, `PairingMismatch`, `Qr`, and `Finalization` without parsing diagnostic text. Public extensible enums such as `Network` are `#[non_exhaustive]`, so integrations should include a wildcard arm when matching them.

From a source checkout, keep the exact version and workspace path together:

```toml
[dependencies]
kassigner-protocol = { version = "=2.0.0", path = "../kassigner-protocol" }
```

After `2.0.0` is published to crates.io, an external consumer can use:

```toml
[dependencies]
kassigner-protocol = "=2.0.0"
```

```rust
use kassigner_protocol::{Network, SigningRequest, SigningResponse};

let request = SigningRequest::from_pskt(&pskt_hex, Network::Mainnet)?;
for frame in request.qr_frames() {
    wallet_ui.render_qr(&frame.payload)?; // host chooses the renderer
}

let response = SigningResponse::decode(&scanned_response_hex)?;
let merged = response.merge_into(&request.original_pskt_hex, request.network)?;
```

## Privacy pairing

Privacy requests carry explicit receive/change ranges plus a wallet-generated nonce. Responses echo the request and include a stable account fingerprint. Returned entries are typed `DerivedAddress { address, branch, index }` values. The signer stores no per-host address cursor.

Use `attach_input_derivation` / `attach_output_derivation` rather than hand-authoring KasSigner proprietary PSKT fields. KSPT v4 treats an input derivation as untrusted and verifies the derived key against the UTXO script before signing.

## WebAssembly

WASM support is explicit rather than part of the native dependency graph. The build wrappers compile with `--no-default-features --features wasm`. Run `./build.sh` on Linux/macOS or `build.ps1` on Windows. The generated `pkg/` package is named `@kassigner/protocol`. Its JavaScript is `wasm-bindgen` loader/binding output only; protocol behavior is Rust/WASM.

See `docs/integration/WALLET_INTEGRATION.md` and `docs/integration/vectors/kassigner_sdk_v2.json` for the integration contract and deterministic vectors.

## License

`kassigner-protocol` is dual-licensed under **MIT OR Apache-2.0**. Its transitive low-level dependency `shared-signer` carries the same permissive terms, so native and WASM wallet integrations do not inherit the GPL terms of the KasSigner/KasSee applications. The standalone application, firmware, `signer-firmware-core`, `offline-signer`, and `online-watcher` remain GPL-3.0.

## Reference signer capability contract

`SignerCapabilities` and `limits()` expose the no-std compatibility limits of the KasSigner v2 reference device. The offline signer consumes the same constants, so host wallets and device validation share one source of truth for KSPT generation, transaction bounds, multisig capacity, and QR framing.
