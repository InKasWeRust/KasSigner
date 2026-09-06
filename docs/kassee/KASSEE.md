[KasSigner](../../README.md) › [Documentation](../README.md) › KasSee

# KasSee

KasSee is the browser-based watch-only companion wallet for KasSigner. It imports a kpub/watch-only identity, derives addresses, tracks UTXOs, builds unsigned transactions and covenants, displays QR payloads for offline signing, scans signed responses, and broadcasts them. It never needs the wallet spending private key.

Pure Rust is compiled to WebAssembly and the wallet workflow runs in the browser; no backend wallet service is required.

## Using KasSee

Visit [kassigner.org](https://kassigner.org/), or build KasSee locally and serve `apps/kassee-web/web/` over HTTP/HTTPS.

KasSee connects to a public Kaspa node automatically. To use your own node, open **Settings** and enter your WebSocket URL (`wss://` or `ws://`).

## Features

- **Import kpub** — scan or paste the extended public key exported from KasSigner.
- **Dashboard** — live balance, UTXO count, and funded-address summary.
- **Send** — build unsigned transactions with live **Low / Normal / Priority** fee choices.
- **Send Max** — sweep available wallet funds to one destination after fees.
- **UTXO selection** — manually choose inputs with a configurable limit (default 8) and value ordering.
- **Receive** — display the next receive address with QR while tracking funded/used state.
- **Address reuse prevention** — funded and used addresses are visibly marked; every address has an explorer link.
- **Address list and verification** — receive/change addresses, derivation paths, QR display, copy, and on-device verification workflow.
- **Address history** — optional used-address/transaction discovery through a configured `kaspa-rest-server` indexer.
- **Broadcast** — scan the signed response from KasSigner and submit it to the network.
- **PSKT/PSKB + KSPT v4** — standard and compact air-gapped signing, relay, and broadcast workflows.
- **Animated QR** — multi-frame transport with frame indicators plus previous/next and pause/play controls.
- **UTXO explorer and consolidation** — inspect, select, merge, and manage wallet UTXOs.
- **Multisig** — deterministic sorted-key P2SH creation, spend construction, co-signer relay, and final broadcast.
- **Covenants++** — create, fund, spend, recover, and monitor the supported covenant families.
- **Private Swap / ZK Crowdfunding / Oracle / ZK Price Oracle** — current hardened advanced covenant workflows.
- **Stealth payments** — dual-key stealth send, scan, index, and spend flows.
- **Assets** — KRC-20 balances, KRC-721 NFTs, and KNS domains.
- **Public-node resolver** — automatically discovers a usable public Kaspa WebSocket node when no custom node is configured.
- **Custom node** — use your own `wss://` or `ws://` Kaspa endpoint from Settings.
- **Connection recovery** — retry/reconnect behavior for node-backed live services.
- **Storage-mass awareness** — transaction planning applies KIP-9 storage-mass checks and avoids unsafe tiny change/remainder outputs.
- **Camera scanner** — scan kpubs, signed transactions, descriptors, and other supported QR payloads directly in the browser.
- **Donation page** — project donation address/QR integrated into the UI.
- **PWA/mobile shells** — KasSee remains installable as a web app, while Android and iOS host the same runtime in native shells.

## Building from source

```bash
make kassee
cd apps/kassee-web/web
python3 -m http.server 8080
```

The build pins the Rust/WASM toolchain and matching `wasm-bindgen` CLI. It stages the canonical deployable site at `target/kassee-web/site/` and mirrors only the generated `pkg/` bindings into `apps/kassee-web/web/pkg/` so the local command above works directly. Both locations are generated build output and are excluded from source archives/source-quality accounting.

## Implementation boundary

KasSee keeps browser bindings separate from wallet/covenant policy. `crates/online-watcher/src/wasm_api/` owns the stable JavaScript/WASM ABI, JS error translation, serialization, logging, and explicit RPC-query exports. Browser-neutral covenant construction and validation live under `contracts/`, while UTXO selection, fee/amount policy, PSKT/PSKB construction, spend preparation, and network-backed transaction workflows live under `transaction_builder/`. Architecture QA rejects browser types in those core owners and rejects transaction/covenant business primitives in the WASM adapters.

This boundary is shared by Web, Android, and iOS builds: native shells host the same KasSee runtime instead of maintaining independent wallet policy implementations.

## Safety model

KasSee is not the final trust display. A compromised browser can alter what it shows or encodes. **Always verify the actual address, amount, fee, covenant context, and warnings on the KasSigner device before approving.** A malicious/public node can also learn queried addresses and lie about network state; use your own node when that privacy/trust trade-off matters.

## Android and iOS

- **Android:** `apps/kassee-android` targets Android 17/API 37 and hosts the current KasSee runtime inside a hardened native shell with app locking and privacy/cover behavior. **Tested.**
- **iOS:** `apps/kassee-ios` hosts the same KasSee runtime in a native Swift shell and uses the platform-neutral runtime-sync path. The iOS application has been tested on macOS Sonoma with Xcode 16.2. A signed Release build plus physical-device smoke remains formal release evidence, not a meaningful unresolved iOS application-qualification gap.

See each app's local README for source-layout details.
