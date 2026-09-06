[KasSigner](../../README.md) › [Documentation](../README.md) › Development › Repository Architecture

# Repository Architecture and Original-Code Migration Map

This document is the short navigation map for the 2.0 refactor. It explains **where responsibilities live now** and where contributors familiar with the original `core/`, `bootloader/`, and `kassee/` layout should look first. Detailed firmware boundaries remain in [Firmware Architecture](FIRMWARE_ARCHITECTURE.md); third-party wallet integration is documented in [Wallet Integration](../integration/WALLET_INTEGRATION.md).

The machine-readable compatibility baseline for the original 1.0.7 feature surface and numeric limits is `qa/contracts/parity/original_feature_capabilities.json`.

## Dependency direction

Arrows below mean **consumer → dependency**. Dependencies must point toward smaller, more reusable layers; trusted firmware/device policy must not leak upward into the permissively licensed integration crates.

```text
apps/signer-firmware (GPL, ESP32-S3 application)
  ├──> offline-signer (GPL, private-key/signing domain)
  ├──> signer-firmware-core (GPL, host-testable device policy)
  ├──> kassigner-protocol (MIT/Apache, no_std protocol core)
  └──> shared-signer (MIT/Apache, smallest shared primitives)

signer-firmware-core ──> kassigner-protocol ──> shared-signer
offline-signer       ──> kassigner-protocol ──> shared-signer

apps/kassee-web (GPL, browser/WASM application)
  ├──> online-watcher (GPL, watch-only wallet/domain/network logic)
  └──> kassigner-sdk (MIT/Apache, third-party wallet facade)
             └──> kassigner-protocol ──> shared-signer

online-watcher ──> kassigner-protocol
online-watcher ──> shared-signer

apps/kassee-android ──┐
apps/kassee-ios     ──┼──> generated/shared KasSee Web runtime + thin native host
browser KasSee      ──┘
```

### Current ownership rules

| Area | Owner | Boundary |
| --- | --- | --- |
| Small cross-side wire/byte primitives | `crates/shared-signer` | No device UI, storage policy, private signing workflow, or KasSee application logic. |
| Public KasSigner wire formats and interoperability rules | `crates/kassigner-protocol` | Canonical KSPT/PSKT-adjacent bridge formats, QR framing/session rules, account/pairing/network types, multisig descriptor parsing. `no_std` where hardware needs the same implementation. |
| Friendly third-party wallet integration surface | `crates/kassigner-sdk` | Host-side facade over protocol operations. Does not own coin selection, node access, broadcast policy, or private keys. |
| Trusted cryptographic signing domain | `crates/offline-signer` | Private derivation, signing, sighash, transaction ownership/change validation, storage crypto. No peripheral/UI ownership. |
| Host-testable physical-device policy | `crates/signer-firmware-core` | Input/power/storage/update/backup/presentation/entropy decisions that should be tested without ESP hardware. No board-register/peripheral ownership. |
| ESP32-S3 hardware/application integration | `apps/signer-firmware` | Board drivers, event loop, trusted-screen UI, camera/SD/touch integration, boot/runtime composition. |
| Watch-only wallet/domain/network engine | `crates/online-watcher` | Address/UTXO state, transaction planning, covenants, multisig coordination, stealth, node queries/submission, WASM-facing wallet services. |
| Browser reference wallet | `apps/kassee-web` | KasSee HTML/CSS/JS and WASM composition; reference consumer of `kassigner-sdk`. |
| Native mobile hosts | `apps/kassee-android`, `apps/kassee-ios` | Thin platform lifecycle/security/camera/file hosts around the shared KasSee runtime; do not fork wallet business logic. |

## Original path → current owner

This table is intentionally about **ownership**, not a promise that files map one-for-one. Large original modules were decomposed by responsibility.

| Original repository area | Current owner(s) | What moved there |
| --- | --- | --- |
| `core/src/wallet/bip39.rs`, BIP39 word/seed logic | `crates/offline-signer/src/derivation/bip39/` | Mnemonic encoding, seed derivation, word handling. |
| `core/src/wallet/bip32.rs`, private HD derivation | `crates/offline-signer/src/derivation/bip32/` | Private child derivation, paths, address-key lookup. |
| Original watch-only/public BIP32/kpub handling | `crates/kassigner-protocol/src/account/` | Public account parsing/derivation needed by host integrations. |
| `core/src/wallet/bip85.rs` | `crates/offline-signer/src/derivation/bip85.rs` | BIP85 child mnemonic derivation. |
| `core/src/wallet/schnorr.rs`, message/ECIES crypto | `crates/offline-signer/src/crypto/` | Secret-key cryptography and signing primitives. |
| `core/src/wallet/transaction.rs`, sighash implementation | `crates/offline-signer/src/transaction/model/`, `transaction/sighash/` | Bounded signer transaction model and consensus signing digest. |
| `core/src/wallet/pskt.rs` compact KSPT grammar | `crates/kassigner-protocol/src/wire/kspt/` | **One canonical no-std KSPT wire codec** used by host and hardware. |
| `core/src/wallet/pskt.rs` signer policy/validation | `crates/offline-signer/src/transaction/kspt/`, `transaction/std_pskt/` | Hardware-side adaptation, validation and signing behavior around canonical wire data. |
| Original multisig descriptor parsing | `crates/kassigner-protocol/src/wire/multisig_descriptor.rs` | One canonical descriptor parser for host and device. |
| `core/src/fat32.rs` and pure storage decisions | `crates/signer-firmware-core/src/storage/` | Host-testable FAT/storage parsing and policy; physical card adapters remain in firmware. |
| `core/src/entropy.rs` and pure entropy decisions | `crates/signer-firmware-core/src/entropy/` + `apps/signer-firmware/src/services/entropy/` | Pure health/mixing policy in firmware-core; hardware sampling/composition in the app. |
| Original SeedQR/stego pure codecs | `crates/signer-firmware-core/src/backup/` | Host-testable SeedQR and picture-carrier logic. |
| `bootloader/src/hw/**` | `apps/signer-firmware/src/hw/**` | Waveshare/M5Stack/board-specific camera, display, touch, SD and register drivers. |
| `bootloader/src/ui/**` | `apps/signer-firmware/src/ui/**` | Trusted-screen drawing and interaction surfaces. |
| `bootloader/src/app/**`, handlers and state machine | `apps/signer-firmware/src/runtime/**` | Firmware event loop, navigation, interaction orchestration and workflow composition. |
| Pure firmware input/power/presentation/update decisions formerly mixed with `bootloader` | `crates/signer-firmware-core/src/{input,power,presentation,update,runtime,time}/` | Hardware-independent policy extracted so normal host QA exercises it. |
| Original backup/encrypted-container workflows | `apps/signer-firmware/src/services/backup/`, `services/stego/` + `crates/offline-signer/src/crypto/` + `signer-firmware-core` codecs | Application workflow, cryptographic container operations and pure media/decision logic separated by concern. |
| `kassee/src/address.rs`, `bip32.rs` | `crates/online-watcher/src/account/` + `crates/kassigner-protocol/src/account/` | Watch-only account state and reusable public-account protocol pieces. |
| `kassee/src/pskt.rs`, `kspt.rs`, `qr.rs` | `crates/online-watcher/src/protocol/` + `crates/kassigner-protocol/src/{pskt,qr,wire}/` + `crates/kassigner-sdk` | KasSee-specific orchestration is a consumer; canonical public protocol/QR behavior lives below it. |
| `kassee/src/rpc.rs` | `crates/online-watcher/src/network/` | Resolver, wRPC queries, fees, UTXOs and submission. |
| `kassee/src/stealth.rs` | `crates/online-watcher/src/privacy/stealth/` | Stealth account/payment scanning and metadata. |
| `kassee/src/*covenant*`, oracle, ZK and transaction builders | `crates/online-watcher/src/contracts/`, `transaction_builder/`, `wasm_api/contracts/` | Covenant/domain construction, validation, spending and WASM facade. |
| `kassee/web/**` | `apps/kassee-web/web/**` | Authored KasSee browser UI/runtime. Android/iOS consume generated copies rather than maintaining divergent wallet logic. |
| `rqrr_nostd/**` | `external/rqrr-nostd/**` | Vendored/controlled QR decoder dependency kept as an independent external Cargo workspace outside first-party crates. |
| `hardware/**` | `external/hardware/**` | Hardware references/vendor material, not product logic. |
| Original `tools/**` | `tools/**`, `scripts/**`, `qa/**` | Reusable tool implementations stay in `tools`; public command wrappers live in `scripts`; assurance/gates live in `qa`. |
| Secure Boot / Pop It! / owner-authority release tooling | `apps/signer-firmware/src/runtime/interactions/settings/advanced/owner_firmware.rs`, `apps/signer-firmware/src/services/persistent_wallet/device/boot_control.rs`, `tools/build/firmware/secure_bootloader/m5stack/`, `tools/build/firmware/owner_authority.py` | Provisioning UI/request staging is compile-time excluded from normal production and enabled only for development simulation or the opt-in `secure-provisioning` / `secure-owner-only` profiles; irreversible eFuse/OTA policy is enforced by the dedicated signed bootloader; host tooling builds enrollment records and owner-signed application images without storing private keys in source. |

## Where to make a change

Use the narrowest owner that can express the change:

- Changing the **bytes on the wire** or a public descriptor/QR rule → `kassigner-protocol`.
- Changing how a third-party wallet **invokes** KasSigner without changing the wire format → `kassigner-sdk`.
- Changing what the device is allowed to **cryptographically sign** → `offline-signer`.
- Changing pure device policy such as input, storage, update, backup or presentation decisions → `signer-firmware-core`.
- Changing an ESP32 peripheral, board, trusted-screen flow or firmware runtime integration → `apps/signer-firmware`.
- Changing CoreS3 Secure Boot, Pop It!, owner-key enrollment, or owner-application install policy → coordinate `apps/signer-firmware` with `tools/build/firmware/secure_bootloader/m5stack/`; application code stages consent/requests, while the second-stage bootloader owns irreversible eFuse and OTA-selection enforcement.
- Changing wallet UTXO selection, node access, transaction planning, covenant coordination or watch-only state → `online-watcher`.
- Changing KasSee presentation/browser interaction → `apps/kassee-web` unless it is truly platform-native lifecycle/security plumbing.

Do not move implementation upward merely for convenience. In particular, `offline-signer` must not absorb board/UI code, `shared-signer` must not become a miscellaneous bucket, and `online-watcher` must not own a second implementation of public KasSigner wire protocols.

## Compatibility contract

`qa/contracts/parity/original_feature_capabilities.json` is the authoritative machine-readable baseline for the latest original 1.0.7 repository. It records the original user-facing feature set, original firmware feature flags, important numeric limits, current owners, and intentional compatibility/security deltas. QA validates that its mapped current owners still exist and that original feature flags remain accounted for.

A refactor may change file layout freely, but it must not silently remove a baseline capability or alter an important limit. Intentional changes belong in the manifest with an explicit disposition instead of being hidden by source movement.
