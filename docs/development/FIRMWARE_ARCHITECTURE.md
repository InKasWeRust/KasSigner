# KasSigner Firmware Architecture

KasSigner firmware uses an event-driven finite-state machine with unidirectional data flow. It is MVC-like, but embedded firmware needs explicit effect, presentation, operation, service, and hardware boundaries that classic web MVC does not model.

## Runtime flow

```text
hardware input
    ↓
pure controller (`controllers.rs`)
    ↓ interaction domain
runtime interaction adapter (`runtime/interactions/`)
    ↓ typed navigation / presentation / operation request
navigation + presentation state (`runtime/navigation`, `runtime/data/presentation`)
    ↓
renderer (`ui/redraw`)
    ↓ loading/modal must be physically visible before expensive work
unified operation engine (`runtime/event_loop/operation_engine`)
    ↓ execution policy: ForegroundExclusive or Stepped
service / crypto / persistence / hardware adapter
    ↓ typed result
navigation + presentation state
    ↓
renderer
```

State flows downward through this pipeline. Lower layers do not invent navigation state, and the pure controller boundary owns no peripheral or service capability.

## Ownership boundaries

| Layer | Owns | Must not own |
| --- | --- | --- |
| `controllers.rs` | normalized input classification | display, I2C, delay, flash, persistence, crypto, services |
| `runtime/interactions/` | event-loop-owned adapters that translate classified input into application effects | authoritative long-operation lifecycle |
| `runtime/navigation/` | stable `AppState`, history and route validation | crypto, storage or peripheral work |
| `runtime/data/presentation/` | one transient operation lifecycle and modal state | driver-specific worker internals |
| `runtime/presentation/` | presentation transitions and recoverable/fatal UI errors | device business logic |
| `runtime/event_loop/operation_engine/` | `Presented → Running`, execution strategy dispatch, timeout/cancel policy | stable-screen routing policy |
| operation drivers | one operation's mechanical work and typed completion/failure | starting a second presentation state machine |
| `services/` + signer crates | domain/security logic, parsing, persistence and crypto | direct UI navigation |
| `hw/` | board/peripheral primitives | application state policy |
| `ui/` | deterministic rendering from state | service calls or blocking business operations |

### Trusted crate boundaries

The host-testable signer stack is intentionally split by responsibility rather than by whether code happens to run on the device:

```text
shared-signer          = genuinely cross-side wire/session primitives
kassigner-protocol     = what externally exchanged bytes and formats mean
offline-signer         = whether/how transaction material is cryptographically signed
signer-firmware-core   = how the physical device behaves around that signer
apps/signer-firmware   = ESP32-S3 board/peripheral adapters and event-loop integration
```

`signer-firmware-core` is `no_std`, GPL-3.0-only, and remains in the normal host-testable workspace. It owns pure input/power/storage decisions, presentation reducers, camera DMA/register plans, BM8563 state, worker-mailbox models, firmware-update/attestation formats, QR classification, SeedQR/steganographic backup logic, advanced policy, entropy health and physical signing authorization. It must not depend on ESP HAL, browser/WASM APIs, `offline-signer`, or `online-watcher`.

`shared-signer` is deliberately narrower: account-key and byte primitives, anti-klepto/covenant wire material, PSKT input types, pairing, and low-level QR frame/session primitives that are genuinely consumed across independent sides. The public raw QR payload envelope, PSKT/PSKB magic, KSPT grammar, and multisig descriptor syntax are owned by `kassigner-protocol`. Encrypted-storage credential metadata belongs to `offline-signer`, while PIN/password acceptance, confirmation, and retry behavior belongs to `signer-firmware-core`; the firmware app adapts those two GPL owners without putting device policy into the permissive SDK graph. Device-only policy must not leak back into `shared-signer`.

## One long-operation lifecycle

Every expensive operation uses the same authoritative lifecycle:

```text
Idle → Queued → Presented → Running/Progress → terminal → Idle
```

`Queued → Presented` happens only when the loading surface has actually been rendered. The operation engine alone performs `Presented → Running`. Drivers may report progress and terminal success/failure through the presentation facade, but they do not start themselves.

There are two execution strategies, not two state machines:

- `Stepped`: Connect KasSee, multisig kpub and transaction signing advance in bounded event-loop steps.
- `ForegroundExclusive`: persistent PIN/password save/unlock renders Loading first, acknowledges the runtime watchdog, then runs one credential KDF synchronously on the normal application/event-loop core. The peer derivation worker remains alive and is never hard-stalled for Argon2. No ordinary peripheral frame runs concurrently. Multi-candidate unlock returns to the outer liveness boundary between KDF attempts.

All firmware Argon2 users enter through `services/memory/password_kdf.rs`; that single adapter enforces PSRAM provenance and a direct caller-owned workspace without any peer-core stall. Persistent credentials additionally use the reusable `ForegroundExclusive` event-loop lane so the loading surface and watchdog boundary are centralized, while backups, steganographic recovery, encrypted transport and benchmark paths reuse the same KDF implementation without duplicating board-specific memory policy.

Driver-internal worker state (for example Core1 kpub generations) is implementation state only. It cannot become a second user-visible operation lifecycle.

## Error and panic policy

Recoverable runtime failures are data:

```text
service Result::Err
    ↓
presentation recoverable error / credential retry state
    ↓
explicit user acknowledgement or retry
    ↓
known stable screen
```

Panics are not a recovery mechanism. Production service/domain code is statically checked to forbid `panic!`, `.unwrap()`, `.expect()` and `unreachable!()` in the enforced service/domain roots. External-input parsers must use checked bounds/arithmetic and return typed malformed-input errors. The JPEG/stego carrier lives in `signer-firmware-core` so host property tests and the `stego_picture_parser` libFuzzer target exercise the same parser used by firmware without exposing device backup internals through the SDK dependency graph.

Fatal boot prerequisites that cannot safely continue (for example invalid PSRAM provenance before the application loop starts) fail closed without unwinding through application state.

An intentional security reset is allowed only for explicitly classified security transitions such as duress, Pop It!, owner-key enrollment, or owner-firmware installation. Ordinary errors must never reset the MCU.

## Input epoch policy

Interactive redraws establish a fresh touch epoch. Credential entry is stricter than ordinary menus: a physical release is required between keys and multi-touch samples are rejected fail-closed. This prevents rapid/multi-finger input from being reinterpreted as multiple credential actions.

## Architecture gates

Repository QA enforces, among other things:

- no legacy effectful `src/controllers/` tree;
- pure `controllers.rs` cannot import hardware/UI/service/persistence capabilities;
- one presentation operation lifecycle; no credential-specific parallel machine;
- one operation-engine `Presented → Running` owner;
- loading render occurs before operation execution in the event loop;
- production service/domain panic-capable constructs are forbidden in the guarded roots;
- explicit checked arithmetic plus host property/fuzz coverage for the JPEG/stego external-input parser;
- software reset remains restricted to deliberate security-reset paths;
- existing module/SRP, UI graph, production E2E and runtime qualification gates remain active.
