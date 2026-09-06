// KasSigner — shared constant-time comparison facade for firmware.
//
// The implementation lives in `shared-signer` so firmware, watcher/security
// policy, and host mutation tests exercise one authoritative primitive.

pub use shared_signer::bytes::constant_time_eq as eq;
