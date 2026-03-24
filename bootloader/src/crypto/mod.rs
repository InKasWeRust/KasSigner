// crypto/mod.rs — Security cryptographic primitives
//
// This module provides security primitives for the entire project:
//   - Constant-time comparison (constant_time)
//   - Secure memory zeroization (secure_zeroize)
//   - XOR-masked secret containers (secret_box)
//   - Flow integrity counters (flow)

pub mod constant_time;
pub mod secure_zeroize;
pub mod secret_box;
pub mod flow;
