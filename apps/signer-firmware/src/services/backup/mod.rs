// KasSigner — Air-gapped offline signing device for Kaspa
//! Device-bound removable wallet backups plus encrypted KSPT transport KDF.
//!
//! Seed and account-XPrv backups require both a validated password and the
//! signer's read-protected eFuse HMAC key. Historical password-only wallet
//! containers are not accepted. Retired recovery-hint raw containers have no production façade.

mod container;
mod device;
mod error;
mod randomness;
mod seed;
mod xprv;

pub use container::{kind as backup_kind, BackupKind};
pub use device::BackupDevice;
pub use error::BackupError;
pub use seed::{MAX_BACKUP_SIZE, decrypt_backup_progress, encrypt_backup_progress};
pub use xprv::{MAX_XPRV_BACKUP_SIZE, MAX_XPRV_DATA, decrypt_xprv_backup_progress, encrypt_xprv_backup};

#[cfg(test)]
pub(crate) use container::open as test_open;
#[cfg(any(test, feature = "workflow-test-auto"))]
pub(crate) use container::seal_for_test;
#[cfg(test)]
pub(crate) use container::seal_legacy_for_test;
