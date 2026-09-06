// Application-state predicates kept separate from the large AppState declaration.

use super::AppState;

impl AppState {
    /// True only for states that render a scanner-facing QR matrix. Manual
    /// SeedQR grid inspection and QR configuration menus are deliberately not
    /// included because they do not present a scannable code.
    pub const fn shows_scannable_qr(self) -> bool {
        matches!(
            self,
            Self::ShowQR
                | Self::ShowAddressQR
                | Self::ExportSeedQR
                | Self::ExportCompactSeedQR
                | Self::ExportPlainWordsQR
                | Self::ExportKpub
                | Self::ExportPrivKey
                | Self::ExportXprv
                | Self::MultisigShowAddressQR
                | Self::SignMsgResultQr
                | Self::CovenantKeyResultQr
                | Self::CovenantSignResultQr
                | Self::PrivateSwapKeyResultQr
                | Self::PrivateSwapResultQr
                | Self::CommitRevealResultQr
                | Self::DecryptSecretResultQr
        )
    }
}


/// Whether the state requires the live QR/ciphertext/message scanner.
///
/// Kept in the always-compiled input model so presentation and hardware-test
/// builds do not depend on the production event-loop module.
#[must_use]
pub const fn is_scan_state(state: AppState) -> bool {
    matches!(
        state,
        AppState::ScanQR | AppState::DecryptSecretScan | AppState::SignMsgScan
    )
}
