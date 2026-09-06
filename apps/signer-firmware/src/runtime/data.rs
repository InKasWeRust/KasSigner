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

// runtime/data.rs — Focused firmware state aggregate
//
// AppData is the stable handler-facing root. Each subsystem owns mutable state
// in a dedicated struct, while hardware peripherals remain outside AppData
// because their lifetimes are tied to `main`.

mod runtime;
mod presentation;
mod navigation;
mod wallet;
mod export;
mod storage;
mod qr;
mod signing;
mod stego;
#[cfg(feature = "waveshare")]
mod camera;
mod settings;
#[cfg(feature = "provisioning-ui")]
mod pop_it;
mod placement;
#[cfg(feature = "workflow-tests")]
mod workflow_tests;

pub use self::runtime::{DestructiveHoldState, RuntimeState};
pub use self::presentation::{ModalState, OperationKind, OperationPhase, PresentationState};
#[cfg(not(feature = "hardware-tests"))]
pub(crate) use self::presentation::OperationExecution;
pub use self::navigation::NavigationState;
pub use self::wallet::WalletState;
pub use self::export::ExportState;
pub use self::storage::{
    AdvancedAvailability, ConfirmationState, DeviceStorageIntent, DuressActivation,
    EncryptedFileOperation,
    EncryptedPayloadKind, PendingStorageAction, PersistenceBackendState, PolicyIntegrity, StorageState, TextFileKind,
    TextFileList, UnlockFeedback,
};
#[cfg(feature = "m5stack")]
pub use self::storage::RtcVerification;
pub use self::qr::{OutgoingQrPurpose, QrState};
#[cfg(all(
    not(feature = "hardware-tests"),
    any(
        not(feature = "workflow-test-auto"),
        all(feature = "m5stack", feature = "workflow-runtime-auto")
    )
))]
pub use self::qr::CameraScanFault;
pub use self::signing::{AntiKleptoPhase, CovenantSigningMode, CovenantSigningPhase, PrivateSwapMode, PrivateSwapPhase, OutputOwnership, SigningState};
pub use self::stego::StegoState;
#[cfg(feature = "waveshare")]
pub use self::camera::CameraState;
pub use self::settings::{ScreenDimTimeout, SettingsState};
#[cfg(feature = "provisioning-ui")]
pub use self::pop_it::PopItState;
#[cfg(feature = "workflow-tests")]
pub(crate) use self::workflow_tests::WorkflowTestState;

/// Stable root state passed to firmware controllers and renderers.
pub struct AppData {
    pub runtime: RuntimeState,
    pub presentation: PresentationState,
    pub navigation: NavigationState,
    pub wallet: WalletState,
    pub export: ExportState,
    pub storage: StorageState,
    pub qr: QrState,
    pub signing: SigningState,
    pub stego: StegoState,
    #[cfg(feature = "waveshare")]
    pub camera: CameraState,
    pub settings: SettingsState,
    #[cfg(feature = "provisioning-ui")]
    pub pop_it: PopItState,
    #[cfg(feature = "workflow-tests")]
    pub(crate) workflow_tests: WorkflowTestState,
}

