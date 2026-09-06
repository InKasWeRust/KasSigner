//! Stack-safe one-shot placement of the long-lived application state.

use core::ptr::NonNull;
use static_cell::StaticCell;

use super::{
    AppData, ExportState, NavigationState, PresentationState, QrState,
    RuntimeState, SettingsState, SigningState, StegoState, StorageState, WalletState,
};
use super::wallet::{AddressState, KeyMaterialState, SeedSession};
#[cfg(feature = "waveshare")]
use super::CameraState;
#[cfg(feature = "workflow-tests")]
use super::WorkflowTestState;
#[cfg(feature = "provisioning-ui")]
use super::PopItState;


pub(crate) struct InitializedAppData {
    ptr: NonNull<AppData>,
}

impl InitializedAppData {
    /// Consume the unique one-shot initialization token and expose the static
    /// application root. The token is only constructed after `StaticCell` has
    /// been claimed and every `AppData` field has been initialized exactly once.
    pub(crate) fn into_mut(mut self) -> &'static mut AppData {
        // SAFETY: construction of `InitializedAppData` is private to
        // `AppData::try_initialize`, which obtains exclusive ownership from the
        // one-shot `StaticCell`. Consuming the non-Copy token prevents safe code
        // from materializing a second mutable reference.
        unsafe { self.ptr.as_mut() }
    }
}

#[inline(never)]
unsafe fn place_runtime(target: *mut RuntimeState) {
    target.write(RuntimeState::new());
}

#[inline(never)]
unsafe fn place_presentation(target: *mut PresentationState) {
    target.write(PresentationState::new());
}

#[inline(never)]
unsafe fn place_navigation(target: *mut NavigationState) {
    target.write(NavigationState::new());
}

#[inline(never)]
unsafe fn place_wallet_seeds(target: *mut SeedSession) {
    target.write(SeedSession::new());
}

#[inline(never)]
unsafe fn place_wallet_keys(target: *mut KeyMaterialState) {
    target.write(KeyMaterialState::new());
}

#[inline(never)]
unsafe fn place_wallet_addresses(target: *mut AddressState) {
    target.write(AddressState::new());
}

#[inline(never)]
unsafe fn place_wallet(target: *mut WalletState) {
    // Do not materialize WalletState::new() as one aggregate here. On Xtensa with
    // release LTO the WalletState constructor grew to an 8,560-byte frame,
    // exceeding the strict 8 KiB first-party stack budget. Place each child at
    // its final static address behind its own no-inline constructor boundary.
    place_wallet_seeds(core::ptr::addr_of_mut!((*target).seeds));
    place_wallet_keys(core::ptr::addr_of_mut!((*target).keys));
    place_wallet_addresses(core::ptr::addr_of_mut!((*target).addresses));
}

#[inline(never)]
unsafe fn place_export(target: *mut ExportState) {
    target.write(ExportState::new());
}

#[inline(never)]
unsafe fn place_storage(target: *mut StorageState) {
    target.write(StorageState::new());
}

#[inline(never)]
unsafe fn place_signing(
    target: *mut SigningState,
    transaction: super::signing::TransactionSigningState,
) {
    SigningState::initialize_in_place(target, transaction);
}

#[inline(never)]
unsafe fn place_stego(target: *mut StegoState) {
    target.write(StegoState::new());
}

#[cfg(feature = "waveshare")]
#[inline(never)]
unsafe fn place_camera(target: *mut CameraState) {
    target.write(CameraState::new());
}

#[inline(never)]
unsafe fn place_settings(target: *mut SettingsState) {
    target.write(SettingsState::new());
}

#[cfg(feature = "provisioning-ui")]
#[inline(never)]
unsafe fn place_pop_it(target: *mut PopItState) {
    target.write(PopItState::new());
}

#[cfg(feature = "workflow-tests")]
#[inline(never)]
unsafe fn place_workflow_tests(target: *mut WorkflowTestState) {
    target.write(WorkflowTestState::new());
}

impl AppData {
    /// Initialize every focused state group directly in the storage owned by the
    /// static cell.
    ///
    /// `AppData` deliberately contains a 16,320-byte internal-SRAM QR buffer plus
    /// other fixed state. Even explicit field writes in one function can let LLVM
    /// coalesce constructor temporaries into an AppData-sized frame under Xtensa
    /// LTO. Each by-value state constructor therefore lives behind its own
    /// no-inline placement boundary, while QR and signing use dedicated in-place
    /// initialization. No whole `AppData` or `QrState` value exists on the ProCpu
    /// stack.
    #[inline(never)]
    pub(crate) fn try_initialize(
        cell: &'static StaticCell<Self>,
    ) -> Result<InitializedAppData, ()> {
        // Complete the only fallible state allocation before claiming the one-shot
        // static cell. The returned transaction root is small because its bulk
        // stores are heap-backed.
        let transaction = SigningState::try_prepare_transaction()?;
        let slot = cell.try_uninit().ok_or(())?;
        let app = slot.as_mut_ptr();

        // SAFETY: `try_uninit` gives this call exclusive ownership of a properly
        // aligned, uninitialized `AppData` slot for the remainder of the program.
        // Every field is written exactly once before `assume_init_mut`; QR and
        // signing perform the same field-complete initialization for their larger
        // aggregates. No reference to `AppData` is created before initialization
        // is complete. The only fallible signing allocation has already succeeded
        // before the static slot is claimed, preserving the one-shot retry boundary.
        unsafe {
            place_runtime(core::ptr::addr_of_mut!((*app).runtime));
            place_presentation(core::ptr::addr_of_mut!((*app).presentation));
            place_navigation(core::ptr::addr_of_mut!((*app).navigation));
            place_wallet(core::ptr::addr_of_mut!((*app).wallet));
            place_export(core::ptr::addr_of_mut!((*app).export));
            place_storage(core::ptr::addr_of_mut!((*app).storage));
            QrState::initialize_in_place(core::ptr::addr_of_mut!((*app).qr));
            place_signing(core::ptr::addr_of_mut!((*app).signing), transaction);
            place_stego(core::ptr::addr_of_mut!((*app).stego));
            #[cfg(feature = "waveshare")]
            place_camera(core::ptr::addr_of_mut!((*app).camera));
            place_settings(core::ptr::addr_of_mut!((*app).settings));
            #[cfg(feature = "provisioning-ui")]
            place_pop_it(core::ptr::addr_of_mut!((*app).pop_it));
            #[cfg(feature = "workflow-tests")]
            place_workflow_tests(core::ptr::addr_of_mut!((*app).workflow_tests));
            Ok(InitializedAppData { ptr: NonNull::from(slot.assume_init_mut()) })
        }
    }
}
