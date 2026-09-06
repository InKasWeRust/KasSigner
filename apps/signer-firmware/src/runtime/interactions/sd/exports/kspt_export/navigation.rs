//! Navigation helpers for the explicit encrypted-file operation lifecycle.

use super::super::super::AppData;
use crate::runtime::{data::EncryptedFileOperation, navigation::ContinuationRoute};

pub(super) fn navigate_from_password(ad: &mut AppData, operation: EncryptedFileOperation) {
    finish_operation(ad, operation.back_state());
}

pub(super) fn finish_operation(ad: &mut AppData, route: ContinuationRoute) {
    ad.storage.export_file.encrypted_operation = EncryptedFileOperation::None;
    ad.wallet.seeds.pp_input.reset();
    crate::runtime::effects::continue_to(ad, route);
}
