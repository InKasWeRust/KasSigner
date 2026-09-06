// runtime/data/pop_it.rs — User-controlled Secure Boot provisioning UI state

use crate::runtime::navigation::ContinuationRoute;

pub struct PopItState {
    pub return_state: ContinuationRoute,
    pub owner_authority_enrolled: bool,
    pub error: Option<&'static str>,
}

impl PopItState {
    pub(super) fn new() -> Self {
        Self {
            return_state: crate::runtime::navigation::continuation!(SettingsMenu),
            owner_authority_enrolled: false,
            error: None,
        }
    }
}
