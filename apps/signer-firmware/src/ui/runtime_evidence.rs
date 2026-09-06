//! Workflow-runtime physical screen evidence.

use crate::runtime::input::AppState;

pub(super) fn record(state: AppState, handled: bool) {
    if !cfg!(feature = "workflow-runtime-auto") {
        core::hint::black_box((state, handled));
        return;
    }
    if handled {
        crate::log!("KASSIGNER_UI_RUNTIME: RENDER {:?}", state);
    } else {
        crate::log!("KASSIGNER_UI_RUNTIME: RENDER-MISS {:?}", state);
    }
}
