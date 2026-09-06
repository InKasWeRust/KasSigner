//! Paging, hit-testing, selection, and delete routing for four-row SD lists.

use crate::{
    hw::touch,
    runtime::{data::AppData, input::AppState, navigation::ContinuationRoute},
};

use super::context::{SdFileListContext, SdListContext};

const FILES_PER_PAGE: usize = 4;
const DELETE_ZONE_MIN_X: u16 = 228;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileListAction {
    None,
    PageChanged,
    Selected {
        index: usize,
        delete_requested: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FileListControllerOutcome {
    None,
    Back,
    PageChanged,
    DeleteRequested,
    OpenRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileListWorkflow {
    pub(in crate::runtime::interactions::sd) allow_delete: bool,
    pub(in crate::runtime::interactions::sd) current_state: AppState,
    pub(in crate::runtime::interactions::sd) back_state: ContinuationRoute,
}


/// Run a file-list workflow from the full SD I/O context.
pub(crate) fn run_sd_file_list_context<'ctx, 'display, 'hal, R>(
    context: SdFileListContext<'ctx, 'display, 'hal>,
    workflow: FileListWorkflow,
    on_open: impl FnOnce(
        &mut AppData,
        &mut crate::hw::display::BootDisplay<'display>,
        &mut esp_hal::delay::Delay,
        &mut dyn FnMut(),
        &mut esp_hal::i2c::master::I2c<'hal, esp_hal::Blocking>,
    ) -> R,
) -> bool {
    let SdFileListContext {
        ad,
        boot_display,
        delay,
        liveness,
        i2c,
        list_zones,
        x,
        y,
        is_back,
    } = context;
    run_file_list_controller(ad, list_zones, x, y, is_back, workflow, |ad| {
        on_open(ad, boot_display, delay, liveness, i2c);
    })
}

/// Run a list-only workflow without exposing its paging plumbing to callers.
pub(crate) fn run_sd_list_context<R>(
    context: SdListContext<'_>,
    workflow: FileListWorkflow,
    on_open: impl FnOnce(&mut AppData) -> R,
) -> bool {
    let SdListContext {
        ad,
        list_zones,
        x,
        y,
        is_back,
    } = context;
    run_file_list_controller(ad, list_zones, x, y, is_back, workflow, on_open)
}

/// Own the common list lifecycle and delegate only the format-specific open action.
fn run_file_list_controller<R>(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; FILES_PER_PAGE],
    x: u16,
    y: u16,
    is_back: bool,
    workflow: FileListWorkflow,
    on_open: impl FnOnce(&mut AppData) -> R,
) -> bool {
    let outcome = handle_file_list_touch(
        ad,
        list_zones,
        x,
        y,
        is_back,
        workflow.allow_delete,
        workflow.current_state,
        workflow.back_state,
    );
    resolve_file_list_outcome(ad, outcome, on_open)
}

fn handle_file_list_touch(
    ad: &mut AppData,
    list_zones: &[touch::TouchZone; FILES_PER_PAGE],
    x: u16,
    y: u16,
    is_back: bool,
    allow_delete: bool,
    current_state: AppState,
    back_state: ContinuationRoute,
) -> FileListControllerOutcome {
    if is_back {
        ad.storage.browser.file_scroll = 0;
        crate::runtime::effects::continue_to(ad, back_state);
        return FileListControllerOutcome::Back;
    }

    let action = navigate_file_list(
        &mut ad.storage.browser.file_scroll,
        ad.storage.browser.file_count,
        list_zones,
        x,
        y,
        allow_delete,
    );
    apply_file_list_action(ad, action, current_state)
}


fn resolve_file_list_outcome<R>(
    ad: &mut AppData,
    outcome: FileListControllerOutcome,
    on_open: impl FnOnce(&mut AppData) -> R,
) -> bool {
    match outcome {
        FileListControllerOutcome::OpenRequested => {
            on_open(ad);
            true
        }
        FileListControllerOutcome::None => false,
        FileListControllerOutcome::Back
        | FileListControllerOutcome::PageChanged
        | FileListControllerOutcome::DeleteRequested => true,
    }
}

fn apply_file_list_action(
    ad: &mut AppData,
    action: FileListAction,
    current_state: AppState,
) -> FileListControllerOutcome {
    match action {
        FileListAction::None => FileListControllerOutcome::None,
        FileListAction::PageChanged => FileListControllerOutcome::PageChanged,
        FileListAction::Selected {
            index,
            delete_requested,
        } => {
            ad.storage.browser.selected_file = ad.storage.browser.file_list[index];
            if delete_requested {
                ad.storage.confirmation.delete_return = crate::runtime::navigation::continuation_from_state(current_state);
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(SdDeleteConfirm));
                FileListControllerOutcome::DeleteRequested
            } else {
                FileListControllerOutcome::OpenRequested
            }
        }
    }
}

fn navigate_file_list(
    scroll: &mut u8,
    file_count: u8,
    list_zones: &[touch::TouchZone; FILES_PER_PAGE],
    x: u16,
    y: u16,
    allow_delete: bool,
) -> FileListAction {
    let scroll_offset = usize::from(*scroll);
    let count = usize::from(file_count);

    if x < 40 && y >= 42 && scroll_offset > 0 {
        *scroll = scroll.saturating_sub(FILES_PER_PAGE as u8);
        return FileListAction::PageChanged;
    }
    if x >= 280 && y >= 42 && scroll_offset.saturating_add(FILES_PER_PAGE) < count {
        *scroll = scroll.saturating_add(FILES_PER_PAGE as u8);
        return FileListAction::PageChanged;
    }

    for (slot, zone) in list_zones.iter().enumerate() {
        if !zone.contains(x, y) {
            continue;
        }
        let index = scroll_offset.saturating_add(slot);
        if index < count {
            return FileListAction::Selected {
                index,
                delete_requested: allow_delete && x > DELETE_ZONE_MIN_X,
            };
        }
        break;
    }
    FileListAction::None
}
