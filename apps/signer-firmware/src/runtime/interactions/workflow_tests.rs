//! Developer-only on-device facade for headless workflow E2E tests.

use crate::{
    runtime::interactions::{menu_selection::{handle_paged_menu_touch, PagedMenuAction}, TouchInput},
    hw::touch::TouchZone,
    runtime::{data::AppData, input::AppState, workflow_tests::{self, WorkflowCategory}},
};

pub(crate) fn handle(
    ad: &mut AppData,
    list_zones: &[TouchZone; 4],
    page_up: &TouchZone,
    page_down: &TouchZone,
    liveness: &mut dyn FnMut(),
    input: TouchInput,
) -> Option<bool> {
    match ad.navigation.app.state {
        AppState::WorkflowTestsMenu => {
            Some(handle_root(ad, list_zones, page_up, page_down, liveness, input))
        }
        AppState::WorkflowTestsCategory { category } => {
            Some(handle_category(
                ad, category, list_zones, page_up, page_down, liveness, input,
            ))
        }
        AppState::WorkflowTestsResult => Some(handle_result(ad)),
        _ => None,
    }
}

fn handle_root(
    ad: &mut AppData,
    zones: &[TouchZone; 4],
    page_up: &TouchZone,
    page_down: &TouchZone,
    liveness: &mut dyn FnMut(),
    input: TouchInput,
) -> bool {
    if input.is_back { crate::runtime::effects::resume(ad, crate::runtime::navigation::ResumeTarget::WorkflowTests); return true; }
    match handle_paged_menu_touch(&mut ad.navigation.workflow_tests_menu, zones, page_up, page_down, input.x, input.y) {
        PagedMenuAction::PageChanged => true,
        PagedMenuAction::Selected(0) => {
            let summary = workflow_tests::execute(
                workflow_tests::WorkflowCommand::RunAll,
                liveness,
            );
            store_result(ad, summary, true);
            true
        }
        PagedMenuAction::Selected(index) => open_category(ad, index),
        PagedMenuAction::None => false,
    }
}

fn open_category(ad: &mut AppData, menu_index: u8) -> bool {
    let Some(category) = workflow_tests::category_from_menu_index(menu_index) else { return false; };
    ad.workflow_tests.selected_category = category as u8;
    ad.navigation.workflow_category_menu = workflow_tests::category_menu(category);
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(WorkflowTestsCategory { category: category as u8 }));
    true
}

fn handle_category(
    ad: &mut AppData,
    raw_category: u8,
    zones: &[TouchZone; 4],
    page_up: &TouchZone,
    page_down: &TouchZone,
    liveness: &mut dyn FnMut(),
    input: TouchInput,
) -> bool {
    if input.is_back { crate::runtime::effects::route(ad, crate::runtime::navigation::route!(WorkflowTestsMenu)); return true; }
    let Some(category) = WorkflowCategory::from_raw(raw_category) else { return false; };
    match handle_paged_menu_touch(&mut ad.navigation.workflow_category_menu, zones, page_up, page_down, input.x, input.y) {
        PagedMenuAction::PageChanged => true,
        PagedMenuAction::Selected(0) => {
            let summary = workflow_tests::execute(
                workflow_tests::WorkflowCommand::RunCategory(category),
                liveness,
            );
            store_result(ad, summary, false);
            true
        }
        PagedMenuAction::Selected(index) => {
            let Some(spec) = workflow_tests::workflow_at(category, index) else { return false; };
            let summary = workflow_tests::execute(
                workflow_tests::WorkflowCommand::RunOne(spec),
                liveness,
            );
            store_result(ad, summary, false);
            true
        }
        PagedMenuAction::None => false,
    }
}

fn handle_result(ad: &mut AppData) -> bool {
    let result = ad.workflow_tests.result;
    if result.ran_all { crate::runtime::effects::route(ad, crate::runtime::navigation::route!(WorkflowTestsMenu)); }
    else { crate::runtime::effects::route(ad, crate::runtime::navigation::route!(WorkflowTestsCategory { category: ad.workflow_tests.selected_category })); }
    true
}

fn store_result(ad: &mut AppData, summary: workflow_tests::WorkflowSummary, ran_all: bool) {
    ad.workflow_tests.result.total = summary.total;
    ad.workflow_tests.result.passed = summary.passed;
    ad.workflow_tests.result.failed = summary.failed;
    ad.workflow_tests.result.ran_all = ran_all;
    crate::runtime::effects::route(ad, crate::runtime::navigation::route!(WorkflowTestsResult));
}
