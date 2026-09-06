//! Developer/legacy navigation surfaces kept out of the production root.

use crate::{hw::display, runtime::{data::AppData, input::AppState}};

pub(super) fn redraw(ad: &mut AppData, boot_display: &mut display::BootDisplay<'_>) -> bool {
    match ad.navigation.app.state {
        AppState::SeedToolsMenu => boot_display.update_menu_content("SEED TOOLS", &ad.navigation.seed_tools_menu),
        #[cfg(feature = "workflow-tests")]
        AppState::WorkflowTestsMenu => boot_display.update_menu_content("E2E TESTS", &ad.navigation.workflow_tests_menu),
        #[cfg(feature = "workflow-tests")]
        AppState::WorkflowTestsCategory { category } => redraw_workflow_category(ad, boot_display, category),
        #[cfg(feature = "workflow-tests")]
        AppState::WorkflowTestsResult => redraw_workflow_result(ad, boot_display),
        AppState::ImportExportChoice => boot_display.draw_import_export_choice(),
        AppState::ImportMenu => boot_display.update_menu_content("IMPORT", &ad.navigation.import_menu),
        AppState::SingleSigMenu => boot_display.update_menu_content("SINGLE SIGNATURE", &ad.navigation.single_sig_menu),
        _ => return false,
    }
    true
}

#[cfg(feature = "workflow-tests")]
fn redraw_workflow_category(ad: &AppData, boot_display: &mut display::BootDisplay<'_>, category: u8) {
    let title = crate::runtime::workflow_tests::WorkflowCategory::from_raw(category)
        .map(crate::runtime::workflow_tests::WorkflowCategory::label)
        .unwrap_or("E2E CATEGORY");
    boot_display.update_menu_content(title, &ad.navigation.workflow_category_menu);
}

#[cfg(feature = "workflow-tests")]
fn redraw_workflow_result(ad: &AppData, boot_display: &mut display::BootDisplay<'_>) {
    let result = ad.workflow_tests.result;
    let mut message: heapless::String<48> = heapless::String::new();
    let _ = core::fmt::Write::write_fmt(&mut message, format_args!("Contracts {}/{}", result.passed, result.total));
    if result.failed == 0 { boot_display.draw_success_screen(message.as_str()); }
    else { boot_display.draw_error_back_screen(message.as_str()); }
}
