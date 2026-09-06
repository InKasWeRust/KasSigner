use super::{Action, AppState, Button, ButtonEvent, Menu, WalletApp};

// Self-tests
// ═══════════════════════════════════════════════════════════════════

/// Run input subsystem tests. Returns (passed, total).
pub fn run_tests() -> (u32, u32) {
    let mut passed = 0u32;
    let total = 5u32;

    // Test 1: BOOT short press
    {
        let mut btn = Button::new();
        let _ = btn.update(false, 100);
        let _ = btn.update(true, 100);
        let _ = btn.update(true, 100);
        let e = btn.update(false, 20);
        if e == ButtonEvent::ShortPress { passed += 1; }
    }

    // Test 2: BOOT long press
    {
        let mut btn = Button::new();
        let _ = btn.update(true, 100);
        let _ = btn.update(true, 400);
        let _ = btn.update(true, 400);
        let e = btn.update(false, 20);
        if e == ButtonEvent::LongPress { passed += 1; }
    }

    // Test 3: PIR short noise rejected
    {
        let mut btn = Button::new_pir();
        let _ = btn.update(true, 50);
        let _ = btn.update(true, 50);
        let e = btn.update(false, 20);
        if e == ButtonEvent::None { passed += 1; }
    }

    // Test 4: Menu navigation — short=move, long=select
    {
        let mut menu = Menu::from_items(&["Alpha", "Beta", "Gamma"]);
        // Initial cursor = 0
        let r1 = menu.handle(ButtonEvent::ShortPress); // cursor → 1
        let ok1 = r1.is_none() && menu.cursor == 1;

        let r2 = menu.handle(ButtonEvent::ShortPress); // cursor → 2
        let ok2 = r2.is_none() && menu.cursor == 2;

        let r3 = menu.handle(ButtonEvent::ShortPress); // cursor → 0 (wrap)
        let ok3 = r3.is_none() && menu.cursor == 0;

        let r4 = menu.handle(ButtonEvent::LongPress);  // select item 0
        let ok4 = r4 == Some(0);

        if ok1 && ok2 && ok3 && ok4 { passed += 1; }
    }

    // Test 5: App flow — main menu → ScanQR, then review → confirm → sign → QR → menu
    {
        let mut app = WalletApp::new();

        // Main menu item 0 is Show Address; move once to item 1 (Scan QR), then select.
        let moved = app.handle_boot(ButtonEvent::ShortPress);
        let action = app.handle_boot(ButtonEvent::LongPress);
        let ok0 = moved == Action::Redraw
            && app.state == AppState::ScanQR
            && action == Action::Redraw;

        // Go back to main menu, then test review flow
        app.go_main_menu();
        app.start_review(2, 1);
        let ok1 = app.state == AppState::ConfirmTx;

        // Inspect is optional: move Confirm → Cancel → Inspect and select.
        app.handle_boot(ButtonEvent::ShortPress);
        app.handle_boot(ButtonEvent::ShortPress);
        app.handle_boot(ButtonEvent::LongPress);
        let ok2 = app.state == AppState::ReviewTx { page: 0 };

        // Navigate pages: summary(0) → out0(1) → out1(2) → ConfirmTx.
        app.handle_boot(ButtonEvent::ShortPress);
        app.handle_boot(ButtonEvent::ShortPress);
        let ok3 = app.state == AppState::ReviewTx { page: 2 };
        app.handle_boot(ButtonEvent::ShortPress);
        let ok4 = app.state == AppState::ConfirmTx;

        // Cursor resets to "Confirm" (0); long press authorizes signing.
        app.handle_boot(ButtonEvent::LongPress);
        let ok5 = app.state == AppState::ConfirmTx && app.review_authorized;

        // Sign → QR → back to menu
        app.advance_signing();
        let ok6 = app.state == AppState::ShowQR;

        app.handle_boot(ButtonEvent::ShortPress);
        let ok7 = app.state == AppState::MainMenu;

        if ok0 && ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7 { passed += 1; }
    }

    (passed, total)
}

#[test]
fn input_vectors_pass() {
    let (passed, total) = run_tests();
    assert_eq!(passed, total);
}
