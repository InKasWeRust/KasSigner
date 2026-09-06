// KasSigner — Air-gapped offline signing device for Kaspa
// Copyright (C) 2025-2026 KasSigner Project (kassigner@proton.me)
// License: GPL-3.0

//! Stable touch-zone layout used by the outer event loop.

pub(crate) type NavigationZones = (
    [crate::hw::touch::TouchZone; 4],
    [crate::hw::touch::TouchZone; 4],
    crate::hw::touch::TouchZone,
    crate::hw::touch::TouchZone,
);

pub(crate) fn touch_zones() -> NavigationZones {
    (
        crate::ui::layout::HOME_GRID_ZONES,
        [
            crate::hw::touch::TouchZone::new(40, 44, 240, 46),
            crate::hw::touch::TouchZone::new(40, 90, 240, 46),
            crate::hw::touch::TouchZone::new(40, 136, 240, 46),
            crate::hw::touch::TouchZone::new(40, 182, 240, 46),
        ],
        crate::hw::touch::TouchZone::new(0, 42, 40, 192),
        crate::hw::touch::TouchZone::new(280, 42, 40, 192),
    )
}
/// Normalize one physical coordinate exactly as the production event loop does.
/// Test harnesses must use this instead of inventing `is_back`.
pub(crate) fn physical_touch_input(x: u16, y: u16) -> crate::runtime::interactions::TouchInput {
    crate::runtime::interactions::TouchInput::new(x, y, crate::ui::layout::is_back_tap(x, y))
}

#[cfg(feature = "workflow-test-auto")]
pub(crate) fn workflow_touch_input(
    x: u16,
    y: u16,
    expected_back: bool,
) -> Option<crate::runtime::interactions::TouchInput> {
    let input = physical_touch_input(x, y);
    if input.is_back != expected_back {
        crate::log!(
            "KASSIGNER_WORKFLOW_TESTS: TOUCH PARITY FAIL ({},{}) expected_back={} production_back={}",
            x, y, expected_back, input.is_back,
        );
        return None;
    }
    Some(input)
}
