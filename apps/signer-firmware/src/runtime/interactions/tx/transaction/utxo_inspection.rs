use crate::runtime::{data::AppData, input::AppState};

pub(super) fn handle(ad: &mut AppData, x: u16, y: u16, is_back: bool) -> bool {
    match ad.navigation.app.state {
        AppState::ReviewTx { page: 0 }
            if !is_back && (20..=115).contains(&x) && (194..=232).contains(&y) =>
        {
            crate::runtime::effects::route(ad, crate::runtime::navigation::route!(InspectUtxoSummary));
            true
        }
        AppState::InspectUtxoSummary | AppState::InspectUtxo { .. } => {
            if is_back {
                crate::runtime::effects::route(ad, crate::runtime::navigation::route!(ReviewTx { page: 0 }));
            } else {
                crate::runtime::effects::advance_inspection(ad);
            }
            true
        }
        _ => false,
    }
}
