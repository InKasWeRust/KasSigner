//! SD-format controller decision. The event loop owns the hold gesture and the
//! storage service owns the formatting hardware effect.

use crate::runtime::{data::AppData, destructive::{self, DestructiveAction}};

pub(super) fn begin(ad: &mut AppData) {
    destructive::begin(ad, DestructiveAction::FormatSd);
}
