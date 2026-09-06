//! Shipment-escrow transaction and address façade.

mod address;
mod deposit;
mod plan;
mod withdraw;

#[cfg(test)]
pub(crate) use address::build_shipping_escrow_json;
pub use address::covenant_ship_escrow;
pub use deposit::create_covenant_borrower_spend;
pub use withdraw::create_covenant_borrower_withdraw;

#[cfg(test)]
mod unit_tests;
