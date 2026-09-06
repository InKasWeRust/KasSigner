#[cfg(test)]
mod common;
mod integration;
#[cfg(test)]
mod kssn;
#[cfg(test)]
mod script;
#[cfg(test)]
mod signing;
#[cfg(test)]
mod status;
#[cfg(test)]
mod validation;
#[cfg(test)]
mod wire_adapter;

pub use integration::run_kspt_tests;

#[cfg(test)]
mod property;
