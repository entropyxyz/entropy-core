#![cfg_attr(not(feature = "std"), no_std)]
//! Types that is shared by clients and substrate nodes,
//! i.e. messages sent from one to the other and structs contained in those messages
//!
//! This helps ensures those structs are synced among clients and nodes.
//!
pub use constraints::*;
pub use types::*;

pub mod constraints;
pub mod types;

#[cfg(test)]
pub const SIGNING_PARTY_SIZE: usize = 2;

// TODO: fix and change back
#[cfg(not(test))]
pub const SIGNING_PARTY_SIZE: usize = 2;
