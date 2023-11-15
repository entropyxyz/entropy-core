#![cfg_attr(not(feature = "std"), no_std)]
//! Types that is shared by clients and substrate nodes,
//! i.e. messages sent from one to the other and structs contained in those messages
//!
//! This helps ensures those structs are synced among clients and nodes.
pub use types::*;

pub mod types;

pub const SIGNING_PARTY_SIZE: usize = 2;

// min balance 12 decimal chain = 0.1
pub const MIN_BALANCE: u128 = 10000000000;

// 6 seconds a block this is one day
/// The amount of blocks before a tx request is pruned from the kvdb
pub const PRUNE_BLOCK: u32 = 14400;

/// Timeout for validators to wait for other validators to join protocol committees
pub const SETUP_TIMEOUT_SECONDS: u64 = 20;

pub const REFRESHES_PRE_SESSION: u128 = 10;
