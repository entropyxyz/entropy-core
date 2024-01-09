// Copyright (C) 2023 Entropy Cryptography Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

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

/// The amount of proactive refreshes we do per session
pub const REFRESHES_PER_SESSION: u32 = 10;

/// Max instructions per wasm program
pub const MAX_INSTRUCTIONS_PER_PROGRAM: u64 = 10_000;
