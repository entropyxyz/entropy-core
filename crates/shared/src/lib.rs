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

// TODO: This should only be used for non-production things...
lazy_static::lazy_static! {

    // Used `DEFAULT_ALICE_MNEMONIC` to generate this
    // Mnemonic: "alarm mutual concert decrease hurry invest culture survey diagram crash snap click"
    pub static ref ALICE_X25519_PUBLIC_KEY: [u8; 32] = [
            10, 192, 41, 240, 184, 83, 178, 59, 237, 101, 45, 109, 13, 230, 155, 124, 195, 141, 148,
            249, 55, 50, 238, 252, 133, 181, 134, 30, 144, 247, 58, 34,

    ];

    // Used `DEFAULT_BOB_MNEMONIC` to generate this
    // Mnemonic: "where sight patient orphan general short empower hope party hurt month voice"
    pub static ref BOB_X25519_PUBLIC_KEY: [u8; 32] = [
            225, 48, 135, 211, 227, 213, 170, 21, 1, 189, 118, 158, 255, 87, 245, 89, 36, 170, 169,
            181, 68, 201, 210, 178, 237, 247, 101, 80, 153, 136, 102, 10,

    ];

}
