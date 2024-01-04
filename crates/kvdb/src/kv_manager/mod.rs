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

//! Key-Value Store service. We use [sled][sled] for the underlying db implementation.
//! For every kvstore initialized, a daemon is spawned that serves basic
//! database functionality using the "actor" pattern (`kv::Kv` is the "handle"): <https://ryhl.io/blog/actors-with-tokio/>
//! See <https://tokio.rs/tokio/tutorial/channels> for tokio channels
//! See `kv` module for the public API.

/// Custom error types for `kv` and `sled_bindings`
pub mod error;
pub mod helpers;
/// public API of kv manager
mod kv;
/// sled bindings for basic kv operations
mod sled_bindings;
/// definition of kv_manager types and default paths
mod types;
/// wrapers for values stored by services
pub mod value;
pub use types::KeyReservation;
pub use value::{KvManager, PartyInfo};

// tests for low-level operations
#[cfg(test)]
mod tests;
