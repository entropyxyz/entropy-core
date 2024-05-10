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
//! A client for the Entropy chain node and Entropy TSS Server.
//! Since the TSS server communicates with the chain node, this is also a dependency of entropy-tss.
pub mod chain_api;
pub mod errors;
pub mod substrate;
pub mod user;
pub mod util;
pub use util::Hasher;

#[cfg(feature = "full-client")]
pub mod client;
#[cfg(feature = "full-client")]
pub use client::*;
