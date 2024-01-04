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

//! Wrap a layer of encryption around [sled]. We use [chacha20poly1305] to encrypt/decrypt values.
//! Specifically, use [chacha20poly1305::XChaCha20Poly1305] because the nonces are generated
//! randomly. To create an new [Db], an key to use as entropy for the stream cipher needs to be
//! provided.

mod constants;
mod kv;
mod password;
mod record;
mod result;

// match the API of sled
pub use kv::EncryptedDb as Db;
pub use password::{Password, PasswordMethod, PasswordSalt};
pub use result::{EncryptedDbError as Error, EncryptedDbResult as Result};

#[cfg(test)]
mod tests;

#[cfg(test)]
pub use tests::get_test_password;
