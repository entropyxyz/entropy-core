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

//! Constants for [encrypted_sled](crate::encrypted_sled)
pub(super) const PASSWORD_VERIFICATION_KEY: &str = "verification_key";
pub(super) const PASSWORD_VERIFICATION_VALUE: &str = "verification_value";
pub(super) const PASSWORD_SALT_KEY: &[u8] = b"password_salt_key";
pub(super) const UNSAFE_PASSWORD: &str = "entropy_unsafe_password";
