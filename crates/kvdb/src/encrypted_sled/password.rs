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

//! Handles the generation of a key for the stream cipher from the user's password using [scrypt]
//! pbkdf.
use std::convert::{TryFrom, TryInto};

use sled::IVec;
use zeroize::Zeroize;

use super::{constants::UNSAFE_PASSWORD, result::EncryptedDbResult};

/// Safely store strings
// TODO use https://docs.rs/secrecy ?
#[derive(Zeroize, Clone)]
#[zeroize(drop)]
pub struct Password(String);

impl AsRef<[u8]> for Password {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<String> for Password {
    fn from(string: String) -> Self {
        Self(string)
    }
}

pub struct PasswordSalt([u8; 32]);

impl AsRef<[u8]> for PasswordSalt {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for PasswordSalt {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<IVec> for PasswordSalt {
    type Error = std::array::TryFromSliceError;

    fn try_from(value: IVec) -> Result<Self, Self::Error> {
        Ok(Self(value.as_ref().try_into()?))
    }
}

use rpassword::read_password;

/// Specifies how [Password] will be retrieved
#[derive(Clone, Debug)]
pub enum PasswordMethod {
    NoPassword,
    Prompt,
}
impl PasswordMethod {
    /// Execute the password method to retrieve a password
    pub fn execute(&self) -> EncryptedDbResult<Password> {
        Ok(match self {
            Self::NoPassword => Password(UNSAFE_PASSWORD.to_string()),
            Self::Prompt => {
                println!("Please type your password:");
                Password(read_password()?)
            },
        })
    }
}

#[cfg(test)]
impl From<&str> for Password {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}
