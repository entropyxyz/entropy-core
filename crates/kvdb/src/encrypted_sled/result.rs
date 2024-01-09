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

//! Custom error handling

#[derive(thiserror::Error, Debug)]
pub enum EncryptedDbError {
    #[error("Your kv store may be corrupted. Sled error: {0}")]
    CorruptedKv(sled::Error),
    #[error("Password read error: {0}")]
    PasswordRead(#[from] std::io::Error), // rpassword::read_password() Error
    #[error("Password scrypt params error: {0}")]
    PasswordScryptParams(#[from] scrypt::errors::InvalidParams),
    #[error("Password scrypt error: {0}")]
    PasswordScryptError(#[from] scrypt::errors::InvalidOutputLen),
    #[error("Sled error: {0}")]
    SledError(#[from] sled::Error),
    #[error("Serialization error: failed to serialize the encrypted record")]
    Serialization,
    #[error("Deserialization error: failed to deserialize encrypted record bytes")]
    Deserialization,
    #[error("ChaCha20 encryption error: {0}")]
    Encryption(String),
    #[error("ChaCha20 decryption error: {0}")]
    Decryption(String),
    #[error("Wrong password")]
    WrongPassword,
    #[error("Missing password salt")]
    MissingPasswordSalt,
    #[error("Malformed password salt: {0}")]
    MalformedPasswordSalt(#[from] std::array::TryFromSliceError),
}
pub type EncryptedDbResult<Success> = Result<Success, EncryptedDbError>;
