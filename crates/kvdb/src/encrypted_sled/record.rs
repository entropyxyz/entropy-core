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

//! The value of [super::Db].

use chacha20poly1305::XNonce;
use serde::{Deserialize, Serialize};
use sled::IVec;

use super::result::{
    EncryptedDbError::{Deserialization, Serialization},
    EncryptedDbResult,
};
use crate::kv_manager::helpers::{deserialize, serialize};

/// The value of [super::Db].
#[derive(Serialize, Deserialize, Debug)]
pub(super) struct EncryptedRecord {
    encrypted_value: Vec<u8>,
    nonce: [u8; 24],
}

impl EncryptedRecord {
    pub(super) fn new(encrypted_value: Vec<u8>, nonce: XNonce) -> Self {
        EncryptedRecord { encrypted_value, nonce: nonce.into() }
    }

    /// Convert a [EncryptedRecord] to bytes using serde.
    pub(super) fn to_bytes(&self) -> EncryptedDbResult<Vec<u8>> {
        serialize(&self).map_err(|_| Serialization)
    }

    /// Convert bytes to a [EncryptedRecord] using serde.
    pub(super) fn from_bytes(bytes: &IVec) -> EncryptedDbResult<EncryptedRecord> {
        deserialize(bytes).ok_or(Deserialization)
    }
}

impl From<EncryptedRecord> for (Vec<u8>, XNonce) {
    fn from(record: EncryptedRecord) -> Self {
        (record.encrypted_value, record.nonce.into())
    }
}
