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
pub mod chain_api;
pub mod substrate;
pub mod user;
use entropy_shared::X25519PublicKey;
use serde::{Deserialize, Serialize};
use subxt::utils::AccountId32;

/// Details of a TSS server
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ValidatorInfo {
    pub x25519_public_key: X25519PublicKey,
    pub ip_address: String,
    pub tss_account: AccountId32,
}

/// Produces a specific hash on a given message
pub struct Hasher;

impl Hasher {
    /// Produces the Keccak256 hash on a given message.
    ///
    /// In practice, if `data` is an RLP-serialized Ethereum transaction, this should produce the
    /// corrosponding .
    pub fn keccak(data: &[u8]) -> [u8; 32] {
        use sha3::{Digest, Keccak256};

        let mut keccak = Keccak256::new();
        keccak.update(data);
        keccak.finalize().into()
    }
}
