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
//! Utilities

use crate::{attestation::create_quote, errors::ClientError};
use axum::Json;
use entropy_shared::{attestation::QuoteContext, X25519PublicKey};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use subxt::utils::AccountId32;

/// Produces a specific hash on a given message
pub struct Hasher;

impl Hasher {
    /// Produces the Keccak256 hash on a given message.
    ///
    /// In practice, if `data` is an RLP-serialized Ethereum transaction, this should produce the
    /// corrosponding .
    pub fn keccak(data: &[u8]) -> [u8; 32] {
        let mut keccak = Keccak256::new();
        keccak.update(data);
        keccak.finalize().into()
    }
}

/// Public signing and encryption keys associated with a server
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ServerPublicKeys {
    /// The account ID
    pub account_id: AccountId32,
    /// The public encryption key
    pub x25519_public_key: X25519PublicKey,
    /// A hex-encoded TDX quote to show that the server is running the desired service
    pub tdx_quote: String,
    /// An option if supported if the node is ready (not all nodes support this option)
    pub ready: Option<bool>,
}

pub async fn get_node_info(
    ready: Option<bool>,
    x25519_public_key: [u8; 32],
    account_id: AccountId32,
    quote_context: QuoteContext,
) -> Result<Json<ServerPublicKeys>, ClientError> {
    Ok(Json(ServerPublicKeys {
        ready,
        x25519_public_key,
        account_id: account_id.clone(),
        tdx_quote: hex::encode(
            create_quote([0; 32], account_id, &x25519_public_key, quote_context).await?,
        ),
    }))
}
