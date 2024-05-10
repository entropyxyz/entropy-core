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
//! User interaction related
use crate::{
    chain_api::{entropy, EntropyConfig},
    substrate::query_chain,
};
use entropy_shared::{user::ValidatorInfo, HashingAlgorithm};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;
use subxt::{backend::legacy::LegacyRpcMethods, OnlineClient};

pub use crate::errors::SubgroupGetError;

/// Represents an unparsed, transaction request coming from the client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserSignatureRequest {
    /// Hex-encoded raw data to be signed (eg. hex-encoded RLP-serialized Ethereum transaction)
    pub message: String,
    /// Hex-encoded auxilary data for program evaluation, will not be signed (eg. zero-knowledge proof, serialized struct, etc)
    pub auxilary_data: Option<Vec<Option<String>>>,
    /// Information from the validators in signing party
    pub validators_info: Vec<ValidatorInfo>,
    /// When the message was created and signed
    pub timestamp: SystemTime,
    /// Hashing algorithm to be used for signing
    pub hash: HashingAlgorithm,
    /// The veryfying key for the signature requested
    pub signature_verifying_key: Vec<u8>,
}

pub async fn get_signers_from_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<Vec<ValidatorInfo>, SubgroupGetError> {
    let all_validators_query = entropy::storage().session().validators();
    let all_validators = query_chain(api, rpc, all_validators_query, None)
        .await?
        .ok_or_else(|| SubgroupGetError::ChainFetch("Get all validators error"))?;
    let block_hash = rpc.chain_get_block_hash(None).await?;
    let mut handles = Vec::new();

    for validator in all_validators {
        let handle: tokio::task::JoinHandle<Result<ValidatorInfo, SubgroupGetError>> =
            tokio::task::spawn({
                let api = api.clone();
                let rpc = rpc.clone();
                async move {
                    let threshold_address_query =
                        entropy::storage().staking_extension().threshold_servers(validator);
                    let server_info = query_chain(&api, &rpc, threshold_address_query, block_hash)
                        .await?
                        .ok_or_else(|| {
                            SubgroupGetError::ChainFetch("threshold_servers query error")
                        })?;
                    Ok(ValidatorInfo {
                        x25519_public_key: server_info.x25519_public_key,
                        ip_address: std::str::from_utf8(&server_info.endpoint)?.to_string(),
                        tss_account: server_info.tss_account,
                    })
                }
            });
        handles.push(handle);
    }
    let mut all_signers: Vec<ValidatorInfo> = vec![];
    for handle in handles {
        all_signers.push(handle.await??);
    }

    Ok(all_signers)
}
