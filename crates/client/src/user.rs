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
use entropy_shared::{user::ValidatorInfo, BlockNumber, HashingAlgorithm};
use rand::prelude::SliceRandom;
use serde::{Deserialize, Serialize};
use subxt::{backend::legacy::LegacyRpcMethods, OnlineClient};

pub use crate::errors::SubgroupGetError;

/// Represents an unparsed, transaction request coming from the client.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserSignatureRequest {
    /// Hex-encoded raw data to be signed (eg. hex-encoded RLP-serialized Ethereum transaction)
    pub message: String,
    /// Hex-encoded auxilary data for program evaluation, will not be signed (eg. zero-knowledge proof, serialized struct, etc)
    pub auxilary_data: Option<Vec<Option<String>>>,
    /// When the message was created and signed
    pub block_number: BlockNumber,
    /// Hashing algorithm to be used for signing
    pub hash: HashingAlgorithm,
    /// The verifying key for the signature requested
    pub signature_verifying_key: Vec<u8>,
}

/// Represents an unparsed, transaction request coming from the relayer to a signer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayerSignatureRequest {
    /// Hex-encoded raw data to be signed (eg. hex-encoded RLP-serialized Ethereum transaction)
    pub message: String,
    /// Hex-encoded auxilary data for program evaluation, will not be signed (eg. zero-knowledge proof, serialized struct, etc)
    pub auxilary_data: Option<Vec<Option<String>>>,
    /// When the message was created and signed
    pub block_number: BlockNumber,
    /// Hashing algorithm to be used for signing
    pub hash: HashingAlgorithm,
    /// The verifying key for the signature requested
    pub signature_verifying_key: Vec<u8>,
    /// Information for the validators in the signing party
    pub validators_info: Vec<ValidatorInfo>,
}

pub async fn get_signers_from_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<Vec<ValidatorInfo>, SubgroupGetError> {
    let signer_query = entropy::storage().staking_extension().signers();
    let signers = query_chain(api, rpc, signer_query, None)
        .await?
        .ok_or_else(|| SubgroupGetError::ChainFetch("Get all validators error"))?;

    let key_info_query = entropy::storage().parameters().signers_info();
    let threshold = query_chain(api, rpc, key_info_query, None)
        .await?
        .ok_or_else(|| SubgroupGetError::ChainFetch("Failed to get signers info"))?
        .threshold;

    let selected_signers: Vec<_> = {
        let mut cloned_signers = signers.clone();
        // TODO: temp remove dave for now until test dave is spun up correctly
        cloned_signers.pop();
        cloned_signers
            .choose_multiple(&mut rand::thread_rng(), threshold as usize)
            .cloned()
            .collect()
    };

    let block_hash = rpc.chain_get_block_hash(None).await?;
    let mut handles = Vec::new();

    for signer in selected_signers {
        let handle: tokio::task::JoinHandle<Result<ValidatorInfo, SubgroupGetError>> =
            tokio::task::spawn({
                let api = api.clone();
                let rpc = rpc.clone();
                async move {
                    let threshold_address_query =
                        entropy::storage().staking_extension().threshold_servers(signer);
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

/// Gets a validator from chain to relay a message to the signers
/// Filters out all signers
pub async fn get_validators_not_signer_for_relay(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<Vec<ValidatorInfo>, SubgroupGetError> {
    let signer_query = entropy::storage().staking_extension().signers();
    let signers = query_chain(api, rpc, signer_query, None)
        .await?
        .ok_or_else(|| SubgroupGetError::ChainFetch("Get all validators error"))?;

    let validators_query = entropy::storage().session().validators();
    let mut validators = query_chain(&api, &rpc, validators_query, None)
        .await?
        .ok_or_else(|| SubgroupGetError::ChainFetch("Error getting validators"))?;

    validators.retain(|validator| !signers.contains(validator));
    let block_hash = rpc.chain_get_block_hash(None).await?;
    let mut handles = Vec::new();

    for validator in validators {
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

    let mut all_validators: Vec<ValidatorInfo> = vec![];
    for handle in handles {
        all_validators.push(handle.await??);
    }

    Ok(all_validators)
}

/// Gets all signers from chain
pub async fn get_all_signers_from_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<Vec<ValidatorInfo>, SubgroupGetError> {
    let signer_query = entropy::storage().staking_extension().signers();
    let signers = query_chain(api, rpc, signer_query, None)
        .await?
        .ok_or_else(|| SubgroupGetError::ChainFetch("Get all validators error"))?;

    let block_hash = rpc.chain_get_block_hash(None).await?;
    let mut handles = Vec::new();

    for signer in signers {
        let handle: tokio::task::JoinHandle<Result<ValidatorInfo, SubgroupGetError>> =
            tokio::task::spawn({
                let api = api.clone();
                let rpc = rpc.clone();
                async move {
                    let threshold_address_query =
                        entropy::storage().staking_extension().threshold_servers(signer);
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
