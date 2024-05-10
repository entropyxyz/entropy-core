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
use entropy_shared::{user::ValidatorInfo, HashingAlgorithm, SIGNING_PARTY_SIZE};
use futures::future::join_all;
use num::{BigInt, Num, ToPrimitive};
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::SystemTime};
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

/// Gets the current signing committee
/// The signing committee is composed as the validators at the index into each subgroup
/// Where the index is computed as the user's sighash as an integer modulo the number of subgroups
pub async fn get_current_subgroup_signers(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    sig_hash: &str,
) -> Result<Vec<ValidatorInfo>, SubgroupGetError> {
    let mut subgroup_signers = vec![];
    let number = Arc::new(BigInt::from_str_radix(sig_hash, 16)?);
    let block_hash = rpc.chain_get_block_hash(None).await?;

    let futures = (0..SIGNING_PARTY_SIZE)
        .map(|i| {
            let owned_number = Arc::clone(&number);
            async move {
                let subgroup_info_query =
                    entropy::storage().staking_extension().signing_groups(i as u8);
                let subgroup_info =
                    query_chain(api, rpc, subgroup_info_query, block_hash)
                        .await?
                        .ok_or_else(|| SubgroupGetError::ChainFetch("Subgroup Fetch Error"))?;

                let index_of_signer_big = &*owned_number % subgroup_info.len();
                let index_of_signer =
                    index_of_signer_big.to_usize().ok_or(SubgroupGetError::Usize("Usize error"))?;

                let threshold_address_query = entropy::storage()
                    .staking_extension()
                    .threshold_servers(subgroup_info[index_of_signer].clone());
                let server_info = query_chain(api, rpc, threshold_address_query, block_hash)
                    .await?
                    .ok_or_else(|| SubgroupGetError::ChainFetch("Subgroup Fetch Error"))?;

                Ok::<_, SubgroupGetError>(ValidatorInfo {
                    x25519_public_key: server_info.x25519_public_key,
                    ip_address: std::str::from_utf8(&server_info.endpoint)?.to_string(),
                    tss_account: server_info.tss_account,
                })
            }
        })
        .collect::<Vec<_>>();
    let results = join_all(futures).await;
    for result in results.into_iter() {
        subgroup_signers.push(result?);
    }
    Ok(subgroup_signers)
}
