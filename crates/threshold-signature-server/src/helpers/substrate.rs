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

//! Utilities for interacting with the Entropy blockchain
use crate::{
    chain_api::{
        entropy::{
            self,
            runtime_types::{
                bounded_collections::bounded_vec::BoundedVec,
                pallet_registry::pallet::RegisteredInfo,
            },
        },
        EntropyConfig,
    },
    user::UserErr,
};
pub use entropy_client::substrate::{query_chain, submit_transaction};
use entropy_shared::user::ValidatorInfo;
use subxt::{backend::legacy::LegacyRpcMethods, utils::AccountId32, Config, OnlineClient};

/// Given a threshold server's account ID, return its corresponding stash (validator) address.
pub async fn get_stash_address(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    threshold_account_id: &AccountId32,
) -> Result<AccountId32, UserErr> {
    let block_hash = rpc.chain_get_block_hash(None).await?;
    let stash_address_query =
        entropy::storage().staking_extension().threshold_to_stash(threshold_account_id);
    let stash_address = query_chain(api, rpc, stash_address_query, block_hash)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Stash Fetch Error"))?;

    Ok(stash_address)
}

/// Queries the user's program from the chain
pub async fn get_program(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    program_pointer: &<EntropyConfig as Config>::Hash,
) -> Result<Vec<u8>, UserErr> {
    let bytecode_address = entropy::storage().programs().programs(program_pointer);

    Ok(query_chain(api, rpc, bytecode_address, None)
        .await?
        .ok_or(UserErr::NoProgramDefined(program_pointer.to_string()))?
        .bytecode)
}

/// Returns a registered user's key visibility
#[tracing::instrument(skip_all, fields(verifying_key))]
pub async fn get_registered_details(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    verifying_key: Vec<u8>,
) -> Result<RegisteredInfo, UserErr> {
    tracing::info!("Querying chain for registration info.");

    let registered_info_query =
        entropy::storage().registry().registered(BoundedVec(verifying_key.clone()));
    let registered_result = query_chain(api, rpc, registered_info_query, None).await?;

    let registration_info = if let Some(old_registration_info) = registered_result {
        old_registration_info
    } else {
        // We failed with the old registration path, let's try the new one
        tracing::warn!("Didn't find user in old `Registered` struct, trying new one");

        let registered_info_query =
            entropy::storage().registry().registered_on_chain(BoundedVec(verifying_key));
        let new_registration_info = query_chain(api, rpc, registered_info_query, None)
            .await?
            .ok_or_else(|| UserErr::ChainFetch("Not Registering error: Register Onchain first"))?;

        new_registration_info
    };

    Ok(registration_info)
}

/// Takes Stash keys and returns validator info from chain
pub async fn get_validators_info(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    validators: Vec<AccountId32>,
) -> Result<Vec<ValidatorInfo>, UserErr> {
    let mut handles = Vec::new();
    let block_hash = rpc.chain_get_block_hash(None).await?;
    for validator in validators {
        let handle: tokio::task::JoinHandle<Result<ValidatorInfo, UserErr>> = tokio::task::spawn({
            let api = api.clone();
            let rpc = rpc.clone();

            async move {
                let threshold_address_query =
                    entropy::storage().staking_extension().threshold_servers(validator);
                let server_info = query_chain(&api, &rpc, threshold_address_query, block_hash)
                    .await?
                    .ok_or_else(|| {
                        UserErr::OptionUnwrapError("Failed to unwrap validator info".to_string())
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
        all_signers.push(handle.await.unwrap().unwrap());
    }
    Ok(all_signers)
}
