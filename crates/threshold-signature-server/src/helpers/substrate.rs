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
                bounded_collections::bounded_vec::BoundedVec, pallet_programs::pallet::ProgramInfo,
            },
        },
        EntropyConfig,
    },
    user::UserErr,
};
pub use entropy_client::substrate::{query_chain, submit_transaction};
use entropy_shared::user::ValidatorInfo;
use rand::prelude::IndexedRandom;
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
) -> Result<ProgramInfo, UserErr> {
    let bytecode_address = entropy::storage().programs().programs(program_pointer);
    let program_info = query_chain(api, rpc, bytecode_address, None)
        .await?
        .ok_or(UserErr::NoProgramDefined(program_pointer.to_string()))?;
    Ok(program_info)
}

/// Queries the oracle data needed for the program
pub async fn get_oracle_data(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    program_oracle_datas: Vec<Vec<u8>>,
) -> Result<Vec<Vec<u8>>, UserErr> {
    let mut oracle_infos = vec![];
    for program_oracle_data in program_oracle_datas {
        let oracle_data_call =
            entropy::storage().oracle().oracle_data(BoundedVec(program_oracle_data));
        let oracle_info =
            query_chain(api, rpc, oracle_data_call, None).await?.unwrap_or(BoundedVec(vec![]));
        oracle_infos.push(oracle_info.0);
    }
    Ok(oracle_infos)
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

/// Returns a threshold of signer's ValidatorInfo from the chain
pub async fn get_signers_from_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<(Vec<ValidatorInfo>, Vec<AccountId32>), UserErr> {
    let signer_query = entropy::storage().staking_extension().signers();
    let signers = query_chain(api, rpc, signer_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Get all validators error"))?;

    let key_info_query = entropy::storage().parameters().signers_info();
    let threshold = query_chain(api, rpc, key_info_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Failed to get signers info"))?
        .threshold;

    let selected_signers: Vec<_> = {
        let cloned_signers = signers.clone();
        cloned_signers.choose_multiple(&mut rand::rng(), threshold as usize).cloned().collect()
    };

    let block_hash = rpc.chain_get_block_hash(None).await?;
    let mut handles = Vec::new();

    for signer in selected_signers {
        let handle: tokio::task::JoinHandle<Result<ValidatorInfo, UserErr>> = tokio::task::spawn({
            let api = api.clone();
            let rpc = rpc.clone();
            async move {
                let threshold_address_query =
                    entropy::storage().staking_extension().threshold_servers(signer);
                let server_info = query_chain(&api, &rpc, threshold_address_query, block_hash)
                    .await?
                    .ok_or_else(|| UserErr::ChainFetch("threshold_servers query error"))?;
                Ok(ValidatorInfo {
                    x25519_public_key: server_info.x25519_public_key,
                    ip_address: std::str::from_utf8(&server_info.endpoint)?.to_string(),
                    tss_account: server_info.tss_account,
                })
            }
        });

        handles.push(handle);
    }

    let mut all_selected_signers: Vec<ValidatorInfo> = vec![];
    for handle in handles {
        all_selected_signers.push(handle.await??);
    }

    Ok((all_selected_signers, signers))
}
