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
pub use entropy_tss_client_common::substrate::{query_chain, submit_transaction};
use subxt::{backend::legacy::LegacyRpcMethods, utils::AccountId32, Config, OnlineClient};

/// Return the subgroup that a particular threshold server belongs to.
pub async fn get_subgroup(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    threshold_account_id: &AccountId32,
) -> Result<u8, UserErr> {
    let block_hash = rpc.chain_get_block_hash(None).await?;
    let stash_address = get_stash_address(api, rpc, threshold_account_id).await?;

    let subgroup_query =
        entropy::storage().staking_extension().validator_to_subgroup(&stash_address);
    let subgroup = query_chain(api, rpc, subgroup_query, block_hash)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Subgroup Error"))?;

    Ok(subgroup)
}

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

/// Returns all the addresses of a specific subgroup
pub async fn return_all_addresses_of_subgroup(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    subgroup: u8,
) -> Result<Vec<AccountId32>, UserErr> {
    let subgroup_addresses_query = entropy::storage().staking_extension().signing_groups(subgroup);
    let subgroup_addresses = query_chain(api, rpc, subgroup_addresses_query, None)
        .await?
        .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;

    Ok(subgroup_addresses)
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
pub async fn get_registered_details(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    verifying_key: Vec<u8>,
) -> Result<RegisteredInfo, UserErr> {
    let registered_info_query = entropy::storage().registry().registered(BoundedVec(verifying_key));
    let result = query_chain(api, rpc, registered_info_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Not Registering error: Register Onchain first"))?;
    Ok(result)
}
