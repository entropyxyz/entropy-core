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
use anyhow::anyhow;
use entropy_shared::MORTALITY_BLOCKS;
use subxt::{
    backend::legacy::LegacyRpcMethods,
    blocks::ExtrinsicEvents,
    config::PolkadotExtrinsicParamsBuilder as Params,
    ext::sp_core::sr25519,
    storage::address::{StorageAddress, Yes},
    tx::{PairSigner, TxPayload, TxStatus},
    utils::{AccountId32, H256},
    Config, OnlineClient,
};

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

// /// Returns all the addresses of a specific subgroup
// pub async fn return_all_addresses_of_subgroup(
//     api: &OnlineClient<EntropyConfig>,
//     rpc: &LegacyRpcMethods<EntropyConfig>,
//     subgroup: u8,
// ) -> Result<Vec<AccountId32>, UserErr> {
//     let subgroup_addresses_query = entropy::storage().staking_extension().signing_groups(subgroup);
//     let subgroup_addresses = query_chain(api, rpc, subgroup_addresses_query, None)
//         .await?
//         .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;

//     Ok(subgroup_addresses)
// }

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

/// Send a transaction to the Entropy chain
///
/// Optionally takes a nonce, otherwise it grabs the latest nonce from the chain
pub async fn submit_transaction<Call: TxPayload>(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
    call: &Call,
    nonce_option: Option<u32>,
) -> anyhow::Result<ExtrinsicEvents<EntropyConfig>> {
    let block_hash =
        rpc.chain_get_block_hash(None).await?.ok_or_else(|| anyhow!("Error getting block hash"))?;

    let nonce = if let Some(nonce) = nonce_option {
        nonce
    } else {
        let nonce_call =
            entropy::apis().account_nonce_api().account_nonce(signer.account_id().clone());
        api.runtime_api().at(block_hash).call(nonce_call).await?
    };

    let latest_block = api.blocks().at_latest().await?;
    let tx_params =
        Params::new().mortal(latest_block.header(), MORTALITY_BLOCKS).nonce(nonce.into()).build();
    let mut tx = api.tx().create_signed(call, signer, tx_params).await?.submit_and_watch().await?;

    while let Some(status) = tx.next().await {
        match status? {
            TxStatus::InBestBlock(tx_in_block) | TxStatus::InFinalizedBlock(tx_in_block) => {
                return Ok(tx_in_block.wait_for_success().await?);
            },
            TxStatus::Error { message }
            | TxStatus::Invalid { message }
            | TxStatus::Dropped { message } => {
                // Handle any errors:
                return Err(anyhow!("Error submitting tx: {message}"));
            },
            // Continue otherwise:
            _ => continue,
        };
    }
    Err(anyhow!("Error getting event"))
}

/// Gets data from the Entropy chain
///
/// Optionally takes a block hash, otherwise the latest block hash from the chain is used
pub async fn query_chain<Address>(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    storage_call: Address,
    block_hash_option: Option<H256>,
) -> anyhow::Result<Option<Address::Target>>
where
    Address: StorageAddress<IsFetchable = Yes>,
{
    let block_hash = if let Some(block_hash) = block_hash_option {
        block_hash
    } else {
        rpc.chain_get_block_hash(None).await?.ok_or_else(|| anyhow!("Error getting block hash"))?
    };

    let result = api.storage().at(block_hash).fetch(&storage_call).await?;

    Ok(result)
}
