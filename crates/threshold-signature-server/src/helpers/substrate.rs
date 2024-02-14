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

use crate::{
    chain_api::{
        entropy::{self, runtime_types::pallet_relayer::pallet::RegisteredInfo},
        EntropyConfig,
    },
    user::UserErr,
};
use anyhow::anyhow;
use entropy_shared::{MORTALITY_BLOCKS, SIGNING_PARTY_SIZE};
use subxt::{
    backend::legacy::LegacyRpcMethods,
    blocks::ExtrinsicEvents,
    config::PolkadotExtrinsicParamsBuilder as Params,
    ext::sp_core::sr25519,
    storage::address::{StorageAddress, Yes},
    tx::{PairSigner, TxPayload},
    utils::{AccountId32, H256},
    Config, OnlineClient,
};

/// gets the subgroup of the working validator
pub async fn get_subgroup(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
) -> Result<(Option<u8>, AccountId32), UserErr> {
    let mut subgroup: Option<u8> = None;
    let threshold_address = signer.account_id();
    let block_hash = rpc.chain_get_block_hash(None).await?;
    let stash_address_query =
        entropy::storage().staking_extension().threshold_to_stash(threshold_address);
    let stash_address = get_data_from_chain(api, rpc, &stash_address_query, block_hash)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Stash Fetch Error"))?;
    for i in 0..SIGNING_PARTY_SIZE {
        let signing_group_addresses_query =
            entropy::storage().staking_extension().signing_groups(i as u8);
        let signing_group_addresses =
            get_data_from_chain(api, rpc, &signing_group_addresses_query, block_hash)
                .await?
                .ok_or_else(|| UserErr::ChainFetch("Subgroup Error"))?;
        if signing_group_addresses.contains(&stash_address) {
            subgroup = Some(i as u8);
            break;
        }
    }
    Ok((subgroup, stash_address))
}

/// Returns all the addresses of a specific subgroup
pub async fn return_all_addresses_of_subgroup(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    subgroup: u8,
) -> Result<Vec<AccountId32>, UserErr> {
    let subgroup_addresses_query = entropy::storage().staking_extension().signing_groups(subgroup);
    let subgroup_addresses = get_data_from_chain(api, rpc, &subgroup_addresses_query, None)
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

    Ok(get_data_from_chain(api, rpc, &bytecode_address, None)
        .await?
        .ok_or(UserErr::NoProgramDefined(program_pointer.to_string()))?
        .bytecode)
}

/// Returns a registered user's key visibility
pub async fn get_registered_details(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    who: &<EntropyConfig as Config>::AccountId,
) -> Result<RegisteredInfo, UserErr> {
    let registered_info_query = entropy::storage().relayer().registered(who);
    let result = get_data_from_chain(api, rpc, &registered_info_query, None)
        .await?
        .ok_or_else(|| UserErr::ChainFetch("Not Registering error: Register Onchain first"))?;
    Ok(result)
}

/// Send a tx to the entropy chain
/// takes an option for nonce, grabs nonce from chain if input is none
pub async fn send_tx<Call: TxPayload>(
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
    let tx_params = Params::new().mortal(latest_block.header(), MORTALITY_BLOCKS).build();
    let tx = api.tx().create_signed_with_nonce(call, signer, nonce.into(), tx_params)?;
    let result = tx.submit_and_watch().await?.wait_for_in_block().await?.wait_for_success().await?;
    Ok(result)
}

/// Gets data from the entropy chain
/// takes an option for block hash, grabs block hash from chain if input is none
pub async fn get_data_from_chain<'address, Address>(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    storage_call: &'address Address,
    block_hash_option: Option<H256>,
) -> anyhow::Result<Option<Address::Target>>
where
    Address: StorageAddress<IsFetchable = Yes> + 'address,
{
    let block_hash = if let Some(block_hash) = block_hash_option {
        block_hash
    } else {
        rpc.chain_get_block_hash(None).await?.ok_or_else(|| anyhow!("Error getting block hash"))?
    };

    let result = api.storage().at(block_hash).fetch(storage_call).await?;

    Ok(result)
}
