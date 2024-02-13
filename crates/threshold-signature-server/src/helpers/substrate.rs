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
use entropy_shared::SIGNING_PARTY_SIZE;
use subxt::{
    backend::legacy::LegacyRpcMethods,
    blocks::ExtrinsicEvents,
    ext::sp_core::sr25519,
    tx::{PairSigner, TxPayload},
    utils::AccountId32,
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
    let stash_address_query =
        entropy::storage().staking_extension().threshold_to_stash(threshold_address);
    let block_hash = rpc
        .chain_get_block_hash(None)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Error getting block hash".to_string()))?;

    let stash_address = api
        .storage()
        .at(block_hash)
        .fetch(&stash_address_query)
        .await?
        .ok_or_else(|| UserErr::SubgroupError("Stash Fetch Error"))?;
    for i in 0..SIGNING_PARTY_SIZE {
        let signing_group_addresses_query =
            entropy::storage().staking_extension().signing_groups(i as u8);
        let signing_group_addresses = api
            .storage()
            .at(block_hash)
            .fetch(&signing_group_addresses_query)
            .await?
            .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
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
    let block_hash = rpc
        .chain_get_block_hash(None)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Error getting block hash".to_string()))?;
    let subgroup_addresses = api
        .storage()
        .at(block_hash)
        .fetch(&subgroup_addresses_query)
        .await?
        .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
    Ok(subgroup_addresses)
}

/// Queries the user's program from the chain
pub async fn get_program(
    substrate_api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    program_pointer: &<EntropyConfig as Config>::Hash,
) -> Result<Vec<u8>, UserErr> {
    let block_hash = rpc
        .chain_get_block_hash(None)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Error getting block hash".to_string()))?;

    let bytecode_address = entropy::storage().programs().programs(program_pointer);

    Ok(substrate_api
        .storage()
        .at(block_hash)
        .fetch(&bytecode_address)
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
    let block_hash = rpc
        .chain_get_block_hash(None)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Error getting block hash".to_string()))?;
    let result = api
        .storage()
        .at(block_hash)
        .fetch(&registered_info_query)
        .await?
        .ok_or_else(|| UserErr::NotRegistering("Register Onchain first"))?;
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

    let tx = api.tx().create_signed_with_nonce(call, signer, nonce.into(), Default::default())?;
    let result = tx.submit_and_watch().await?.wait_for_in_block().await?.wait_for_success().await?;
    Ok(result)
}
