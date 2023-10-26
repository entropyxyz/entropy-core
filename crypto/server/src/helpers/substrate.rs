use entropy_shared::{KeyVisibility, SIGNING_PARTY_SIZE};
use subxt::{
    backend::legacy::LegacyRpcMethods, ext::sp_core::sr25519, tx::PairSigner, utils::AccountId32,
    Config, OnlineClient,
};

use crate::{
    chain_api::{entropy, EntropyConfig},
    user::UserErr,
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
        .ok_or_else(|| UserErr::OptionUnwrapError("Error getting block hash"))?;

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
        .ok_or_else(|| UserErr::OptionUnwrapError("Error getting block hash"))?;
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
    sig_req_account: &<EntropyConfig as Config>::AccountId,
) -> Result<Vec<u8>, UserErr> {
    let bytecode_address = entropy::storage().programs().bytecode(sig_req_account);
    let block_hash = rpc
        .chain_get_block_hash(None)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Error getting block hash"))?;

    substrate_api
        .storage()
        .at(block_hash)
        .fetch(&bytecode_address)
        .await?
        .ok_or(UserErr::NoProgramDefined)
}

/// Puts a user in the Registering state on-chain and waits for that transaction to be included in a
/// block
#[cfg(test)]
pub async fn make_register(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    sig_req_keyring: sr25519::Pair,
    program_modification_account: &AccountId32,
    key_visibility: KeyVisibility,
) {
    use subxt::utils::Static;

    let sig_req_account = PairSigner::<EntropyConfig, sr25519::Pair>::new(sig_req_keyring);

    let registering_query = entropy::storage().relayer().registering(sig_req_account.account_id());
    let block_hash = rpc.chain_get_block_hash(None).await.unwrap().unwrap();
    let is_registering_1 = api.storage().at(block_hash).fetch(&registering_query).await.unwrap();
    assert!(is_registering_1.is_none());

    // register the user
    let empty_program = vec![];
    let registering_tx = entropy::tx().relayer().register(
        program_modification_account.clone(),
        Static(key_visibility),
        empty_program,
    );

    api.tx()
        .sign_and_submit_then_watch_default(&registering_tx, &sig_req_account)
        .await
        .unwrap()
        .wait_for_in_block()
        .await
        .unwrap()
        .wait_for_success()
        .await
        .unwrap();

    let block_hash_2 = rpc.chain_get_block_hash(None).await.unwrap().unwrap();

    let query_registering_status = api.storage().at(block_hash_2).fetch(&registering_query).await;
    assert!(query_registering_status.unwrap().unwrap().is_registering);
}

/// Returns wether an account is registered
pub async fn get_key_visibility(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    who: &<EntropyConfig as Config>::AccountId,
) -> Result<KeyVisibility, UserErr> {
    let registered_info_query = entropy::storage().relayer().registered(who);
    let block_hash = rpc
        .chain_get_block_hash(None)
        .await?
        .ok_or_else(|| UserErr::OptionUnwrapError("Error getting block hash"))?;
    let result = api
        .storage()
        .at(block_hash)
        .fetch(&registered_info_query)
        .await?
        .ok_or_else(|| UserErr::NotRegistering("Register Onchain first"))?;
    Ok(result.key_visibility.0)
}
