use entropy_shared::{Acl, Constraints, KeyVisibility, SIGNING_PARTY_SIZE};
#[cfg(test)]
use subxt::utils::AccountId32;
use subxt::{ext::sp_core::sr25519, tx::PairSigner, utils::Static, Config, OnlineClient};

use crate::{
    chain_api::{entropy, EntropyConfig},
    user::UserErr,
};

/// gets the subgroup of the working validator
pub async fn get_subgroup(
    api: &OnlineClient<EntropyConfig>,
    signer: &PairSigner<EntropyConfig, sr25519::Pair>,
) -> Result<Option<u8>, UserErr> {
    let mut subgroup: Option<u8> = None;
    let threshold_address = signer.account_id();
    let stash_address_query =
        entropy::storage().staking_extension().threshold_to_stash(threshold_address);
    let stash_address = api
        .storage()
        .at_latest()
        .await?
        .fetch(&stash_address_query)
        .await?
        .ok_or_else(|| UserErr::SubgroupError("Stash Fetch Error"))?;
    for i in 0..SIGNING_PARTY_SIZE {
        let signing_group_addresses_query =
            entropy::storage().staking_extension().signing_groups(i as u8);
        let signing_group_addresses = api
            .storage()
            .at_latest()
            .await?
            .fetch(&signing_group_addresses_query)
            .await?
            .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
        if signing_group_addresses.contains(&stash_address) {
            subgroup = Some(i as u8);
            break;
        }
    }
    Ok(subgroup)
}

/// Queries the user's Constraints from the chain
pub async fn get_constraints(
    substrate_api: &OnlineClient<EntropyConfig>,
    sig_req_account: &<EntropyConfig as Config>::AccountId,
) -> Result<Constraints, UserErr> {
    // ConstraintsPallet::ActiveArchitectures contains which ACL architectures have active ACLs, but
    // I think this code is going to be scrapped as part of a new constraints system before we
    // support 10+ architectures. If we ever need to use it, this link is a great starting point: https://github.com/paritytech/subxt/blob/master/examples/examples/storage_iterating.rs

    let evm_acl_storage_address = entropy::storage().constraints().evm_acl(sig_req_account);
    let btc_acl_storage_address = entropy::storage().constraints().btc_acl(sig_req_account);

    let (evm_acl_result, btc_acl_result) = futures::join!(
        substrate_api.storage().at_latest().await?.fetch(&evm_acl_storage_address),
        substrate_api.storage().at_latest().await?.fetch(&btc_acl_storage_address)
    );

    // if both are errors, the user has no constraints set, and we should error
    if evm_acl_result.is_err() && btc_acl_result.is_err() {
        return Err(UserErr::GenericSubstrate(evm_acl_result.unwrap_err()));
    }

    Ok(Constraints {
        evm_acl: Some(
            evm_acl_result
                .unwrap_or_default()
                .unwrap_or_else(|| Static(Acl::<[u8; 20]>::default()))
                .0,
        ),
        btc_acl: Some(
            btc_acl_result
                .unwrap_or_default()
                .unwrap_or_else(|| Static(Acl::<[u8; 32]>::default()))
                .0,
        ),
    })
}

/// Puts a user in the Registering state on-chain and waits for that transaction to be included in a
/// block
#[cfg(test)]
pub async fn make_register(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keyring: sr25519::Pair,
    constraint_account: &AccountId32,
    key_visibility: KeyVisibility,
) {
    let sig_req_account = PairSigner::<EntropyConfig, sr25519::Pair>::new(sig_req_keyring);

    let registering_query = entropy::storage().relayer().registering(sig_req_account.account_id());
    let is_registering_1 =
        api.storage().at_latest().await.unwrap().fetch(&registering_query).await.unwrap();
    println!("is_registering_1: {:?}", is_registering_1);
    assert!(is_registering_1.is_none());

    // register the user
    let registering_tx =
        entropy::tx().relayer().register(constraint_account.clone(), Static(key_visibility), None);

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

    let query_registering_status =
        api.storage().at_latest().await.unwrap().fetch(&registering_query).await;
    assert!(query_registering_status.unwrap().unwrap().is_registering);
}

/// Returns wether an account is registered
pub async fn get_key_visibility(
    api: &OnlineClient<EntropyConfig>,
    who: &<EntropyConfig as Config>::AccountId,
) -> Result<KeyVisibility, UserErr> {
    let registered_info_query = entropy::storage().relayer().registered(who);
    let result = api
        .storage()
        .at_latest()
        .await?
        .fetch(&registered_info_query)
        .await?
        .ok_or_else(|| UserErr::NotRegistering("Register Onchain first"))?;
    Ok(result.0)
}
