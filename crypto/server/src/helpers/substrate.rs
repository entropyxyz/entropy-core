use entropy_shared::{SIGNING_PARTY_SIZE, Constraints, Acl};
use subxt::{
    ext::sp_core::sr25519,
    tx::PairSigner,
    dynamic,
    OnlineClient,
    Config, storage::address::{StorageMapKey, StorageHasher},
};

use crate::{
    chain_api::{
        EntropyConfig,
        entropy,
    },
    user::UserErr,
};

#[cfg(test)]
use sp_keyring::Sr25519Keyring;

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
        .fetch(&stash_address_query, None)
        .await?
        .ok_or_else(|| UserErr::SubgroupError("Stash Fetch Error"))?;
    for i in 0..SIGNING_PARTY_SIZE {
        let signing_group_addresses_query =
            entropy::storage().staking_extension().signing_groups(i as u8);
        let signing_group_addresses = api
            .storage()
            .fetch(&signing_group_addresses_query, None)
            .await?
            .ok_or_else(|| UserErr::SubgroupError("Subgroup Error"))?;
        if signing_group_addresses.contains(&stash_address) {
            subgroup = Some(i as u8);
            break;
        }
    }
    Ok(subgroup)
}


// Queries the user's Constraints from the chain
pub async fn get_constraints(
    api: &OnlineClient<EntropyConfig>,
    sig_req_account: &<EntropyConfig as Config>::AccountId,
) -> Result<Option<Constraints>, UserErr> {

        let key_addr = entropy::storage().constraints().active_architectures_root();

        // Obtain the root bytes (`twox_128("ConstraintsPallet") ++ twox_128("ActiveArchitectures")`).
        let mut query_key = key_addr.to_root_bytes();

        // We know that the first key is a T::AccountId (the signature requesting account) and is hashed by twox64_concat.
        // We can build a `StorageMapKey` that replicates that, and append those bytes to the above.
        StorageMapKey::new(sig_req_account, StorageHasher::Blake2_128Concat).to_bytes(&mut query_key);

        // The final query key is essentially the result of:
        // `twox_128("ConstraintsPallet") ++ twox_128("ActiveArchitectures") ++ twox_64(2u32) ++ 2u32`
        println!("\nExample 3\nQuery key: 0x{}", hex::encode(&query_key));

        let keys = api
            .storage()
            .fetch_keys(&query_key, 10, None, None)
            .await?;

        println!("Obtained keys:");
        for key in keys.iter() {
            println!("Key: 0x{}", hex::encode(key));

            // if let Some(storage_data) =
            //     api.storage().fetch_raw(&key.0, None).await?
            // {
            //     // We know the return value to be `QueryId` (`u64`) from inspecting either:
            //     // - polkadot code
            //     // - polkadot.rs generated file under `version_notifiers()` fn
            //     // - metadata in json format
            //     let value = u64::decode(&mut &storage_data[..])?;
            //     println!("  Value: {value}");
            // }
        }
    // let threshold_address = signer.account_id();

    // let registered = api
    //     .storage()
    //     .iter(&entropy::storage().constraints().active_architectures(0, 1), 10, None)
    //     .await?
    //     .ok_or(None)?;

    // let (evm_acl, btc_acl) = futures::join!(
    //     api.storage().fetch(&entropy::storage().constraints().evm_acl(threshold_address), None),
    //     api.storage().fetch(&entropy::storage().constraints().btc_acl(threshold_address), None)
    // )?.await;

    // let constraints = Constraints {
    //     evm_acl: evm_query.ok_or(None)?,
    //     btc_acl: btc_query.ok_or(None)?,
    // };

    Ok(None)
}

/// Registers a user on the chain and waits for the transaction to be included in a block 
/// Generally used for test context
#[cfg(test)]
pub async fn make_register(
    api: &OnlineClient<EntropyConfig>,
    sig_req_keyring: &Sr25519Keyring,
    constraint_keyring: &Sr25519Keyring,
    initial_constraints: Option<Constraints>,
) {
    let sig_req_account =
        PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(sig_req_keyring.pair());
    let constraint_modificaiton_account =
        PairSigner::<EntropyConfig, sp_core::sr25519::Pair>::new(constraint_keyring.pair());
    let registering_query =
        entropy::storage().relayer().registering(sig_req_keyring.to_account_id());
    let is_registering_1 = api.storage().fetch(&registering_query, None).await.unwrap();
    println!("is_registering_1: {:?}", is_registering_1);
    assert!(is_registering_1.is_none());

    // // This pattern described here allows us to use the entropy_shared types instead of having to reexport them from subxt. See example here:
    // // https://github.com/paritytech/subxt/blob/master/examples/examples/dynamic_multisig.rs
    // let registering_tx = entropy::relayer::calls::Register {
    //     constraint_account: constraint_keyring.to_account_id(),
    //     initial_constraints: initial_constraints,
    // };

    // let tx = subxt::dynamic::tx(
    //     "ConstraintsPallet",
    //     "register",
    //     vec![

    //     ],
    // );
    // let constraints = match initial_constraints {
    //     Some(constraints) => Some((&mut constraints).unwrap()),
    //     None => None,
    // };

    let registering_tx = entropy::tx().relayer().register(constraint_keyring.to_account_id(), None);

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

    let is_registering_2 = api.storage().fetch(&registering_query, None).await;
    assert!(is_registering_2.unwrap().unwrap().is_registering);

    // This encoded call data was generated in polkadot.js.org/apps extrinsics view
    let update_constraints_tx = subxt::tx::StaticTxPayload::new(
        "ConstraintsPallet",
        "update_constraints",
        hex::decode("3600d43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d01041111111111111111111111111111111111111111000000").unwrap(),
        [0u8; 32]
    ).unvalidated();

    api.tx()
        .sign_and_submit_then_watch_default(&update_constraints_tx, &constraint_modificaiton_account)
        .await
        .unwrap()
        .wait_for_in_block()
        .await
        .unwrap()
        .wait_for_success()
        .await
        .unwrap();
    }