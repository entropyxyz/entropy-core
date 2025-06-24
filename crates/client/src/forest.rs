use crate::chain_api::entropy::runtime_types::pallet_forest::module::JoiningForestServerInfo;
use crate::{
    chain_api::{entropy, EntropyConfig},
    errors::{ClientError, SubstrateError},
    request_attestation,
    substrate::{query_chain, submit_transaction_with_pair},
};
use backoff::ExponentialBackoff;
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::time::Duration;
use subxt::{blocks::ExtrinsicEvents, OnlineClient, backend::legacy::LegacyRpcMethods};

/// Declares an itself to the chain by calling add box to the forest pallet
/// Will log and backoff if account does not have funds, assumption is that
/// deployer will see this and fund the account to complete the spin up process
pub async fn delcare_to_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    server_info: JoiningForestServerInfo,
    pair: &sr25519::Pair,
    nonce_option: Option<u32>,
) -> Result<(), ClientError> {
    // Use the default maximum elapsed time of 15 minutes.
    // This means if we do not get a connection within 15 minutes the process will terminate and the
    // keypair will be lost.
    let backoff = if cfg!(test) { create_test_backoff() } else { ExponentialBackoff::default() };

    let nonce = request_attestation(api, rpc, pair).await?;
    // let quote = create_quote(
    //     nonce,
    //     SubxtAccountId32(pair.public().0),
    //     server_info.x25519_public_key,
    // )
    // .await?;
    // TODO fix quite
    let add_tree_call = entropy::tx().forest().add_tree(server_info, vec![]);
    let add_tree = || async {
        println!(
            "attempted to make add_tree tx, If failed probably add funds to {:?}",
            pair.public().to_ss58check()
        );
        let in_block =
            submit_transaction_with_pair(api, rpc, &pair, &add_tree_call, nonce_option).await?;
        let _result_event = in_block
            .find_first::<entropy::forest::events::TreeAdded>()
            .map_err(|_| SubstrateError::NoEvent)?
            .ok_or(SubstrateError::NoEvent)?;
        Ok(())
    };
    // TODO: maybe add loggings here if fialed
    backoff::future::retry(backoff.clone(), add_tree).await.map_err(|_| ClientError::TimedOut)?;
    Ok(())
}

fn create_test_backoff() -> ExponentialBackoff {
    let mut backoff = ExponentialBackoff::default();
    backoff.max_elapsed_time = Some(Duration::from_secs(5));
    backoff.initial_interval = Duration::from_millis(50);
    backoff.max_interval = Duration::from_millis(500);
    backoff
}
