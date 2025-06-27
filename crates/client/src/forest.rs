use crate::chain_api::entropy::runtime_types::pallet_forest::module::ForestServerInfo;
use crate::{
    attestation::create_quote,
    chain_api::{entropy, EntropyConfig},
    errors::{ClientError, SubstrateError},
    substrate::submit_transaction_with_pair,
    user::request_attestation,
};
use backoff::ExponentialBackoff;
use entropy_shared::attestation::QuoteContext;
use sp_core::{crypto::Ss58Codec, sr25519, Pair};
use std::time::Duration;
use subxt::{backend::legacy::LegacyRpcMethods, utils::AccountId32, OnlineClient};

/// Declares an itself to the chain by calling add box to the forest pallet
/// Will log and backoff if account does not have funds, assumption is that
/// deployer will see this and fund the account to complete the spin up process
pub async fn declare_to_chain(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
    endpoint: String,
    x25519_public_key: [u8; 32],
    pair: &sr25519::Pair,
    nonce_option: Option<u32>,
) -> Result<(), ClientError> {
    // Use the default maximum elapsed time of 15 minutes.
    // This means if we do not get a connection within 15 minutes the process will terminate and the
    // keypair will be lost.
    let backoff = if cfg!(test) { create_test_backoff() } else { ExponentialBackoff::default() };

    let nonce = request_attestation(api, rpc, pair).await?;
    let tdx_quote = create_quote(
        nonce,
        AccountId32(pair.public().0),
        &x25519_public_key,
        QuoteContext::ForestAddTree,
    )
    .await?;

    let server_info = ForestServerInfo { endpoint: endpoint.into(), x25519_public_key, tdx_quote };

    let add_tree_call = entropy::tx().forest().add_tree(server_info);
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

// Get all available API key servers from the chain
pub async fn get_api_key_servers(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<Vec<(AccountId32, ForestServerInfo)>, ClientError> {
    let block_hash = rpc.chain_get_block_hash(None).await?.ok_or(ClientError::BlockHash)?;
    let storage_address = entropy::storage().forest().trees_iter();
    let mut iter = api.storage().at(block_hash).iter(storage_address).await?;
    let mut servers = Vec::new();
    while let Some(Ok(kv)) = iter.next().await {
        let key: [u8; 32] = kv.key_bytes[kv.key_bytes.len() - 32..].try_into()?;
        servers.push((key.into(), kv.value))
    }
    Ok(servers)
}
