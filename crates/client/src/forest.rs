use crate::chain_api::entropy::runtime_types::pallet_forest::module::ForestServerInfo;
use crate::{
    attestation::create_quote,
    chain_api::{entropy, get_api, get_rpc, EntropyConfig},
    errors::{ClientError, SubstrateError},
    substrate::submit_transaction_with_pair,
    user::request_attestation,
};
use axum::Json;
use backoff::ExponentialBackoff;
use entropy_shared::{attestation::QuoteContext, X25519PublicKey};
use serde::{Deserialize, Serialize};
use sp_core::{
    crypto::{AccountId32, Ss58Codec},
    sr25519, Pair,
};
use std::time::Duration;
use subxt::{
    backend::legacy::LegacyRpcMethods, utils::AccountId32 as SubxtAccountId32, OnlineClient,
};
use x25519_dalek::StaticSecret;

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
        SubxtAccountId32(pair.public().0),
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
            submit_transaction_with_pair(api, rpc, pair, &add_tree_call, nonce_option).await?;
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
    ExponentialBackoff {
        max_elapsed_time: Some(Duration::from_secs(5)),
        initial_interval: Duration::from_millis(50),
        max_interval: Duration::from_millis(500),
        ..Default::default()
    }
}

// Get all available API key servers from the chain
pub async fn get_api_key_servers(
    api: &OnlineClient<EntropyConfig>,
    rpc: &LegacyRpcMethods<EntropyConfig>,
) -> Result<Vec<(SubxtAccountId32, ForestServerInfo)>, ClientError> {
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

/// Public signing and encryption keys associated with a server
#[derive(Serialize, Deserialize, Clone, Debug, Eq, PartialEq)]
pub struct ServerPublicKeys {
    /// The account ID
    pub account_id: SubxtAccountId32,
    /// The public encryption key
    pub x25519_public_key: X25519PublicKey,
    /// A hex-encoded TDX quote to show that the server is running the desired service
    pub tdx_quote: String,
    /// An option if supported if the node is ready (not all nodes support this option)
    pub ready: Option<bool>,
}

pub async fn get_node_info(
    ready: Option<bool>,
    x25519_public_key: [u8; 32],
    account_id: SubxtAccountId32,
    quote_context: QuoteContext,
) -> Result<Json<ServerPublicKeys>, ClientError> {
    Ok(Json(ServerPublicKeys {
        ready,
        x25519_public_key,
        account_id: account_id.clone(),
        tdx_quote: hex::encode(
            create_quote([0; 32], account_id, &x25519_public_key, quote_context).await?,
        ),
    }))
}

/// A Tree state for Trees.
/// All trees need to maintain at least this information in their app state
#[derive(Clone)]
pub struct TreeState {
    /// Keypair for tree id account
    pub pair: sr25519::Pair,
    /// Secret encryption key
    pub x25519_secret: StaticSecret,
    /// Configuation containing the chain endpoint
    pub configuration: Configuration,
}

impl TreeState {
    /// Setup [`TreeState`] with given secret keys
    pub fn new(
        configuration: Configuration,
        pair: sr25519::Pair,
        x25519_secret: StaticSecret,
    ) -> Self {
        Self { pair, x25519_secret, configuration }
    }

    /// Convenience function to get Entropy client and Legacy RPC client
    pub async fn get_api_rpc(
        &self,
    ) -> Result<(OnlineClient<EntropyConfig>, LegacyRpcMethods<EntropyConfig>), ClientError> {
        Ok((
            get_api(&self.configuration.endpoint).await?,
            get_rpc(&self.configuration.endpoint).await?,
        ))
    }

    /// Get the [`AccountId32`]
    pub fn account_id(&self) -> AccountId32 {
        AccountId32::new(self.pair.public().0)
    }

    /// Get the subxt account ID
    pub fn subxt_account_id(&self) -> SubxtAccountId32 {
        SubxtAccountId32(self.pair.public().0)
    }

    /// Get the x25519 public key
    pub fn x25519_public_key(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.x25519_secret).to_bytes()
    }
}

/// Configuration for chain endpoint
#[derive(Clone)]
pub struct Configuration {
    pub endpoint: String,
}

impl Configuration {
    pub fn new(endpoint: String) -> Configuration {
        Configuration { endpoint }
    }
}
