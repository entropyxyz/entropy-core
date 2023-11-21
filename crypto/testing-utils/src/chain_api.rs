#![allow(clippy::all)]
pub use subxt::PolkadotConfig as EntropyConfig;
use subxt::{
    backend::{legacy::LegacyRpcMethods, rpc::RpcClient},
    OnlineClient,
};

#[subxt::subxt(
    runtime_metadata_path = "../server/entropy_metadata.scale",
    substitute_type(
        path = "entropy_shared::types::KeyVisibility",
        with = "::subxt::utils::Static<::entropy_shared::KeyVisibility>",
    )
)]
pub mod entropy {}

/// Creates an api instance to talk to chain
/// Chain endpoint set on launch
pub async fn get_api(url: &str) -> Result<OnlineClient<EntropyConfig>, subxt::Error> {
    let api = OnlineClient::<EntropyConfig>::from_url(url).await?;
    Ok(api)
}

/// Creates a rpc instance to talk to chain
/// Chain endpoint set on launch
pub async fn get_rpc(url: &str) -> Result<LegacyRpcMethods<EntropyConfig>, subxt::Error> {
    let rpc_client = RpcClient::from_url(url).await?;
    let rpc_methods = LegacyRpcMethods::<EntropyConfig>::new(rpc_client);
    Ok(rpc_methods)
}
