#![allow(clippy::all)]
use subxt::{
    tx::{PairSigner, SubstrateExtrinsicParams},
    OnlineClient, PolkadotConfig,
};
#[subxt::subxt(runtime_metadata_path = "entropy_metadata.scale")]
pub mod entropy {}

pub type EntropyRuntime =
    entropy::RuntimeApi<PolkadotConfig, SubstrateExtrinsicParams<PolkadotConfig>>;

/// Creates an api instance to talk to chain
/// Chain endpoint set on launch
pub async fn get_api(url: &str) -> Result<EntropyRuntime, subxt::Error<entropy::DispatchError>> {
    let api = OnlineClient::<PolkadotConfig>::new()
        .ws_client(url)
        .build()
        .await?
        .to_runtime_api::<EntropyRuntime>();
    Ok(api)
}
