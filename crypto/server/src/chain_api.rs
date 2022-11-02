#![allow(clippy::all)]
pub use subxt::config::PolkadotConfig as EntropyConfig;
use subxt::{
    config::Config,
    tx::{PairSigner, SubstrateExtrinsicParams},
    OnlineClient,
};
#[subxt::subxt(runtime_metadata_path = "entropy_metadata.scale")]
pub mod entropy {}

/// Creates an api instance to talk to chain
/// Chain endpoint set on launch
pub async fn get_api(url: &str) -> Result<OnlineClient<EntropyConfig>, subxt::Error> {
    let api = OnlineClient::<EntropyConfig>::from_url(url).await?;
    Ok(api)
}
