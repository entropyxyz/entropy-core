use subxt::{
    ClientBuilder, DefaultConfig, PairSigner, PolkadotExtrinsicParams,
};

#[subxt::subxt(runtime_metadata_path = "entropy_metadata.scale")]
pub mod entropy {}

pub type EntropyRuntime =
    entropy::RuntimeApi<DefaultConfig, PolkadotExtrinsicParams<DefaultConfig>>;

/// Creates an api instance to talk to chain
/// Chain endpoint set on launch
pub async fn get_api(url: &str) -> Result<EntropyRuntime, subxt::Error<entropy::DispatchError>> {
    let api = ClientBuilder::new().set_url(url).build().await?.to_runtime_api::<EntropyRuntime>();
    Ok(api)
}
