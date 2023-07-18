#![allow(clippy::all)]
pub use subxt::config::PolkadotConfig as EntropyConfig;
use subxt::OnlineClient;

#[subxt::subxt(
    runtime_metadata_path = "entropy_metadata.scale",
    substitute_type(
        path = "entropy_shared::constraints::acl::Acl<Address>",
        with = "::subxt::utils::Static<::entropy_shared::Acl<Address>>",
    ),
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
