#![allow(clippy::all)]
pub use subxt::config::PolkadotConfig as EntropyConfig;
use subxt::OnlineClient;

#[subxt::subxt(runtime_metadata_path = "entropy_metadata.scale")]
pub mod entropy {
    #[subxt::subxt(substitute_type = "entropy::shared")]
    use ::entropy_shared;
    #[subxt::subxt(substitute_type = "entropy_shared::constraints::acl::Acl")]
    use ::entropy_shared::Acl;
    #[subxt::subxt(substitute_type = "entropy_shared::constraints::Constraints")]
    use ::entropy_shared::Constraints;
    #[subxt::subxt(substitute_type = "sp_core::crypto::AccountId32")]
    use ::sp_core::crypto::AccountId32;
}

/// Creates an api instance to talk to chain
/// Chain endpoint set on launch
pub async fn get_api(url: &str) -> Result<OnlineClient<EntropyConfig>, subxt::Error> {
    let api = OnlineClient::<EntropyConfig>::from_url(url).await?;
    Ok(api)
}
