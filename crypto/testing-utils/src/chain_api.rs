#![allow(clippy::all)]
pub use subxt::config::PolkadotConfig as EntropyConfig;

#[subxt::subxt(runtime_metadata_path = "../server/entropy_metadata.scale")]
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
